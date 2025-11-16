# -*- coding: utf-8 -*-
"""
Main detection engine for verbose error messages
Coordinates pattern matching and confidence scoring
"""

import re
from .patterns import DetectionPatterns
from .scoring import ConfidenceScorer, BehavioralAnalyzer


class VerboseErrorDetector:
    """Main detection engine"""
    
    def __init__(self):
        self.patterns = DetectionPatterns.get_all_patterns()
        self.scorer = ConfidenceScorer()
    
    def detect(self, test_response, baseline_response=None, threshold=15):
        """
        Main detection method
        
        Args:
            test_response: Response object to analyze
            baseline_response: Baseline response for comparison (optional)
            threshold: Minimum score threshold
            
        Returns:
            Detection result dictionary
        """
        self.scorer.reset()
        
        response_body = test_response.get('body', '')
        status_code = test_response.get('status', 200)

        if status_code < 400 and baseline_response and response_body == baseline_response.get('body', ''):
            return self._build_result(threshold)

        if status_code >= 400:
            self.scorer.add_status_code(status_code)

        extracted = self._extract_evidence(response_body)

        for lang, samples in extracted['stack_traces'].items():
            if samples:
                self.scorer.add_stack_trace(lang, samples)
        
        for db, samples in extracted['database_errors'].items():
            if samples:
                self.scorer.add_database_error(db, samples)
        
        for framework in extracted['frameworks']:
            self.scorer.add_framework_error(framework)
        
        for error_type in extracted['validation_errors']:
            self.scorer.add_validation_error(error_type)
        
        if extracted['paths']:
            self.scorer.add_path_disclosure(extracted['paths'])
        
        if extracted['sensitive_info']:
            self.scorer.add_sensitive_info('credentials/IPs/keys', len(extracted['sensitive_info']))

        if baseline_response:
            changes = BehavioralAnalyzer.analyze(baseline_response, test_response)
            if changes:
                self.scorer.add_behavioral_change(changes)

        result = self._build_result(threshold)
        result['extracted_evidence'] = extracted
        
        return result
    
    def _extract_evidence(self, response_body):
        """
        Extract all evidence from response body
        
        Args:
            response_body: Response body text
            
        Returns:
            Dictionary with all extracted evidence
        """
        extracted = {
            'stack_traces': {},
            'database_errors': {},
            'frameworks': [],
            'validation_errors': [],
            'paths': [],
            'sensitive_info': [],
        }

        for lang, patterns in self.patterns['stack_traces'].items():
            matches = []
            for pattern in patterns:
                found = pattern.findall(response_body)
                if found:
                    matches.extend(found[:5])
                    if len(matches) >= 5:
                        break
            if matches:
                extracted['stack_traces'][lang] = matches[:5]

        for db, patterns in self.patterns['database_errors'].items():
            matches = []
            for pattern in patterns:
                if pattern.search(response_body):
                    matches.append(pattern.pattern)
                    break
            if matches:
                extracted['database_errors'][db] = matches

        for framework, patterns in self.patterns['framework_errors'].items():
            for pattern in patterns:
                if pattern.search(response_body):
                    extracted['frameworks'].append(framework)
                    break

        for error_type, patterns in self.patterns['validation_errors'].items():
            for pattern in patterns:
                if pattern.search(response_body):
                    extracted['validation_errors'].append(error_type)
                    break

        for pattern in self.patterns['path_disclosure']:
            matches = pattern.findall(response_body)
            if matches:
                extracted['paths'].extend(matches[:10])
                if len(extracted['paths']) >= 10:
                    break

        for pattern in self.patterns['sensitive_info']:
            matches = pattern.findall(response_body)
            if matches:
                extracted['sensitive_info'].extend(matches[:5])
                if len(extracted['sensitive_info']) >= 5:
                    break
        
        return extracted
    
    def _build_result(self, threshold):
        """Build detection result dictionary"""
        result = self.scorer.get_result(threshold)

        if result['vulnerable'] and self.scorer.evidences:
            first_evidence = self.scorer.evidences[0]
            result['response_sample'] = first_evidence.get('description', '')[:200]
        
        return result


class FalsePositiveFilter:
    """Filter out known false positives"""
    
    FALSE_POSITIVE_PATTERNS = {
        'cdn_wa': [
            r'cloudflare',
            r'ray id:',
            r'access denied.*web application firewall',
            r'this request has been blocked',
            r'akamai',
            r'incapsula',
            r'sucuri',
            r'blocked by administrator',
        ],
        'custom_error_pages': [
            r'<title>404.*not found</title>',
            r'oops.*something went wrong',
            r'page not found',
            r"we're sorry",
            r'error code: \d{3,4}',
        ],
        'generic_servers': [
            r'nginx/\d+\.\d+\.\d+',
            r'apache/\d+\.\d+\.\d+ .* server at',
            r'iis \d+\.\d+ detailed error',
        ],
    }
    
    def __init__(self):
        self.patterns = {}
        for category, pattern_list in self.FALSE_POSITIVE_PATTERNS.items():
            self.patterns[category] = [re.compile(p, re.IGNORECASE) for p in pattern_list]
    
    def is_false_positive(self, response_body):
        """
        Check if response is a false positive
        
        Args:
            response_body: Response body text
            
        Returns:
            Tuple of (is_fp, reason)
        """
        body_lower = response_body.lower()
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern.search(body_lower):
                    return True, "False positive: {0}".format(category)
        
        return False, None
    
    def filter_result(self, detection_result, response_body):
        """
        Filter detection result for false positives
        
        Args:
            detection_result: Result from VerboseErrorDetector
            response_body: Response body text
            
        Returns:
            Modified detection result (marked as FP if applicable)
        """
        if detection_result['vulnerable']:
            is_fp, reason = self.is_false_positive(response_body)
            if is_fp:
                detection_result['vulnerable'] = False
                detection_result['false_positive'] = True
                detection_result['fp_reason'] = reason
        
        return detection_result
