# -*- coding: utf-8 -*-
"""
Confidence scoring system for verbose error detection
Calculates score based on multiple evidence types
"""

class ConfidenceScorer:
    """Calculate confidence score for findings"""
    
    # Point values for different evidence types
    POINTS = {
        # High confidence indicators (20-30 points)
        'stack_trace': 30,
        'database_error': 25,
        'path_disclosure': 20,
        
        # Medium confidence indicators (10-20 points)
        'framework_error': 15,
        'sensitive_info': 15,
        'validation_error': 12,
        'parse_error': 12,
        
        # Low confidence indicators (3-8 points)
        'behavioral_change': 8,
        'status_500': 5,
        'status_400': 3,
        'generic_error_keywords': 5,
    }
    
    # Severity mapping based on score
    SEVERITY_MAPPING = {
        (80, 100): {'severity': 'CRITICAL', 'confidence': 'Very High'},
        (50, 79): {'severity': 'HIGH', 'confidence': 'High'},
        (30, 49): {'severity': 'MEDIUM', 'confidence': 'Medium'},
        (15, 29): {'severity': 'LOW', 'confidence': 'Low-Medium'},
        (5, 14): {'severity': 'INFO', 'confidence': 'Low'},
        (0, 4): {'severity': 'INFO', 'confidence': 'Very Low'},
    }
    
    def __init__(self):
        self.score = 0
        self.evidences = []
        self.evidence_types = set()
    
    def add_evidence(self, evidence_type, description, points=None):
        """
        Add evidence and update score
        
        Args:
            evidence_type: Type of evidence (stack_trace, database_error, etc.)
            description: Description of the evidence
            points: Custom points (optional, uses default if None)
        """
        # Avoid duplicate points for same evidence type
        if evidence_type in self.evidence_types:
            return
        
        if points is None:
            points = self.POINTS.get(evidence_type, 0)
        
        self.score += points
        self.evidence_types.add(evidence_type)
        self.evidences.append({
            'type': evidence_type,
            'description': description,
            'points': points
        })
    
    def add_stack_trace(self, language, samples):
        """Add stack trace evidence"""
        description = "{0} stack trace detected ({1} lines)".format(language.upper(), len(samples))
        self.add_evidence('stack_trace', description, self.POINTS['stack_trace'])
    
    def add_database_error(self, database, samples):
        """Add database error evidence"""
        description = "{0} error detected".format(database.upper())
        self.add_evidence('database_error', description, self.POINTS['database_error'])
    
    def add_path_disclosure(self, paths):
        """Add path disclosure evidence"""
        description = "File paths disclosed: {0} found".format(len(paths))
        self.add_evidence('path_disclosure', description, self.POINTS['path_disclosure'])
    
    def add_framework_error(self, framework):
        """Add framework error evidence"""
        description = "{0} framework error detected".format(framework.title())
        self.add_evidence('framework_error', description, self.POINTS['framework_error'])
    
    def add_sensitive_info(self, info_type, count):
        """Add sensitive information evidence"""
        description = "{0} disclosed ({1} found)".format(info_type, count)
        self.add_evidence('sensitive_info', description, self.POINTS['sensitive_info'])
    
    def add_validation_error(self, error_type):
        """Add validation error evidence"""
        description = "{0} with details".format(error_type)
        self.add_evidence('validation_error', description, self.POINTS['validation_error'])
    
    def add_status_code(self, status_code):
        """Add status code evidence"""
        if status_code >= 500:
            self.add_evidence('status_500', "HTTP {0} error".format(status_code), self.POINTS['status_500'])
        elif status_code >= 400:
            self.add_evidence('status_400', "HTTP {0} error".format(status_code), self.POINTS['status_400'])
    
    def add_behavioral_change(self, changes):
        """Add behavioral analysis evidence"""
        description = "Behavioral changes: {0}".format(', '.join(changes))
        self.add_evidence('behavioral_change', description, self.POINTS['behavioral_change'])
    
    def get_severity_and_confidence(self):
        """
        Get severity and confidence level based on score
        
        Returns:
            dict with 'severity' and 'confidence' keys
        """
        for score_range, result in self.SEVERITY_MAPPING.items():
            if score_range[0] <= self.score <= score_range[1]:
                return result
        return {'severity': 'INFO', 'confidence': 'Very Low'}
    
    def is_vulnerable(self, threshold=15):
        """
        Check if score exceeds threshold
        
        Args:
            threshold: Minimum score to consider vulnerable
            
        Returns:
            True if vulnerable, False otherwise
        """
        return self.score >= threshold
    
    def get_result(self, threshold=15):
        """
        Get complete scoring result
        
        Args:
            threshold: Minimum score threshold
            
        Returns:
            Dictionary with complete results
        """
        severity_conf = self.get_severity_and_confidence()
        
        return {
            'vulnerable': self.is_vulnerable(threshold),
            'score': self.score,
            'severity': severity_conf['severity'],
            'confidence': severity_conf['confidence'],
            'evidences': self.evidences,
            'evidence_types': list(self.evidence_types),
            'threshold': threshold
        }
    
    def reset(self):
        """Reset scorer for new analysis"""
        self.score = 0
        self.evidences = []
        self.evidence_types = set()


class BehavioralAnalyzer:
    """Analyze behavioral changes between baseline and test response"""
    
    @staticmethod
    def analyze(baseline_response, test_response):
        """
        Compare baseline and test responses
        
        Args:
            baseline_response: Baseline response object
            test_response: Test response object
            
        Returns:
            List of behavioral change descriptions
        """
        changes = []
        
        if test_response.get('status') != baseline_response.get('status'):
            changes.append("Status code changed: {0} → {1}".format(baseline_response.get('status'), test_response.get('status')))
        
        baseline_length = len(baseline_response.get('body', ''))
        test_length = len(test_response.get('body', ''))
        
        if baseline_length > 0:
            length_diff = abs(test_length - baseline_length)
            length_ratio = length_diff / baseline_length
            
            if length_ratio > 0.5:
                percentage = round(length_ratio * 100, 1)
                changes.append("Significant length change: {0} bytes ({1}%)".format(length_diff, percentage))
        
        baseline_time = baseline_response.get('time', 0)
        test_time = test_response.get('time', 0)
        
        if baseline_time > 0 and test_time > baseline_time * 2:
            bt = round(baseline_time, 2)
            tt = round(test_time, 2)
            changes.append("Response time increased: {0}s -> {1}s".format(bt, tt))
        
        baseline_ct = baseline_response.get('content_type', '')
        test_ct = test_response.get('content_type', '')
        
        if baseline_ct and test_ct and baseline_ct != test_ct:
            changes.append("Content-Type changed: {0} → {1}".format(baseline_ct, test_ct))
        
        return changes
