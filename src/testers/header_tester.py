# -*- coding: utf-8 -*-
"""
Header Manipulation Tester
Dynamically extracts and tests ALL headers from request
"""

from config.payloads import Payloads
from detection.detector import VerboseErrorDetector


class HeaderTester:
    """Test all headers with manipulation payloads"""
    
    def __init__(self, http_helper):
        """
        Initialize header tester
        
        Args:
            http_helper: HttpHelper instance for sending requests
        """
        self.http_helper = http_helper
        self.detector = VerboseErrorDetector()
        self.enable_early_exit = True
    
    def test(self, request, baseline_response, threshold=15):
        """
        Test all headers in request with payloads
        
        Args:
            request: Original request dict
            baseline_response: Baseline response for comparison
            threshold: Detection threshold
            
        Returns:
            List of findings
        """
        findings = []
        
        # Extract ALL headers from request
        headers = request.get('headers', {})
        
        if not headers:
            print("[*] Header Tester: No headers found in request")
            return findings
        
        print("[*] Header Tester: Found " + str(len(headers)) + " headers to test")
        
        # Categorize headers by priority
        critical_headers, custom_headers, standard_headers = self._categorize_headers(headers)
        
        # Test in priority order: Critical -> Custom -> Standard
        test_order = critical_headers + custom_headers + standard_headers
        
        for header_name, original_value in test_order:
            print("[*] Header Tester: Testing header '" + str(header_name) + "'")
            
            header_findings = self._test_single_header(
                request, 
                header_name, 
                original_value, 
                baseline_response, 
                threshold
            )
            
            if header_findings:
                findings.extend(header_findings)
                
                if self.enable_early_exit:
                    print("[+] Header Tester: Found vulnerability in '" + str(header_name) + "', moving to next header")
        
        print("[*] Header Tester: Complete. Found " + str(len(findings)) + " vulnerabilities across " + str(len([f for f in findings])) + " headers")
        
        return findings
    
    def _test_single_header(self, request, header_name, original_value, baseline_response, threshold):
        """Test a single header with all payloads"""
        findings = []
        
        # Get header payloads
        payloads = Payloads.get_all_header_payloads()
        
        tested_count = 0
        for payload_template in payloads:
            tested_count += 1
            
            test_value = Payloads.apply_payload(original_value, payload_template)
            
            modified_request = request.copy()
            modified_headers = modified_request.get('headers', {}).copy()
            modified_headers[header_name] = test_value
            modified_request['headers'] = modified_headers
            
            try:
                response = self.http_helper.send_request(modified_request)
                if hasattr(self, 'scanner') and self.scanner:
                    self.scanner.increment_request_count(1)
                
                # Detect verbose error
                result = self.detector.detect(response, baseline_response, threshold)
                
                if result['vulnerable']:
                    print("[+] Header Tester: Vulnerability found in header '" + str(header_name) + "' with payload!")
                    
                    finding = {
                        'category': 'Header Manipulation',
                        'header_name': header_name,
                        'original_value': original_value,
                        'test_value': test_value,
                        'payload_template': payload_template,
                        'detection_result': result,
                        'request': modified_request,
                        'response': response
                    }
                    findings.append(finding)
                    
                    if hasattr(self, 'scanner') and self.scanner:
                        self.scanner.notify_finding(finding)
                    
                    if self.enable_early_exit:
                        print("[*] Header Tester: Early exit for '" + str(header_name) + "' (tested " + str(tested_count) + "/" + str(len(payloads)) + " payloads)")
                        break
                        
            except Exception as e:
                print("[-] Header Tester: Error testing header '" + str(header_name) + "': " + str(str(e)) + "")
                continue
        
        return findings
    
    def _categorize_headers(self, headers):
        """
        Categorize headers by priority
        
        Returns:
            Tuple of (critical, custom, standard) header lists
        """
        critical = []
        custom = []
        standard = []
        
        critical_names = ['host', 'cookie', 'content-type', 'content-length', 'authorization']
        
        for name, value in headers.items():
            name_lower = name.lower()
            
            if name_lower in critical_names:
                critical.append((name, value))
            elif name.startswith('X-') or name.startswith('Sec-'):
                custom.append((name, value))
            else:
                standard.append((name, value))
        
        return critical, custom, standard
