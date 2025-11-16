# -*- coding: utf-8 -*-
"""
HTTP Method Fuzzing Tester
Tests various HTTP methods to trigger verbose errors
"""

from config.payloads import Payloads
from detection.detector import VerboseErrorDetector


class MethodTester:
    """Test HTTP methods for verbose errors"""
    
    def __init__(self, http_helper):
        """
        Initialize method tester
        
        Args:
            http_helper: HttpHelper instance for sending requests
        """
        self.http_helper = http_helper
        self.detector = VerboseErrorDetector()
        self.enable_early_exit = True
    
    def test(self, request, baseline_response, threshold=15):
        """
        Test request with various HTTP methods
        
        Args:
            request: Original request dict
            baseline_response: Baseline response for comparison
            threshold: Detection threshold
            
        Returns:
            List of findings
        """
        findings = []
        original_method = request.get('method', 'GET')
        
        print("[*] Method Tester: Testing endpoint with method fuzzing")

        all_methods = Payloads.get_method_payloads()

        tested_count = 0
        for method in all_methods:
            if method.upper() == original_method.upper():
                continue
            
            tested_count += 1
            print("[*] Method Tester: Testing method '" + str(method) + "' (" + str(tested_count) + "/" + str(len(all_methods)-1) + ")")
            
            modified_request = request.copy()
            modified_request['method'] = method
            
            try:
                response = self.http_helper.send_request(modified_request)
                if hasattr(self, 'scanner') and self.scanner:
                    self.scanner.increment_request_count(1)
                
                result = self.detector.detect(response, baseline_response, threshold)
                
                if result['vulnerable']:
                    print("[+] Method Tester: Vulnerability found with method '" + str(method) + "'!")
                    
                    finding = {
                        'category': 'HTTP Method Fuzzing',
                        'subcategory': self._categorize_method(method),
                        'original_method': original_method,
                        'test_method': method,
                        'detection_result': result,
                        'request': modified_request,
                        'response': response
                    }
                    findings.append(finding)
                    
                    if hasattr(self, 'scanner') and self.scanner:
                        self.scanner.notify_finding(finding)
                    
                    if self.enable_early_exit:
                        print("[*] Method Tester: Early exit activated (found " + str(len(findings)) + " vulnerability)")
                        break
                        
            except Exception as e:
                print("[-] Method Tester: Error testing method '" + str(method) + "': " + str(str(e)) + "")
                continue
        
        if not findings:
            print("[*] Method Tester: No vulnerabilities found (tested " + str(tested_count) + " methods)")
        
        return findings
    
    def _categorize_method(self, method):
        """Categorize method type for reporting"""
        method_upper = method.upper()
        
        if method_upper in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
            return 'Invalid Standard Method'
        elif method != method_upper:
            return 'Method Case Manipulation'
        else:
            return 'Random Invalid Method'
