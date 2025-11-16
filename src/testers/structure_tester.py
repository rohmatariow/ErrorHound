# -*- coding: utf-8 -*-
"""
Body Structure Breaking Tester
Tests JSON/XML/Form structure breaking to trigger parse errors
"""

from config.payloads import Payloads
from detection.detector import VerboseErrorDetector


class StructureTester:
    """Test body structure breaking"""
    
    def __init__(self, http_helper):
        """
        Initialize structure tester
        
        Args:
            http_helper: HttpHelper instance for sending requests
        """
        self.http_helper = http_helper
        self.detector = VerboseErrorDetector()
        self.enable_early_exit = True
    
    def test(self, request, baseline_response, threshold=15):
        """
        Test body structure breaking
        
        Args:
            request: Original request dict
            baseline_response: Baseline response for comparison
            threshold: Detection threshold
            
        Returns:
            List of findings
        """
        findings = []

        body = request.get('body', '')
        content_type = request.get('headers', {}).get('Content-Type', '')
        
        if not body:
            print("[*] Structure Tester: No body in request, skipping")
            return findings

        format_type = self._detect_format(content_type, body)
        
        if not format_type:
            print("[*] Structure Tester: Could not detect format (Content-Type: " + str(content_type) + ")")
            return findings
        
        print("[*] Structure Tester: Detected format: " + str(format_type) + "")

        payloads = self._get_payloads_for_format(format_type)
        
        if not payloads:
            print("[*] Structure Tester: No payloads for format: " + str(format_type) + "")
            return findings

        tested_count = 0
        for payload in payloads:
            tested_count += 1
            print("[*] Structure Tester: Testing payload " + str(tested_count) + "/" + str(len(payloads)) + "")
            modified_body = self._apply_structure_breaking(body, payload, format_type)
            modified_request = request.copy()
            modified_request['body'] = modified_body

            try:
                response = self.http_helper.send_request(modified_request)
                if hasattr(self, 'scanner') and self.scanner:
                    self.scanner.increment_request_count(1)
                
                result = self.detector.detect(response, baseline_response, threshold)
                
                if result['vulnerable']:
                    print("[+] Structure Tester: Vulnerability found with " + str(format_type) + " structure breaking!")
                    
                    finding = {
                        'category': 'Body Structure Breaking',
                        'format_type': format_type,
                        'payload': payload,
                        'original_body': body[:200],
                        'modified_body': modified_body[:200],
                        'detection_result': result,
                        'request': modified_request,
                        'response': response
                    }
                    findings.append(finding)

                    if hasattr(self, 'scanner') and self.scanner:
                        self.scanner.notify_finding(finding)

                    if self.enable_early_exit:
                        print("[*] Structure Tester: Early exit (tested " + str(tested_count) + "/" + str(len(payloads)) + " payloads)")
                        break
                        
            except Exception as e:
                print("[-] Structure Tester: Error testing payload: " + str(str(e)) + "")
                continue
        
        if not findings:
            print("[*] Structure Tester: No vulnerabilities found (tested " + str(tested_count) + " payloads)")
        
        return findings
    
    def _detect_format(self, content_type, body):
        """Detect body format"""
        content_type_lower = content_type.lower()
        
        if 'json' in content_type_lower:
            return 'json'
        elif 'xml' in content_type_lower:
            return 'xml'
        elif 'x-www-form-urlencoded' in content_type_lower:
            return 'form'
        elif 'multipart' in content_type_lower:
            return 'multipart'

        body_stripped = body.strip()
        if body_stripped.startswith('{') or body_stripped.startswith('['):
            return 'json'
        elif body_stripped.startswith('<'):
            return 'xml'
        elif '=' in body and '&' in body:
            return 'form'
        
        return None
    
    def _get_payloads_for_format(self, format_type):
        """Get payloads for specific format"""
        if format_type == 'json':
            return Payloads.get_json_breaking_payloads()
        elif format_type == 'xml':
            return Payloads.XML_STRUCTURE_BREAKING.get('tier_1_most_likely', []) + \
                   Payloads.XML_STRUCTURE_BREAKING.get('tier_2_likely', [])
        elif format_type == 'form':
            return Payloads.FORM_DATA_BREAKING.get('tier_1_most_likely', []) + \
                   Payloads.FORM_DATA_BREAKING.get('tier_2_likely', [])
        
        return []
    
    def _apply_structure_breaking(self, body, payload, format_type):
        """
        Apply structure-breaking payload to body
        
        Note: This is a simple implementation that uses the payload as-is.
        In production, you might want more sophisticated logic.
        """
        if format_type == 'json':
            return payload

        elif format_type == 'xml':
            return payload

        elif format_type == 'form':
            return payload
        
        return payload
