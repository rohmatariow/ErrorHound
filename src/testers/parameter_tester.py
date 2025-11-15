# -*- coding: utf-8 -*-
"""
Parameter Value Injection Tester
Tests parameters with injection payloads (SQL, XSS, etc.)
"""

import json
from config.payloads import Payloads
from detection.detector import VerboseErrorDetector


class ParameterTester:
    """Test parameters with injection payloads"""
    
    def __init__(self, http_helper):
        """
        Initialize parameter tester
        
        Args:
            http_helper: HttpHelper instance for sending requests
        """
        self.http_helper = http_helper
        self.detector = VerboseErrorDetector()
        self.enable_early_exit = True
    
    def test(self, request, baseline_response, threshold=15):
        """
        Test parameters with injection payloads
        
        Args:
            request: Original request dict
            baseline_response: Baseline response for comparison
            threshold: Detection threshold
            
        Returns:
            List of findings
        """
        findings = []
        
        # Extract parameters from request
        parameters = self._extract_parameters(request)
        
        if not parameters:
            print("[*] Parameter Tester: No parameters found in request")
            return findings
        
        print("[*] Parameter Tester: Found " + str(len(parameters)) + " parameters to test")
        
        for param_name, param_value, param_location in parameters:
            print("[*] Parameter Tester: Testing parameter '" + str(param_name) + "' (location: " + str(param_location) + ")")
            
            param_findings = self._test_single_parameter(
                request,
                param_name,
                param_value,
                param_location,
                baseline_response,
                threshold
            )
            
            findings.extend(param_findings)
        
        print("[*] Parameter Tester: Complete. Found " + str(len(findings)) + " vulnerabilities")
        
        return findings
    
    def _test_single_parameter(self, request, param_name, param_value, param_location, baseline_response, threshold):
        """Test a single parameter with injection payloads"""
        findings = []
        
        # Get ALL injection payloads (not just SQL)
        all_payloads = Payloads.get_parameter_payloads('all')
        
        print("[*] Parameter Tester: Testing '" + param_name + "' with " + str(len(all_payloads)) + " payloads")
        
        tested_count = 0
        for payload in all_payloads:
            tested_count += 1
            
            if hasattr(self, 'scanner') and self.scanner and self.scanner.should_stop():
                print("[!] Parameter Tester: STOP requested - terminating")
                break
            
            if tested_count % 5 == 0:
                print("[*] Parameter Tester: Progress - tested " + str(tested_count) + "/" + str(len(all_payloads)))
            
            modified_request = self._modify_parameter(
                request,
                param_name,
                payload,
                param_location
            )
            
            if not modified_request:
                continue
            
            try:
                if tested_count <= 3:
                    print("[DEBUG] Payload: " + str(payload)[:30])
                    if param_location == 'url':
                        print("[DEBUG] Modified URL: " + str(modified_request.get('url', 'N/A'))[:100])
                
                response = self.http_helper.send_request(modified_request)
                
                if hasattr(self, 'scanner') and self.scanner:
                    self.scanner.increment_request_count(1)
                
                if tested_count <= 3:
                    print("[DEBUG] Response status: " + str(response.get('status', 'N/A')))
                    print("[DEBUG] Response body length: " + str(len(response.get('body', ''))))
                    print("[DEBUG] Response body preview: " + str(response.get('body', ''))[:100])
                
                # Detect verbose error
                result = self.detector.detect(response, baseline_response, threshold)
                
                if result['vulnerable']:
                    print("[+] Parameter Tester: Vulnerability found in parameter '" + str(param_name) + "'!")
                    print("[+] Payload: " + str(payload)[:50])
                    print("[+] Score: " + str(result['score']) + " | Severity: " + result['severity'])
                    
                    finding = {
                        'category': 'Parameter Value Injection',
                        'parameter_name': param_name,
                        'parameter_location': param_location,
                        'original_value': param_value,
                        'test_payload': payload,
                        'detection_result': result,
                        'request': modified_request,
                        'response': response
                    }
                    findings.append(finding)
                    
                    if hasattr(self, 'scanner') and self.scanner:
                        self.scanner.notify_finding(finding)
                    
                    if self.enable_early_exit:
                        print("[*] Parameter Tester: Early exit for '" + str(param_name) + "' (tested " + str(tested_count) + "/" + str(len(all_payloads)) + " payloads)")
                        break
                        
            except Exception as e:
                print("[-] Parameter Tester: Error testing parameter '" + str(param_name) + "': " + str(str(e)) + "")
                continue
        
        return findings
    
    def _extract_parameters(self, request):
        """
        Extract parameters from request
        
        Returns:
            List of tuples: (param_name, param_value, location)
        """
        parameters = []
        
        # 1. URL parameters
        url = request.get('url', '')
        if '?' in url:
            query_string = url.split('?', 1)[1]
            for pair in query_string.split('&'):
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    parameters.append((name, value, 'url'))
        
        # 2. Body parameters (JSON)
        body = request.get('body', '')
        content_type = request.get('headers', {}).get('Content-Type', '')
        
        if 'json' in content_type.lower() and body:
            try:
                json_data = json.loads(body)
                params = self._extract_json_params(json_data)
                for name, value in params:
                    parameters.append((name, value, 'json'))
            except:
                pass
        
        # 3. Body parameters (form data)
        elif 'x-www-form-urlencoded' in content_type.lower() and body:
            for pair in body.split('&'):
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    parameters.append((name, value, 'form'))
        
        return parameters
    
    def _extract_json_params(self, json_data, prefix=''):
        """Extract parameters from JSON recursively"""
        params = []
        
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                full_key = "{0}.{1}".format(prefix, key) if prefix else key
                
                if isinstance(value, (dict, list)):
                    params.extend(self._extract_json_params(value, full_key))
                else:
                    params.append((full_key, str(value)))
        
        elif isinstance(json_data, list):
            for i, item in enumerate(json_data):
                full_key = "{0}[{1}]".format(prefix, i)
                if isinstance(item, (dict, list)):
                    params.extend(self._extract_json_params(item, full_key))
                else:
                    params.append((full_key, str(item)))
        
        return params
    
    def _modify_parameter(self, request, param_name, payload, param_location):
        """Modify a parameter with payload"""
        modified_request = request.copy()
        
        try:
            if param_location == 'url':
                url = modified_request['url']
                if '?' in url:
                    base_url, query = url.split('?', 1)
                    params = []
                    for pair in query.split('&'):
                        if '=' in pair:
                            name, value = pair.split('=', 1)
                            if name == param_name:
                                params.append("{0}={1}".format(name, payload))
                            else:
                                params.append(pair)
                        else:
                            params.append(pair)
                    modified_request['url'] = "{0}?{1}".format(base_url, '&'.join(params))
            
            elif param_location == 'json':
                body = modified_request.get('body', '')
                
                # Check if payload is a syntax corruption payload
                is_corruption = False
                corruption_payloads = ['10test', '10tes', '123abc', '99invalid', 'trues', 'falses', 
                                      'True', 'FALSE', 'test"quote', "test'quote", '10.5.5']
                if payload in corruption_payloads:
                    is_corruption = True
                
                if is_corruption:
                    import re
                    final_key = param_name.split('.')[-1].split('[')[0]
                    
                    patterns = [
                        (r'"' + re.escape(final_key) + r'"\s*:\s*"[^"]*"', 
                         '"' + final_key + '": ' + payload),
                        (r'"' + re.escape(final_key) + r'"\s*:\s*-?\d+\.?\d*',
                         '"' + final_key + '": ' + payload),
                        (r'"' + re.escape(final_key) + r'"\s*:\s*(true|false)',
                         '"' + final_key + '": ' + payload),
                    ]
                    
                    replaced = False
                    for pattern, replacement in patterns:
                        if re.search(pattern, body):
                            body = re.sub(pattern, replacement, body, count=1)
                            replaced = True
                            break
                    
                    if replaced:
                        modified_request['body'] = body
                    else:
                        json_data = json.loads(body)
                        keys = param_name.split('.')
                        current = json_data
                        for key in keys[:-1]:
                            if '[' in key:
                                key_name = key.split('[')[0]
                                index = int(key.split('[')[1].rstrip(']'))
                                current = current[key_name][index]
                            else:
                                current = current[key]
                        
                        final_key = keys[-1]
                        if '[' in final_key:
                            key_name = final_key.split('[')[0]
                            index = int(final_key.split('[')[1].rstrip(']'))
                            current[key_name][index] = payload
                        else:
                            current[final_key] = payload
                        
                        modified_request['body'] = json.dumps(json_data)
                else:
                    json_data = json.loads(body)
            
                    keys = param_name.split('.')
                    current = json_data
                    for key in keys[:-1]:
                        if '[' in key:
                            key_name = key.split('[')[0]
                            index = int(key.split('[')[1].rstrip(']'))
                            current = current[key_name][index]
                        else:
                            current = current[key]
                    
                    final_key = keys[-1]
                    if '[' in final_key:
                        key_name = final_key.split('[')[0]
                        index = int(final_key.split('[')[1].rstrip(']'))
                        current[key_name][index] = payload
                    else:
                        current[final_key] = payload
                    
                    modified_request['body'] = json.dumps(json_data)
            
            elif param_location == 'form':
                body = modified_request.get('body', '')
                params = []
                for pair in body.split('&'):
                    if '=' in pair:
                        name, value = pair.split('=', 1)
                        if name == param_name:
                            params.append("{0}={1}".format(name, payload))
                        else:
                            params.append(pair)
                    else:
                        params.append(pair)
                modified_request['body'] = '&'.join(params)
            
            return modified_request
            
        except Exception as e:
            print("[-] Parameter Tester: Error modifying parameter '" + str(param_name) + "': " + str(str(e)) + "")
            return None
