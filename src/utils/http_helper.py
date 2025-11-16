# -*- coding: utf-8 -*-
"""
HTTP utilities for Burp Suite (old API)
"""

import time


class HttpHelper:
    """Helper for HTTP operations via Burp"""
    
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
    
    def parse_request(self, baseRequestResponse):
        """Parse request from IHttpRequestResponse"""
        try:
            request = baseRequestResponse.getRequest()
            requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
            
            headers = {}
            for header in requestInfo.getHeaders():
                if ':' in header:
                    name, value = header.split(':', 1)
                    headers[name.strip()] = value.strip()
            
            method = requestInfo.getMethod()
            url = str(requestInfo.getUrl())
            
            bodyOffset = requestInfo.getBodyOffset()
            body = self.helpers.bytesToString(request[bodyOffset:])
            
            httpService = baseRequestResponse.getHttpService()
            
            return {
                'method': method,
                'url': url,
                'host': httpService.getHost(),
                'port': httpService.getPort(),
                'protocol': httpService.getProtocol(),
                'headers': headers,
                'body': body,
                'baseRequestResponse': baseRequestResponse
            }
        except Exception as e:
            print("[-] HttpHelper parse error: " + str(e))
            return None
    
    def parse_response(self, baseRequestResponse):
        """Parse response from IHttpRequestResponse"""
        try:
            response = baseRequestResponse.getResponse()
            if not response:
                return None
            
            responseInfo = self.helpers.analyzeResponse(response)
            
            headers = {}
            for header in responseInfo.getHeaders():
                if ':' in header:
                    name, value = header.split(':', 1)
                    headers[name.strip()] = value.strip()
            
            status = responseInfo.getStatusCode()
            bodyOffset = responseInfo.getBodyOffset()
            body = self.helpers.bytesToString(response[bodyOffset:])
            
            content_type = headers.get('Content-Type', '')
            
            return {
                'status': status,
                'headers': headers,
                'body': body,
                'content_type': content_type,
                'time': 0
            }
        except Exception as e:
            print("[-] HttpHelper response parse error: " + str(e))
            return None
    
    def send_request(self, request_dict):
        """Send HTTP request via Burp"""
        try:
            baseRequestResponse = request_dict.get('baseRequestResponse')
            if not baseRequestResponse:
                return {'status': 0, 'headers': {}, 'body': 'Error: No base request', 'content_type': '', 'time': 0}
            
            httpService = baseRequestResponse.getHttpService()
            originalRequest = baseRequestResponse.getRequest()
            
            # Build modified request
            modifiedRequest = self._build_modified_request(request_dict, originalRequest)
            
            # Send request
            start_time = time.time()
            newRequestResponse = self.callbacks.makeHttpRequest(httpService, modifiedRequest)
            
            # Parse response
            response = self.parse_response(newRequestResponse)
            if response:
                response['time'] = time.time() - start_time
                response['raw_request_bytes'] = modifiedRequest  # Store raw bytes
                return response
            else:
                # Return empty but valid response if parsing failed
                return {'status': 0, 'headers': {}, 'body': '', 'content_type': '', 'time': time.time() - start_time, 'raw_request_bytes': modifiedRequest}
            
        except Exception as e:
            print("[-] HttpHelper send error: " + str(e))
            return {'status': 0, 'headers': {}, 'body': 'Error: ' + str(e), 'content_type': '', 'time': 0}
    
    def _build_modified_request(self, request_dict, originalRequest):
        """Build modified request bytes"""
        try:
            # Get original request info
            requestInfo = self.helpers.analyzeRequest(originalRequest)
            headers = list(requestInfo.getHeaders())
            
            # Modify method or URL if needed
            if 'method' in request_dict or 'url' in request_dict:
                if headers:
                    parts = headers[0].split(' ')
                    if len(parts) >= 3:
                        # Modify method
                        if 'method' in request_dict:
                            parts[0] = request_dict['method']
                        
                        # Modify URL/path
                        if 'url' in request_dict:
                            # Extract path and query from URL
                            url = request_dict['url']
                            if '://' in url:
                                # Full URL - extract path
                                path_start = url.find('/', url.find('://') + 3)
                                if path_start > 0:
                                    parts[1] = url[path_start:]
                            else:
                                # Already just path
                                parts[1] = url
                        
                        headers[0] = ' '.join(parts)
            
            # Modify headers if needed
            if 'headers' in request_dict:
                new_headers = request_dict['headers']
                # Replace matching headers
                for i in range(1, len(headers)):
                    if ':' in headers[i]:
                        name = headers[i].split(':', 1)[0].strip()
                        if name in new_headers:
                            headers[i] = name + ': ' + str(new_headers[name])
            
            # Get body
            bodyOffset = requestInfo.getBodyOffset()
            body = request_dict.get('body', self.helpers.bytesToString(originalRequest[bodyOffset:]))
            
            # Build new request
            return self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body))
            
        except Exception as e:
            print("[-] HttpHelper build error: " + str(e))
            return originalRequest
