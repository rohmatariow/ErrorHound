# -*- coding: utf-8 -*-
"""
Issue reporter for Burp Scanner with highlighting support
"""

from burp import IScanIssue, IHttpRequestResponse, IHttpRequestResponseWithMarkers
from java.net import URL
from java.util import ArrayList, List
from array import array


class IssueReporter:
    """Report findings to Burp Scanner"""
    
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
    
    def create_issue(self, finding, baseRequestResponse, response_dict):
        """Create custom IScanIssue with vuln request/response and highlighting"""
        try:
            detection_result = finding.get('detection_result', {})
            confidence = detection_result.get('confidence', 'Certain')
            
            # Determine severity based on response content sensitivity
            severity = self._determine_severity(response_dict, detection_result)
            
            # Simple, clear issue name
            issue_name = "Verbose Error Message"
            
            # Create request/response for the ACTUAL vulnerability
            vuln_request = finding.get('request')
            vuln_response = response_dict
            
            # Build vulnerable IHttpRequestResponseWithMarkers (with highlight support)
            httpService = baseRequestResponse.getHttpService()
            vuln_message = self._create_http_message_with_markers(httpService, vuln_request, vuln_response, finding)
            
            issue = CustomScanIssue(
                httpService,
                self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [vuln_message],
                issue_name,
                self._build_detail(finding, detection_result, vuln_message, severity),
                severity,
                confidence
            )
            return issue
        except Exception as e:
            print("[-] Reporter error: " + str(e))
            import traceback
            traceback.print_exc()
            return None
    
    def _determine_severity(self, response_dict, detection_result):
        """Determine severity based on response content"""
        body = response_dict.get('body', '').lower()
        
        # HIGH: Credentials or highly sensitive data exposed
        high_keywords = [
            'password', 'passwd', 'pwd=', 'secret', 'api_key', 'apikey', 
            'private_key', 'privatekey', 'access_token', 'accesstoken',
            'db_password', 'database_password', 'connection_string',
            'aws_secret', 'mysql_password', 'postgres_password'
        ]
        
        for keyword in high_keywords:
            if keyword in body:
                return "HIGH"
        
        # MEDIUM: Sensitive configuration or internal info (need multiple indicators)
        medium_keywords = [
            '/etc/', '/var/', '/usr/', 'c:\\', 'database', 'config',
            'version', 'internal', 'localhost', '127.0.0.1', '192.168.'
        ]
        
        medium_count = 0
        for keyword in medium_keywords:
            if keyword in body:
                medium_count += 1
                if medium_count >= 3:  # Multiple sensitive indicators
                    return "MEDIUM"
        
        # Default: LOW (just error disclosure, no critical data)
        return "LOW"
    
    def _create_http_message_with_markers(self, httpService, request_dict, response_dict, finding):
        """Create IHttpRequestResponseWithMarkers with highlighting"""
        try:
            # Get request bytes
            if 'raw_request_bytes' in response_dict:
                request_bytes = response_dict['raw_request_bytes']
            elif 'raw_bytes' in request_dict:
                request_bytes = request_dict['raw_bytes']
            else:
                request_bytes = self._build_request_bytes(request_dict)
            
            # Build response bytes
            response_bytes = self._build_response_bytes(response_dict)
            
            # Calculate markers
            request_markers = self._get_request_markers(finding, request_bytes)
            response_markers = self._get_response_markers(response_dict, response_bytes)
            
            # Create message with markers
            return HttpRequestResponseWithMarkers(httpService, request_bytes, response_bytes, 
                                                 request_markers, response_markers)
            
        except Exception as e:
            print("[-] Error creating HTTP message: " + str(e))
            import traceback
            traceback.print_exc()
            return None
    
    def _build_request_bytes(self, request_dict):
        """Build request bytes from dict"""
        lines = []
        
        # Request line
        method = request_dict.get('method', 'GET')
        url = request_dict.get('url', '/')
        if '://' in url:
            path = '/' + url.split('/', 3)[3] if url.count('/') >= 3 else '/'
        else:
            path = url
        lines.append(method + ' ' + path + ' HTTP/1.1')
        
        # Headers
        headers = request_dict.get('headers', {})
        for name, value in headers.items():
            lines.append(name + ': ' + str(value))
        
        # Body
        body = request_dict.get('body', '')
        request_str = '\r\n'.join(lines) + '\r\n\r\n' + body
        
        return self.helpers.stringToBytes(request_str)
    
    def _build_response_bytes(self, response_dict):
        """Build response bytes from dict"""
        lines = []
        
        # Status line
        status = response_dict.get('status', 200)
        lines.append('HTTP/1.1 ' + str(status) + ' OK')
        
        # Headers
        headers = response_dict.get('headers', {})
        for name, value in headers.items():
            lines.append(name + ': ' + str(value))
        
        # Body
        body = response_dict.get('body', '')
        response_str = '\r\n'.join(lines) + '\r\n\r\n' + body
        
        return self.helpers.stringToBytes(response_str)
    
    def _get_request_markers(self, finding, request_bytes):
        """Get request markers for payload highlighting"""
        try:
            if not request_bytes:
                return None
            
            request_str = self.helpers.bytesToString(request_bytes)
            
            # Find payload in request
            payload = None
            if 'test_payload' in finding:
                payload = str(finding['test_payload'])
            elif 'test_method' in finding:
                payload = finding['test_method']
            elif 'test_value' in finding:
                payload = str(finding['test_value'])
            
            if payload and len(payload) > 1:
                start = request_str.find(payload)
                if start >= 0:
                    markers = ArrayList()
                    markers.add(array('i', [start, start + len(payload)]))
                    return markers
            
            return None
        except Exception as e:
            print("[-] Error getting request markers: " + str(e))
            return None
    
    def _get_response_markers(self, response_dict, response_bytes):
        """Get response markers for error highlighting"""
        try:
            if not response_bytes:
                return None
            
            response_str = self.helpers.bytesToString(response_bytes)
            
            # Find error keywords
            error_keywords = ['Fatal error', 'Exception', 'Error:', 'Traceback', 'Stack trace',
                            'at java.', 'at org.', 'SQLException', 'Warning:', 'Notice:',
                            'TypeError', 'SyntaxError', 'ValueError', 'RuntimeError']
            
            markers = ArrayList()
            
            for keyword in error_keywords:
                start = 0
                while True:
                    pos = response_str.find(keyword, start)
                    if pos < 0:
                        break
                    # Highlight entire error line
                    end_pos = min(pos + 200, len(response_str))
                    newline_pos = response_str.find('\n', pos)
                    if newline_pos > 0 and newline_pos < end_pos:
                        end_pos = newline_pos
                    markers.add(array('i', [pos, end_pos]))
                    start = end_pos
                    if len(markers) >= 5:
                        break
                if len(markers) >= 5:
                    break
            
            return markers if len(markers) > 0 else None
        except Exception as e:
            print("[-] Error getting response markers: " + str(e))
            return None
    
    def _build_detail(self, finding, detection_result, vuln_message, severity):
        """Build issue detail HTML with payload location info"""
        lines = []
        lines.append("<b>Verbose Error Message Detected</b><br><br>")
        
        # Basic info
        lines.append("Category: " + str(finding.get('category', 'Unknown')) + "<br>")
        lines.append("Score: " + str(detection_result.get('score', 0)) + "/100<br>")
        lines.append("Severity: " + severity + "<br><br>")
        
        # Payload location info (TEXT FALLBACK)
        lines.append("<b>Payload Information:</b><br>")
        
        payload_info = self._get_payload_location_info(finding, vuln_message)
        if payload_info:
            lines.append(payload_info)
        
        # Parameter/Header/Method info
        if 'test_payload' in finding:
            lines.append("<b>Test Payload:</b> <code>" + self._escape_html(str(finding['test_payload'])[:200]) + "</code><br>")
        if 'parameter_name' in finding:
            lines.append("<b>Parameter:</b> " + self._escape_html(finding['parameter_name']) + "<br>")
        if 'header_name' in finding:
            lines.append("<b>Header:</b> " + self._escape_html(finding['header_name']) + "<br>")
        if 'test_method' in finding:
            lines.append("<b>Method:</b> " + self._escape_html(finding['test_method']) + "<br>")
        
        lines.append("<br>")
        
        # Evidence
        evidences = detection_result.get('evidences', [])
        if evidences:
            lines.append("<b>Evidence:</b><br>")
            for evidence in evidences:
                desc = evidence.get('description', '')
                points = evidence.get('points', 0)
                lines.append("&nbsp;&nbsp;- " + self._escape_html(desc) + " (+" + str(points) + " points)<br>")
        
        return ''.join(lines)
    
    def _get_payload_location_info(self, finding, vuln_message):
        """Get detailed payload location info for text display"""
        try:
            if not vuln_message:
                return None
            
            request_bytes = vuln_message.getRequest()
            if not request_bytes:
                return None
            
            request_str = self.helpers.bytesToString(request_bytes)
            
            # Find payload
            payload = None
            if 'test_payload' in finding:
                payload = str(finding['test_payload'])
            elif 'test_method' in finding:
                payload = finding['test_method']
            elif 'test_value' in finding:
                payload = str(finding['test_value'])
            
            if not payload:
                return None
            
            start = request_str.find(payload)
            if start < 0:
                return None
            
            end = start + len(payload)
            
            # Count line number
            line_num = request_str[:start].count('\n') + 1
            
            # Get context (50 chars before and after)
            context_start = max(0, start - 50)
            context_end = min(len(request_str), end + 50)
            context = request_str[context_start:context_end]
            
            # Mark payload in context
            payload_pos_in_context = start - context_start
            marked_context = (context[:payload_pos_in_context] + 
                            "<b style='color:red'>" + payload + "</b>" + 
                            context[payload_pos_in_context + len(payload):])
            
            info = []
            info.append("<b>Location:</b> Line " + str(line_num) + ", bytes " + str(start) + "-" + str(end) + "<br>")
            info.append("<b>Context:</b><br>")
            info.append("<code style='background-color:#f0f0f0; padding:5px; display:block; white-space:pre-wrap;'>")
            info.append(self._escape_html_except_tags(marked_context))
            info.append("</code><br>")
            
            return ''.join(info)
            
        except Exception as e:
            print("[-] Error getting payload location: " + str(e))
            return None
    
    def _escape_html(self, text):
        """Escape HTML special chars"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))
    
    def _escape_html_except_tags(self, text):
        """Escape HTML but keep <b> tags"""
        # Simple approach: only escape & < > outside of our tags
        import re
        # Replace & not followed by amp; lt; gt; quot; #x27;
        text = re.sub(r'&(?!(amp|lt|gt|quot|#x27);)', '&amp;', text)
        # Replace < not followed by b> or /b>
        text = re.sub(r'<(?!/?b[> ])', '&lt;', text)
        # Replace > not preceded by b or /b
        text = re.sub(r'(?<![b\'/])>', '&gt;', text)
        return text


class HttpRequestResponseWithMarkers(IHttpRequestResponseWithMarkers):
    """IHttpRequestResponseWithMarkers implementation with marker support"""
    
    def __init__(self, httpService, request, response, request_markers=None, response_markers=None):
        self._httpService = httpService
        self._request = request
        self._response = response
        self._comment = None
        self._highlight = None
        self._request_markers = request_markers if request_markers else ArrayList()
        self._response_markers = response_markers if response_markers else ArrayList()
    
    def getRequest(self):
        return self._request
    
    def setRequest(self, request):
        self._request = request
    
    def getResponse(self):
        return self._response
    
    def setResponse(self, response):
        self._response = response
    
    def getComment(self):
        return self._comment
    
    def setComment(self, comment):
        self._comment = comment
    
    def getHighlight(self):
        return self._highlight
    
    def setHighlight(self, color):
        self._highlight = color
    
    def getHttpService(self):
        return self._httpService
    
    def setHttpService(self, httpService):
        self._httpService = httpService
    
    # IHttpRequestResponseWithMarkers specific methods
    def getRequestMarkers(self):
        """Return request markers for Burp highlighting"""
        return self._request_markers
    
    def getResponseMarkers(self):
        """Return response markers for Burp highlighting"""
        return self._response_markers


class CustomScanIssue(IScanIssue):
    """Custom IScanIssue implementation"""
    
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        if 'HIGH' in self._severity.upper() or 'CRITICAL' in self._severity.upper():
            return "High"
        elif 'MEDIUM' in self._severity.upper():
            return "Medium"
        elif 'LOW' in self._severity.upper():
            return "Low"
        return "Information"
    
    def getConfidence(self):
        if 'HIGH' in self._confidence.upper():
            return "Certain"
        elif 'MEDIUM' in self._confidence.upper():
            return "Firm"
        return "Tentative"
    
    def getIssueBackground(self):
        return None
    
    def getRemediationBackground(self):
        return None
    
    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return "Implement proper error handling. Disable debug mode in production. Return generic error messages."
    
    def getHttpMessages(self):
        """Return HttpRequestResponseWithMarkers for highlighting support"""
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService
