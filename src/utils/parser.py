# -*- coding: utf-8 -*-
"""
Format parsing utilities for JSON/XML/Form data
"""

import json


class FormatParser:
    """Parser for different data formats"""
    
    @staticmethod
    def detect_format(content_type, body):
        """
        Detect body format
        
        Returns:
            String: 'json', 'xml', 'form', 'multipart', or None
        """
        content_type_lower = content_type.lower()
        
        if 'json' in content_type_lower:
            return 'json'
        elif 'xml' in content_type_lower:
            return 'xml'
        elif 'x-www-form-urlencoded' in content_type_lower:
            return 'form'
        elif 'multipart' in content_type_lower:
            return 'multipart'
        
        # Fallback: detect from body
        if body:
            body_stripped = body.strip()
            if body_stripped.startswith('{') or body_stripped.startswith('['):
                return 'json'
            elif body_stripped.startswith('<'):
                return 'xml'
            elif '=' in body and '&' in body:
                return 'form'
        
        return None
    
    @staticmethod
    def parse_json(body):
        """Parse JSON body"""
        try:
            return json.loads(body)
        except:
            return None
    
    @staticmethod
    def parse_form(body):
        """Parse form data"""
        params = {}
        for pair in body.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
        return params
    
    @staticmethod
    def rebuild_json(data):
        """Rebuild JSON from parsed data"""
        try:
            return json.dumps(data)
        except:
            return None
    
    @staticmethod
    def rebuild_form(params):
        """Rebuild form data"""
        pairs = ["{0}={1}".format(k, v) for k, v in params.items()]
        return '&'.join(pairs)
