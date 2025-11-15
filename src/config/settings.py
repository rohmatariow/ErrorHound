# -*- coding: utf-8 -*-
"""
Configuration and preset management for Verbose Error Scanner
"""

class Settings:
    """Global settings and presets"""
    
    # Preset configurations
    PRESETS = {
        'strict': {
            'name': 'Strict',
            'description': 'Fewer findings, high confidence only',
            'use_case': 'Penetration tests, client reports',
            'min_score': 30,
            'enable_early_exit': True,
            'test_phases': {
                'method_fuzzing': True,
                'header_manipulation': True,
                'structure_breaking': True,
                'parameter_injection': True,
                'nested_manipulation': True
            },
            'request_delay': (1.0, 2.0),
            'max_threads': 3,
            'enable_false_positive_filter': True
        },
        'balanced': {
            'name': 'Balanced',
            'description': 'Recommended for most scenarios',
            'use_case': 'General testing',
            'min_score': 15,
            'enable_early_exit': True,
            'test_phases': {
                'method_fuzzing': True,
                'header_manipulation': True,
                'structure_breaking': True,
                'parameter_injection': True,
                'nested_manipulation': True
            },
            'request_delay': (0.5, 1.5),
            'max_threads': 5,
            'enable_false_positive_filter': True
        },
        'sensitive': {
            'name': 'Sensitive',
            'description': 'More findings, manual verification needed',
            'use_case': 'Bug bounty, exploration',
            'min_score': 10,
            'enable_early_exit': True,
            'test_phases': {
                'method_fuzzing': True,
                'header_manipulation': True,
                'structure_breaking': True,
                'parameter_injection': True,
                'nested_manipulation': True
            },
            'request_delay': (0.3, 1.0),
            'max_threads': 8,
            'enable_false_positive_filter': False
        }
    }
    
    # Detection settings
    DETECTION = {
        'status_codes_of_interest': [400, 401, 403, 404, 405, 500, 501, 502, 503],
        'response_length_threshold': 0.3,  # 30% change from baseline
        'response_time_threshold': 2.0,    # 2x slower than baseline
        'max_evidence_samples': 5,         # Max samples to collect per type
    }
    
    # Performance settings
    PERFORMANCE = {
        'request_timeout': 30,              # seconds
        'max_requests_per_minute': 60,
        'enable_adaptive_throttling': True,
        'cache_ttl': 3600,                 # 1 hour
        'max_cache_size': 1000,            # entries
    }
    
    # Scope settings
    SCOPE = {
        'use_burp_scope': True,
        'exclude_extensions': ['.js', '.css', '.png', '.jpg', '.gi', '.svg', '.ico', '.wof', '.tt'],
        'exclude_mime_types': ['image/', 'font/', 'video/', 'audio/']
    }
    
    # UI settings
    UI = {
        'show_advanced_options': False,
        'auto_scroll_to_findings': True,
        'max_findings_display': 100
    }


class ThresholdManager:
    """Manage detection threshold (preset or custom)"""
    
    def __init__(self):
        self.mode = 'balanced'
        self.custom_enabled = False
        self.custom_threshold = None
    
    def get_threshold(self):
        """Get current threshold value"""
        if self.custom_enabled and self.custom_threshold is not None:
            return self.custom_threshold
        return Settings.PRESETS[self.mode]['min_score']
    
    def set_mode(self, mode):
        """Set preset mode"""
        if mode in Settings.PRESETS:
            self.mode = mode
            self.custom_enabled = False
            return True
        return False
    
    def enable_custom(self, value):
        """Enable custom threshold"""
        if 0 <= value <= 100:
            self.custom_enabled = True
            self.custom_threshold = value
            return True
        return False
    
    def get_current_preset(self):
        """Get current preset configuration"""
        if self.custom_enabled:
            return None
        return Settings.PRESETS[self.mode]
    
    def get_description(self):
        """Get description of current mode"""
        if self.custom_enabled:
            return "Custom threshold: {0}".format(self.custom_threshold)
        return Settings.PRESETS[self.mode]['description']
