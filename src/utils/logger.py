# -*- coding: utf-8 -*-
"""
Simple logging utility for the extension
"""

import datetime


class Logger:
    """Simple logger for debugging"""
    
    def __init__(self, verbose=True):
        self.verbose = verbose
    
    def info(self, message):
        """Log info message"""
        if self.verbose:
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            print("[" + str(timestamp) + "] [INFO] " + str(message) + "")
    
    def error(self, message):
        """Log error message"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        print("[" + str(timestamp) + "] [ERROR] " + str(message) + "")
    
    def debug(self, message):
        """Log debug message"""
        if self.verbose:
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            print("[" + str(timestamp) + "] [DEBUG] " + str(message) + "")
    
    def success(self, message):
        """Log success message"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        print("[" + str(timestamp) + "] [SUCCESS] " + str(message) + "")
