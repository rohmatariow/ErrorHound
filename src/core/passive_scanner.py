# -*- coding: utf-8 -*-
"""
Passive scanner implementation for Burp Suite
Implements IScannerCheck interface
"""

from burp import IScannerCheck
from detection.detector import VerboseErrorDetector
from utils.reporter import IssueReporter
from utils.http_helper import HttpHelper
from config.settings import ThresholdManager


class PassiveScanner(IScannerCheck):
    """Passive scanner for Burp Suite (IScannerCheck)"""
    
    def __init__(self, callbacks, helpers, scanner):
        self.callbacks = callbacks
        self.helpers = helpers
        self.scanner = scanner
        self.detector = VerboseErrorDetector()
        self.reporter = IssueReporter(callbacks, helpers)
        self.http_helper = HttpHelper(callbacks, helpers)
        self.threshold_mgr = ThresholdManager()
        print("[+] Passive Scanner initialized")
    
    def doPassiveScan(self, baseRequestResponse):
        try:
            response = self.http_helper.parse_response(baseRequestResponse)
            if not response or response['status'] < 400:
                return []
            
            threshold = self.threshold_mgr.get_threshold()
            result = self.detector.detect(response, threshold=threshold)
            
            if result['vulnerable']:
                print("[+] Passive: Verbose error detected (score: " + str(result['score']) + ")")
                finding = {'category': 'Passive Detection', 'detection_result': result}
                issue = self.reporter.create_issue(finding, baseRequestResponse, response)
                if issue:
                    return [issue]
            return []
        except:
            return []
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1
