# -*- coding: utf-8 -*-
"""
Active scanner implementation for Burp Suite
"""

from burp import IScannerCheck
from utils.reporter import IssueReporter


class ActiveScanner(IScannerCheck):
    """Active scanner for Burp Suite"""
    
    def __init__(self, callbacks, helpers, scanner):
        self.callbacks = callbacks
        self.helpers = helpers
        self.scanner = scanner
        self.reporter = IssueReporter(callbacks, helpers)
        self.last_findings = []
        print("[+] Active Scanner initialized")
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        try:
            print("\n[*] Active scan triggered")
            findings = self.scanner.run_active_scan(baseRequestResponse)
            
            self.last_findings = findings
            
            # Convert to issues
            issues = []
            for finding in findings:
                issue = self.reporter.create_issue(finding, baseRequestResponse, finding.get('response'))
                if issue:
                    issues.append(issue)
            
            print("[+] Active scan complete: " + str(len(issues)) + " issues")
            return issues
            
        except Exception as e:
            print("[-] Error in active scan: " + str(e))
            import traceback
            traceback.print_exc()
            return []
    
    def get_last_findings(self):
        """Get last scan findings (for UI)"""
        return self.last_findings
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1
