# -*- coding: utf-8 -*-
"""
Main scanner coordinator
Orchestrates all test phases
"""

from testers.method_tester import MethodTester
from testers.header_tester import HeaderTester
from testers.structure_tester import StructureTester
from testers.parameter_tester import ParameterTester
from utils.http_helper import HttpHelper
from config.settings import ThresholdManager


class VerboseErrorScanner:
    """Main scanner that coordinates all testing phases"""
    
    def __init__(self, callbacks, helpers):
        """
        Initialize scanner
        
        Args:
            callbacks: IBurpExtenderCallbacks object
            helpers: IExtensionHelpers object
        """
        self.callbacks = callbacks
        self.helpers = helpers
        self.threshold_mgr = ThresholdManager()
        self.ui_tab = None
        self.active_scanner = None
        self.total_requests_made = 0 
        self.stop_requested = False
        
        # Initialize HTTP helper
        http_helper = HttpHelper(callbacks, helpers)
        
        # Initialize all testers
        self.method_tester = MethodTester(http_helper)
        self.header_tester = HeaderTester(http_helper)
        self.structure_tester = StructureTester(http_helper)
        self.parameter_tester = ParameterTester(http_helper)
        
        # Wire scanner reference to testers for real-time updates
        self.parameter_tester.scanner = self
        self.method_tester.scanner = self
        self.header_tester.scanner = self
        self.structure_tester.scanner = self
        
        print("[+] ErrorHound initialized")
    
    def request_stop(self):
        """Request scan to stop"""
        self.stop_requested = True
        print("[!] STOP REQUESTED - scan will terminate")
    
    def reset_stop_flag(self):
        """Reset stop flag before new scan"""
        self.stop_requested = False
    
    def should_stop(self):
        """Check if scan should stop"""
        return self.stop_requested
    
    def increment_request_count(self, count=1):
        """Increment total request counter"""
        self.total_requests_made += count
        if self.ui_tab:
            self.ui_tab.increment_stats(requests=count)
    
    def set_ui_tab(self, ui_tab):
        """Set UI tab reference for logging"""
        self.ui_tab = ui_tab
    
    def set_active_scanner(self, active_scanner):
        """Set active scanner reference"""
        self.active_scanner = active_scanner
    
    def notify_finding(self, finding):
        """Notify UI immediately when finding is discovered"""
        try:
            if self.ui_tab:
                self.ui_tab.add_finding(finding)
        
            if self.active_scanner:
                from utils.reporter import IssueReporter
                reporter = IssueReporter(self.callbacks, self.helpers)
                
                baseRequestResponse = finding.get('request', {}).get('baseRequestResponse')
                if baseRequestResponse:
                    issue = reporter.create_issue(finding, baseRequestResponse, finding.get('response'))
                    if issue:
                        self.callbacks.addScanIssue(issue)
                        print("[+] Issue added to Burp: " + issue.getIssueName())
        except Exception as e:
            print("[-] Error in notify_finding: " + str(e))
            import traceback
            traceback.print_exc()
    
    def log(self, message):
        """Log to UI if available, otherwise print"""
        if self.ui_tab:
            self.ui_tab.log(message)
        else:
            print("[*] " + message)
    
    def run_active_scan(self, baseRequestResponse):
        """
        Run full active scan on request
        
        Args:
            baseRequestResponse: IHttpRequestResponse object
            
        Returns:
            List of findings
        """
        print("\n" + "="*70)
        print("STARTING ACTIVE SCAN")
        print("="*70)
        self.log("=== ACTIVE SCAN STARTED ===")
        
        self.reset_stop_flag()
        
        if self.ui_tab:
            self.ui_tab.set_scan_running(True)
        
        # Parse request
        http_helper = HttpHelper(self.callbacks, self.helpers)
        request = http_helper.parse_request(baseRequestResponse)
        
        if not request:
            print("[-] Failed to parse request")
            self.log("ERROR: Failed to parse request")
            if self.ui_tab:
                self.ui_tab.set_scan_running(False)
            return []
        
        print("[*] Target: " + str(request['method']) + " " + str(request['url']) + "")
        self.log("Target: " + str(request['method']) + " " + str(request['url']))
        
        threshold = self.threshold_mgr.get_threshold()
        print("[*] Using threshold: " + str(threshold) + " (" + str(self.threshold_mgr.get_description()) + ")")
        self.log("Threshold: " + str(threshold) + " (" + self.threshold_mgr.get_description() + ")")
        
        print("[*] Getting baseline response...")
        self.log("Getting baseline response...")
        baseline_response = self._get_baseline(request, http_helper)
        
        if not baseline_response:
            print("[-] Failed to get baseline response")
            self.log("ERROR: Failed to get baseline")
            if self.ui_tab:
                self.ui_tab.set_scan_running(False)
            return []
        
        print("[*] Baseline: Status " + str(baseline_response['status']) + ", " + str(len(baseline_response['body'])) + " bytes")
        self.log("Baseline: HTTP " + str(baseline_response['status']) + " (" + str(len(baseline_response['body'])) + " bytes)")
        
        all_findings = []
        
        # Phase 0: HTTP Method Fuzzing
        if not self.should_stop():
            print("\n" + "-"*70)
            print("PHASE 0: HTTP METHOD FUZZING")
            print("-"*70)
            self.log("Phase 0: Testing HTTP methods...")
            method_findings = self.method_tester.test(request, baseline_response, threshold)
            all_findings.extend(method_findings)
            print("[*] Phase 0 complete: " + str(len(method_findings)) + " findings")
            self.log("Phase 0: " + str(len(method_findings)) + " findings")
        
        # Phase 1: Header Manipulation
        if not self.should_stop():
            print("\n" + "-"*70)
            print("PHASE 1: HEADER MANIPULATION")
            print("-"*70)
            self.log("Phase 1: Testing headers...")
            header_findings = self.header_tester.test(request, baseline_response, threshold)
            all_findings.extend(header_findings)
            print("[*] Phase 1 complete: " + str(len(header_findings)) + " findings")
            self.log("Phase 1: " + str(len(header_findings)) + " findings")
        
        # Phase 2: Structure Breaking
        if not self.should_stop():
            print("\n" + "-"*70)
            print("PHASE 2: BODY STRUCTURE BREAKING")
            print("-"*70)
            self.log("Phase 2: Testing structure...")
            structure_findings = self.structure_tester.test(request, baseline_response, threshold)
            all_findings.extend(structure_findings)
            print("[*] Phase 2 complete: " + str(len(structure_findings)) + " findings")
            self.log("Phase 2: " + str(len(structure_findings)) + " findings")
        
        # Phase 3: Parameter Injection
        if not self.should_stop():
            print("\n" + "-"*70)
            print("PHASE 3: PARAMETER VALUE INJECTION")
            print("-"*70)
            self.log("Phase 3: Testing parameters...")
            parameter_findings = self.parameter_tester.test(request, baseline_response, threshold)
            all_findings.extend(parameter_findings)
            print("[*] Phase 3 complete: " + str(len(parameter_findings)) + " findings")
            self.log("Phase 3: " + str(len(parameter_findings)) + " findings")
        
        # Summary
        print("\n" + "="*70)
        if self.should_stop():
            print("SCAN STOPPED BY USER")
            print("="*70)
            self.log("=== SCAN STOPPED BY USER ===")
        else:
            print("SCAN COMPLETE")
            print("="*70)
            self.log("=== SCAN COMPLETE ===")
        
        print("[+] Total findings: " + str(len(all_findings)) + "")
        print("    - Method fuzzing: " + str(len([f for f in all_findings if 'Method' in f.get('category', '')])) + "")
        print("    - Header manipulation: " + str(len([f for f in all_findings if 'Header' in f.get('category', '')])) + "")
        print("    - Structure breaking: " + str(len([f for f in all_findings if 'Structure' in f.get('category', '')])) + "")
        print("    - Parameter injection: " + str(len([f for f in all_findings if 'Parameter' in f.get('category', '')])) + "")
        print("="*70 + "\n")
        
        # Log to UI
        self.log("Total findings: " + str(len(all_findings)))
        if len(all_findings) > 0:
            method_count = len([f for f in all_findings if 'Method' in f.get('category', '')])
            header_count = len([f for f in all_findings if 'Header' in f.get('category', '')])
            structure_count = len([f for f in all_findings if 'Structure' in f.get('category', '')])
            param_count = len([f for f in all_findings if 'Parameter' in f.get('category', '')])
            self.log("Method: " + str(method_count) + " | Header: " + str(header_count) + " | Structure: " + str(structure_count) + " | Param: " + str(param_count))
        else:
            self.log("No vulnerabilities found")
        
        # Update UI to show scan complete
        if self.ui_tab:
            self.ui_tab.set_scan_running(False)
        
        return all_findings
    
    def _get_baseline(self, request, http_helper):
        """
        Get baseline response for comparison
        
        Args:
            request: Request dict
            http_helper: HttpHelper instance
            
        Returns:
            Baseline response dict
        """
        try:
            baseline = http_helper.send_request(request)
            return baseline
        except Exception as e:
            print("[-] Error getting baseline: " + str(str(e)) + "")
            return None
    
    def set_mode(self, mode):
        """Set detection mode (strict/balanced/sensitive)"""
        if self.threshold_mgr.set_mode(mode):
            print("[*] Mode set to: " + str(mode) + "")
            return True
        return False
    
    def set_custom_threshold(self, value):
        """Set custom threshold value"""
        if self.threshold_mgr.enable_custom(value):
            print("[*] Custom threshold set to: " + str(value) + "")
            return True
        return False
