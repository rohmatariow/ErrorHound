# -*- coding: utf-8 -*-
"""
Context menu handler for Burp Suite
"""

from burp import IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
from java.lang import Thread, Runnable


class ScanRunnable(Runnable):
    """Runnable for executing scan in separate thread"""
    
    def __init__(self, callbacks, active_scanner, messages, ui_tab=None):
        self.callbacks = callbacks
        self.active_scanner = active_scanner
        self.messages = messages
        self.ui_tab = ui_tab
    
    def run(self):
        print("\n" + "="*70)
        print("CONTEXT MENU SCAN TRIGGERED")
        print("="*70)
        
        try:
            print("[*] Scanning " + str(len(self.messages)) + " request(s)...")
            
            total_issues = 0
            total_requests = 0
            
            for baseRequestResponse in self.messages:
                try:
                    if self.ui_tab:
                        self.ui_tab.increment_stats(scans=1, requests=0)
                    
                    issues = self.active_scanner.doActiveScan(baseRequestResponse, None)
                    
                    findings = self.active_scanner.get_last_findings()
                    
                    scan_requests = 1
                    scan_requests += len(findings) * 5
                    total_requests += scan_requests
                    total_issues += len(issues)
                    
                    if issues:
                        print("[+] Found " + str(len(issues)) + " issue(s)")
                    else:
                        print("[*] No vulnerabilities found")
                    
                        
                except Exception as e:
                    print("[-] Error scanning: " + str(e))
                    import traceback
                    traceback.print_exc()
            
            print("\n" + "="*70)
            print("SCAN COMPLETE - Total issues: " + str(total_issues))
            print("Check: Target -> Site map -> Issues")
            print("="*70 + "\n")
            
        except Exception as e:
            print("[-] Scan error: " + str(e))
            import traceback
            traceback.print_exc()


class ContextMenuHandler(IContextMenuFactory):
    """Handle context menu actions"""
    
    def __init__(self, callbacks, scanner, active_scanner, ui_tab=None):
        self.callbacks = callbacks
        self.scanner = scanner
        self.active_scanner = active_scanner
        self.ui_tab = ui_tab
        print("[+] Context Menu initialized")
    
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        context = invocation.getInvocationContext()
        
        if context in [0, 1, 2, 3, 4, 5, 6]:
            menu_item = JMenuItem("ErrorHound: Scan for Verbose Errors", actionPerformed=lambda x: self._scan_selected(invocation))
            menu_list.add(menu_item)
        
        return menu_list
    
    def _scan_selected(self, invocation):
        try:
            messages = invocation.getSelectedMessages()
            
            if not messages or len(messages) == 0:
                print("[-] No messages selected")
                return
            
            runnable = ScanRunnable(self.callbacks, self.active_scanner, messages, self.ui_tab)
            thread = Thread(runnable)
            thread.start()
            
            print("[*] Scan started in background thread...")
            
        except Exception as e:
            print("[-] Context menu error: " + str(e))
            import traceback
            traceback.print_exc()
