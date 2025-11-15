# -*- coding: utf-8 -*-
"""
ErrorHound - Burp Suite Extension
Implements IBurpExtender interface for Burp Suite
"""

from burp import IBurpExtender
import sys
import os

try:
    current_dir = os.path.dirname(os.path.realpath(__file__ if '__file__' in dir() else 'main.py'))
except:
    current_dir = os.getcwd()

if current_dir not in sys.path:
    sys.path.insert(0, current_dir)


class BurpExtender(IBurpExtender):
    """
    Burp Extension implementation
    Inherits from IBurpExtender interface
    """
    
    def registerExtenderCallbacks(self, callbacks):
        """
        Called by Burp when extension is loaded
        
        Args:
            callbacks: IBurpExtenderCallbacks object
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("ErrorHound")
        
        print("="*70)
        print("ErrorHound - Loading...")
        print("="*70)
        
        try:
            from config.settings import Settings, ThresholdManager
            from config.payloads import Payloads
            from detection.detector import VerboseErrorDetector
            from detection.scoring import ConfidenceScorer
            from core.scanner import VerboseErrorScanner
            from core.active_scanner import ActiveScanner
            from core.passive_scanner import PassiveScanner
            
            print("[+] All modules imported successfully")
            print("[*] Initializing components...")
            
            self._scanner = VerboseErrorScanner(callbacks, self._helpers)
            
            self._active_scanner = ActiveScanner(callbacks, self._helpers, self._scanner)
            self._passive_scanner = PassiveScanner(callbacks, self._helpers, self._scanner)
            
            from ui_tab import ExtensionTab
            self._ui_tab = ExtensionTab(callbacks, self._scanner)
            
            self._scanner.set_ui_tab(self._ui_tab)
            self._scanner.set_active_scanner(self._active_scanner)
            
            from context_menu import ContextMenuHandler
            self._context_menu = ContextMenuHandler(callbacks, self._scanner, self._active_scanner, self._ui_tab)
            
            print("[*] Registering scanner checks...")
            callbacks.registerScannerCheck(self._active_scanner)
            print("[+] Active scanner registered")
            
            callbacks.registerScannerCheck(self._passive_scanner)
            print("[+] Passive scanner registered")
            
            callbacks.registerContextMenuFactory(self._context_menu)
            print("[+] Context menu registered")
            
            callbacks.addSuiteTab(self._ui_tab)
            print("[+] UI tab registered")
            
            print("\n" + "="*70)
            print("ErrorHound LOADED SUCCESSFULLY!")
            print("="*70)
            print("\nFeatures:")
            print("  * Passive Mode: Automatic monitoring")
            print("  * Active Mode: Right-click -> Scan")
            print("  * Detection: 100+ patterns")
            print("  * Scoring: 0-100 confidence scale")
            print("  * Modes: Strict/Balanced/Sensitive")
            print("\nCurrent Mode: Balanced (threshold=15)")
            print("="*70 + "\n")
            
        except Exception as e:
            print("\n[-] ERROR: Failed to initialize extension")
            print("[-] " + str(e))
            import traceback
            traceback.print_exc()
