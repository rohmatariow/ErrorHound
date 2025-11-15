# -*- coding: utf-8 -*-
"""
Extension UI Tab - Full Featured
"""

from burp import ITab, IMessageEditorController
from javax.swing import (JPanel, JLabel, JButton, JTextArea, JScrollPane, 
                         BoxLayout, Box, BorderFactory, JComboBox, 
                         JTextField, JCheckBox, JSpinner, SpinnerNumberModel,
                         JTable, JTabbedPane, SwingUtilities, JSplitPane, ListSelectionModel)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.awt import Dimension, Color, Font, BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener


class ExtensionTab(ITab, IMessageEditorController):
    """Main extension tab with request/response viewer"""
    
    def __init__(self, callbacks, scanner):
        self.callbacks = callbacks
        self.scanner = scanner
        self.vuln_count = 0
        self.scan_count = 0
        self.request_count = 0
        self.findings_list = []
        self.current_finding = None
        
        self.request_viewer = callbacks.createMessageEditor(self, False)
        self.response_viewer = callbacks.createMessageEditor(self, False)
        
        self.tabbedPane = JTabbedPane()
        
        # Tabs
        self.tabbedPane.addTab("Configuration", self._create_config_panel())
        self.tabbedPane.addTab("Results", self._create_results_panel())
        self.tabbedPane.addTab("Statistics", self._create_stats_panel())
        self.tabbedPane.addTab("Logs", self._create_logs_panel())
        
        print("[+] Extension Tab initialized")
    
    def _create_config_panel(self):
        """Configuration panel"""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        
        title = JLabel("ErrorHound Configuration")
        title.setFont(Font("Arial", Font.BOLD, 18))
        panel.add(title)

        subtitle = JLabel("by @rohmatariow")
        subtitle.setFont(Font("Arial", Font.ITALIC, 10))
        subtitle.setForeground(Color(100, 100, 100))
        panel.add(subtitle)
        
        panel.add(Box.createRigidArea(Dimension(0, 20)))
        
        panel.add(self._create_mode_panel())
        
        panel.add(Box.createVerticalGlue())
        return panel
    
    def _create_mode_panel(self):
        """Mode selection panel"""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder("Detection Mode"))
        panel.setMaximumSize(Dimension(999999, 150))
        
        mode_select = JPanel(FlowLayout(FlowLayout.LEFT))
        mode_select.add(JLabel("Mode: "))
        
        modes = ["Strict (30)", "Balanced (15)", "Sensitive (10)", "Custom"]
        self.mode_combo = JComboBox(modes)
        self.mode_combo.setSelectedIndex(1)
        self.mode_combo.addActionListener(lambda e: self._on_mode_change())
        mode_select.add(self.mode_combo)
        panel.add(mode_select)
        
        desc = JTextArea(3, 50)
        desc.setEditable(False)
        desc.setLineWrap(True)
        desc.setWrapStyleWord(True)
        desc.setText(
            "Strict: High confidence only (30+) - Minimal FPs, best for reports\n" +
            "Balanced: Recommended (15+) - Good balance of coverage and accuracy\n" +
            "Sensitive: Maximum coverage (10+) - May include lower confidence findings"
        )
        desc.setBackground(panel.getBackground())
        panel.add(desc)
        
        return panel
    
    def _create_advanced_panel(self):
        """Advanced settings panel"""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder("Advanced Settings (Custom Mode)"))
        panel.setMaximumSize(Dimension(999999, 350))
        
        # Threshold
        threshold_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        threshold_panel.add(JLabel("Detection Threshold (0-100): "))
        self.threshold_spinner = JSpinner(SpinnerNumberModel(15, 0, 100, 1))
        self.threshold_spinner.setEnabled(False)
        threshold_panel.add(self.threshold_spinner)
        apply_btn = JButton("Apply", actionPerformed=lambda e: self._apply_custom())
        threshold_panel.add(apply_btn)
        panel.add(threshold_panel)
        
        panel.add(Box.createRigidArea(Dimension(0, 10)))
        
        perf_label = JLabel("Performance Options:")
        perf_label.setFont(Font("Arial", Font.BOLD, 12))
        panel.add(perf_label)
        
        self.early_exit_check = JCheckBox("Enable Early Exit (70-90% faster)", True)
        panel.add(self.early_exit_check)
        
        self.max_payloads_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.max_payloads_panel.add(JLabel("Max Payloads per Category: "))
        self.max_payloads_spinner = JSpinner(SpinnerNumberModel(50, 1, 500, 10))
        self.max_payloads_panel.add(self.max_payloads_spinner)
        panel.add(self.max_payloads_panel)
        
        panel.add(Box.createRigidArea(Dimension(0, 10)))
        
        phases_label = JLabel("Active Test Phases:")
        phases_label.setFont(Font("Arial", Font.BOLD, 12))
        panel.add(phases_label)
        
        self.phase_method = JCheckBox("Phase 0: HTTP Method Fuzzing (20+ methods)", True)
        panel.add(self.phase_method)
        
        self.phase_header = JCheckBox("Phase 1: Header Manipulation (ALL headers, 15+ payloads each)", True)
        panel.add(self.phase_header)
        
        self.phase_structure = JCheckBox("Phase 2: Body Structure Breaking (JSON/XML/Form)", True)
        panel.add(self.phase_structure)
        
        self.phase_param = JCheckBox("Phase 3: Parameter Injection (SQL, XSS, etc)", True)
        panel.add(self.phase_param)
        
        panel.add(Box.createRigidArea(Dimension(0, 10)))
        
        det_label = JLabel("Detection Options:")
        det_label.setFont(Font("Arial", Font.BOLD, 12))
        panel.add(det_label)
        
        self.fp_filter_check = JCheckBox("Enable False Positive Filtering", True)
        panel.add(self.fp_filter_check)
        
        self.passive_scan_check = JCheckBox("Enable Passive Scanning", True)
        panel.add(self.passive_scan_check)
        
        return panel
    
    def _create_status_panel(self):
        """Status panel with stop button"""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder("Current Status"))
        panel.setMaximumSize(Dimension(999999, 120))
        
        self.status_label = JLabel("Extension Status: Active")
        self.status_label.setForeground(Color(0, 128, 0))
        panel.add(self.status_label)
        
        self.mode_display_label = JLabel("Current Mode: Balanced (threshold=15)")
        panel.add(self.mode_display_label)
        
        self.scan_status_label = JLabel("Scan Status: Idle")
        panel.add(self.scan_status_label)
        
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.stop_button = JButton("Stop Scan", actionPerformed=lambda e: self._stop_scan())
        self.stop_button.setEnabled(False)
        self.stop_button.setBackground(Color(200, 50, 50))
        self.stop_button.setForeground(Color.WHITE)
        button_panel.add(self.stop_button)
        panel.add(button_panel)
        
        return panel
    
    def _create_results_panel(self):
        """Results display with req/resp viewer"""
        panel = JPanel(BorderLayout())
        
        top_panel = JPanel(BorderLayout())
        top_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10))
        
        title_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("Vulnerability Findings")
        title.setFont(Font("Arial", Font.BOLD, 16))
        title_panel.add(title)
        clear_btn = JButton("Clear All", actionPerformed=lambda e: self._clear_results())
        title_panel.add(clear_btn)
        top_panel.add(title_panel, BorderLayout.NORTH)
        
        columns = ["#", "Host", "Method", "URL", "Status", "Length", "Severity", "Category", "Location", "Score", "Time"]
        self.results_model = DefaultTableModel(columns, 0)
        self.results_table = JTable(self.results_model)
        
        from javax.swing.table import TableRowSorter
        sorter = TableRowSorter(self.results_model)
        
        from java.util import Comparator
        class IntegerComparator(Comparator):
            def compare(self, o1, o2):
                try:
                    return int(o1) - int(o2)
                except:
                    return 0
        
        sorter.setComparator(0, IntegerComparator())
        sorter.setComparator(4, IntegerComparator())
        sorter.setComparator(5, IntegerComparator())
        sorter.setComparator(9, IntegerComparator())
        
        self.results_table.setRowSorter(sorter)
        self.results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        
        selection_model = self.results_table.getSelectionModel()
        selection_model.addListSelectionListener(ResultsSelectionListener(self))
        
        self.results_table.getColumnModel().getColumn(0).setPreferredWidth(40)   # #
        self.results_table.getColumnModel().getColumn(1).setPreferredWidth(150)  # Host
        self.results_table.getColumnModel().getColumn(2).setPreferredWidth(60)   # Method
        self.results_table.getColumnModel().getColumn(3).setPreferredWidth(200)  # URL
        self.results_table.getColumnModel().getColumn(4).setPreferredWidth(60)   # Status
        self.results_table.getColumnModel().getColumn(5).setPreferredWidth(70)   # Length
        self.results_table.getColumnModel().getColumn(6).setPreferredWidth(80)   # Severity
        self.results_table.getColumnModel().getColumn(7).setPreferredWidth(150)  # Category
        self.results_table.getColumnModel().getColumn(8).setPreferredWidth(200)  # Location
        self.results_table.getColumnModel().getColumn(9).setPreferredWidth(60)   # Score
        self.results_table.getColumnModel().getColumn(10).setPreferredWidth(80)  # Time
        
        scroll = JScrollPane(self.results_table)
        scroll.setPreferredSize(Dimension(800, 200))
        top_panel.add(scroll, BorderLayout.CENTER)
        
        self.summary_label = JLabel("Total Findings: 0")
        self.summary_label.setFont(Font("Arial", Font.BOLD, 12))
        top_panel.add(self.summary_label, BorderLayout.SOUTH)
        
        bottom_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        bottom_panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10))
        
        req_panel = JPanel(BorderLayout())
        req_panel.setBorder(BorderFactory.createTitledBorder("Request"))
        req_panel.add(self.request_viewer.getComponent(), BorderLayout.CENTER)
        
        resp_panel = JPanel(BorderLayout())
        resp_panel.setBorder(BorderFactory.createTitledBorder("Response"))
        resp_panel.add(self.response_viewer.getComponent(), BorderLayout.CENTER)
        
        bottom_panel.setLeftComponent(req_panel)
        bottom_panel.setRightComponent(resp_panel)
        bottom_panel.setDividerLocation(400)
        
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split.setTopComponent(top_panel)
        main_split.setBottomComponent(bottom_panel)
        main_split.setDividerLocation(250)
        
        panel.add(main_split, BorderLayout.CENTER)
        return panel
    
    def _create_stats_panel(self):
        """Statistics with clear button"""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        
        title = JLabel("Scan Statistics")
        title.setFont(Font("Arial", Font.BOLD, 18))
        title.setAlignmentX(0.0)
        panel.add(title)
        panel.add(Box.createRigidArea(Dimension(0, 20)))
        
        stats_panel = JPanel()
        stats_panel.setLayout(BoxLayout(stats_panel, BoxLayout.Y_AXIS))
        stats_panel.setBorder(BorderFactory.createTitledBorder("Overview"))
        stats_panel.setAlignmentX(0.0)
        
        self.scans_label = JLabel("Total Scans Run: 0")
        self.scans_label.setFont(Font("Arial", Font.PLAIN, 14))
        self.scans_label.setAlignmentX(0.0)
        stats_panel.add(self.scans_label)
        stats_panel.add(Box.createRigidArea(Dimension(0, 10)))
        
        self.vulns_label = JLabel("Vulnerabilities Found: 0")
        self.vulns_label.setFont(Font("Arial", Font.PLAIN, 14))
        self.vulns_label.setAlignmentX(0.0)
        stats_panel.add(self.vulns_label)
        stats_panel.add(Box.createRigidArea(Dimension(0, 10)))
        
        self.requests_label = JLabel("Total Requests Tested: 0")
        self.requests_label.setFont(Font("Arial", Font.PLAIN, 14))
        self.requests_label.setAlignmentX(0.0)
        stats_panel.add(self.requests_label)
        
        panel.add(stats_panel)
        panel.add(Box.createRigidArea(Dimension(0, 15)))
        
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        button_panel.setAlignmentX(0.0)
        clear_stats_btn = JButton("Clear Statistics", actionPerformed=lambda e: self._clear_stats())
        button_panel.add(clear_stats_btn)
        panel.add(button_panel)
        
        panel.add(Box.createVerticalGlue())
        
        return panel
    
    def _create_logs_panel(self):
        """Logs display"""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        title_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("Extension Logs")
        title.setFont(Font("Arial", Font.BOLD, 16))
        title_panel.add(title)
        clear_btn = JButton("Clear Logs", actionPerformed=lambda e: self._clear_logs())
        title_panel.add(clear_btn)
        panel.add(title_panel, BorderLayout.NORTH)
        
        self.log_area = JTextArea(20, 80)
        self.log_area.setEditable(False)
        self.log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.log_area.setLineWrap(False)
        scroll = JScrollPane(self.log_area)
        panel.add(scroll, BorderLayout.CENTER)
        
        return panel
    
    def _on_mode_change(self):
        """Mode change handler"""
        selected = self.mode_combo.getSelectedIndex()
        
        if selected == 3:
            self.threshold_spinner.setEnabled(True)
            self.log("Switched to Custom mode - configure advanced settings")
        else:
            self.threshold_spinner.setEnabled(False)
            if selected == 0:
                self.scanner.set_mode('strict')
                self.mode_display_label.setText("Current Mode: Strict (threshold=30)")
                self.log("Mode: Strict (threshold=30)")
            elif selected == 1:
                self.scanner.set_mode('balanced')
                self.mode_display_label.setText("Current Mode: Balanced (threshold=15)")
                self.log("Mode: Balanced (threshold=15)")
            elif selected == 2:
                self.scanner.set_mode('sensitive')
                self.mode_display_label.setText("Current Mode: Sensitive (threshold=10)")
                self.log("Mode: Sensitive (threshold=10)")
    
    def _apply_custom(self):
        """Apply custom settings"""
        value = self.threshold_spinner.getValue()
        self.scanner.set_custom_threshold(value)
        self.mode_display_label.setText("Current Mode: Custom (threshold=" + str(value) + ")")
        self.log("Custom threshold applied: " + str(value))
    
    def add_finding(self, finding):
        """Add finding to results"""
        try:
            import time
            self.vuln_count += 1
            
            self.findings_list.append(finding)
            
            category = finding.get('category', 'Unknown')
            detection = finding.get('detection_result', {})
            severity = detection.get('severity', 'MEDIUM')
            score = detection.get('score', 0)
            
            request_dict = finding.get('request', {})
            response_dict = finding.get('response', {})
            
            url = request_dict.get('url', '')
            if '://' in url:
                host = url.split('://')[1].split('/')[0].split(':')[0]
            else:
                headers = request_dict.get('headers', {})
                host = headers.get('Host', headers.get('host', 'N/A'))
            
            method = request_dict.get('method', 'GET')
            
            if '://' in url:
                path = '/' + url.split('/', 3)[3] if url.count('/') >= 3 else '/'
            else:
                path = url
            if len(path) > 80:
                path = path[:77] + '...'
            
            status = str(response_dict.get('status', 'N/A'))
            
            body = response_dict.get('body', '')
            length = str(len(body))
            
            if 'test_method' in finding:
                location = "Method: " + finding['test_method']
            elif 'header_name' in finding:
                location = "Header: " + finding['header_name']
            elif 'parameter_name' in finding:
                location = "Param: " + finding['parameter_name']
                if 'test_payload' in finding:
                    payload_preview = str(finding['test_payload'])[:30]
                    location += " = " + payload_preview
            else:
                location = "Unknown"
            
            timestamp = time.strftime("%H:%M:%S")
            
            row = [
                str(self.vuln_count),  # #
                host,                  # Host
                method,                # Method
                path,                  # URL
                status,                # Status
                length,                # Length
                severity,              # Severity
                category,              # Category
                location,              # Location
                str(score),            # Score
                timestamp              # Time
            ]
            
            def add_row():
                self.results_model.addRow(row)
                self.summary_label.setText("Total Findings: " + str(self.vuln_count))
            
            SwingUtilities.invokeLater(add_row)
            
            log_msg = "Finding #" + str(self.vuln_count) + ": " + severity + " - " + category + " at " + location
            self.log(log_msg)
            
            evidences = detection.get('evidences', [])
            if evidences:
                for ev in evidences[:3]:
                    self.log("  Evidence: " + ev.get('description', ''))
            
        except Exception as e:
            self.log("ERROR adding finding: " + str(e))
            import traceback
            traceback.print_exc()
    
    def _on_finding_selected(self, row_index):
        """Handle finding selection to show req/resp"""
        try:
            if 0 <= row_index < len(self.findings_list):
                finding = self.findings_list[row_index]
                self.current_finding = finding
                
                response_dict = finding.get('response', {})
                request_dict = finding.get('request', {})
                
                if 'raw_request_bytes' in response_dict:
                    request_bytes = response_dict['raw_request_bytes']
                    self.request_viewer.setMessage(request_bytes, True)
                    
                    payload = self._get_payload_from_finding(finding)
                    if payload:
                        request_str = self.callbacks.getHelpers().bytesToString(request_bytes)
                        start = request_str.find(str(payload))
                        if start >= 0:
                            try:
                                from java.util import ArrayList
                                from array import array
                                markers = ArrayList()
                                markers.add(array('i', [start, start + len(str(payload))]))
                                self.request_viewer.setSearchExpression(str(payload))
                            except:
                                pass
                else:
                    self.request_viewer.setMessage(None, True)
                
                response_bytes = self._build_response_bytes(response_dict)
                self.response_viewer.setMessage(response_bytes, False)
                
        except Exception as e:
            print("[-] Error showing finding: " + str(e))
    
    def _get_payload_from_finding(self, finding):
        """Extract payload from finding"""
        if 'test_payload' in finding:
            return finding['test_payload']
        elif 'test_method' in finding:
            return finding['test_method']
        elif 'test_value' in finding:
            return finding['test_value']
        return None
    
    def _build_response_bytes(self, response_dict):
        """Build response bytes from dict"""
        try:
            lines = []
            status = response_dict.get('status', 200)
            lines.append('HTTP/1.1 ' + str(status) + ' OK')
            
            headers = response_dict.get('headers', {})
            for name, value in headers.items():
                lines.append(name + ': ' + str(value))
            
            body = response_dict.get('body', '')
            response_str = '\r\n'.join(lines) + '\r\n\r\n' + body
            
            return self.callbacks.getHelpers().stringToBytes(response_str)
        except:
            return None
    
    def getHttpService(self):
        if self.current_finding:
            request = self.current_finding.get('request', {})
            baseReq = request.get('baseRequestResponse')
            if baseReq:
                return baseReq.getHttpService()
        return None
    
    def getRequest(self):
        if self.current_finding:
            response = self.current_finding.get('response', {})
            return response.get('raw_request_bytes')
        return None
    
    def getResponse(self):
        if self.current_finding:
            response_dict = self.current_finding.get('response', {})
            return self._build_response_bytes(response_dict)
        return None
    
    def increment_stats(self, scans=0, requests=0):
        """Update statistics"""
        if scans > 0:
            self.scan_count += scans
            
            def update_scans():
                self.scans_label.setText("Total Scans Run: " + str(self.scan_count))
            SwingUtilities.invokeLater(update_scans)
            
        if requests > 0:
            self.request_count += requests
            
            def update_requests():
                self.requests_label.setText("Total Requests Tested: " + str(self.request_count))
            SwingUtilities.invokeLater(update_requests)
        
        def update_vulns():
            self.vulns_label.setText("Vulnerabilities Found: " + str(self.vuln_count))
        SwingUtilities.invokeLater(update_vulns)
    
    def _clear_results(self):
        """Clear results"""
        self.results_model.setRowCount(0)
        self.vuln_count = 0
        self.findings_list = []
        self.summary_label.setText("Total Findings: 0")
        self.log("Results cleared")
    
    def _clear_logs(self):
        """Clear logs"""
        self.log_area.setText("")
    
    def _clear_stats(self):
        """Clear statistics"""
        self.scan_count = 0
        self.request_count = 0
        
        def update_stats():
            self.scans_label.setText("Total Scans Run: 0")
            self.requests_label.setText("Total Requests Tested: 0")
            self.vulns_label.setText("Vulnerabilities Found: " + str(self.vuln_count))
        
        SwingUtilities.invokeLater(update_stats)
        self.log("Statistics cleared")
    
    def _stop_scan(self):
        """Stop current scan"""
        if self.scanner:
            self.scanner.request_stop()
            self.log("STOP requested - scan will terminate after current test")
            self.scan_status_label.setText("Scan Status: Stopping...")
            
            def disable_button():
                self.stop_button.setEnabled(False)
            SwingUtilities.invokeLater(disable_button)
    
    def set_scan_running(self, running):
        """Update UI for scan state"""
        def update():
            if running:
                self.scan_status_label.setText("Scan Status: Running...")
                self.stop_button.setEnabled(True)
            else:
                self.scan_status_label.setText("Scan Status: Idle")
                self.stop_button.setEnabled(False)
        
        SwingUtilities.invokeLater(update)
    
    def log(self, message):
        """Add log message"""
        import time
        timestamp = time.strftime("%H:%M:%S")
        log_line = "[" + timestamp + "] " + message + "\n"
        
        def append_log():
            current = self.log_area.getText()
            self.log_area.setText(current + log_line)
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
        
        SwingUtilities.invokeLater(append_log)
    
    def getTabCaption(self):
        return "ErrorHound"
    
    def getUiComponent(self):
        return self.tabbedPane


class ResultsSelectionListener(ListSelectionListener):
    """Listener for table selection"""
    
    def __init__(self, tab):
        self.tab = tab
    
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            selected_row = self.tab.results_table.getSelectedRow()
            if selected_row >= 0:
                model_row = self.tab.results_table.convertRowIndexToModel(selected_row)
                self.tab._on_finding_selected(model_row)
