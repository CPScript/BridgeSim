#!/usr/bin/env python3

# MIT License

# Copyright (c) 2025 CPScript

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import threading
import json
import os
import sys
import time
import hashlib
import struct
import socket
import psutil
import platform
from datetime import datetime
import sqlite3
import zipfile
import xml.etree.ElementTree as ET
import base64
import re
import signal
import tempfile
from PIL import Image, ImageTk
import io

class NFCControllerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("POOPIEFART62 Controller - ")
        self.root.geometry("1600x1000")
        self.root.configure(bg='#1a1a1a')
        self.root.resizable(True, True)
        
        self.devices = {}
        self.current_device = None
        self.scanning = False
        self.reverse_engineering_active = False
        self.system_monitor_active = False
        self.screen_monitor_active = False
        self.keylogger_active = False
        self.network_monitor_active = False
        self.command_history = []
        self.screen_image = None
        
        self.setup_styles()
        self.create_menu()
        self.create_layout()
        self.start_device_monitor()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Dark.TFrame', background='#1a1a1a')
        style.configure('Dark.TLabel', background='#1a1a1a', foreground='#ffffff')
        style.configure('Dark.TButton', background='#2a2a2a', foreground='#ffffff', borderwidth=1)
        style.configure('Dark.TEntry', background='#2a2a2a', foreground='#ffffff', borderwidth=1)
        style.configure('Dark.TCombobox', background='#2a2a2a', foreground='#ffffff', borderwidth=1)
        style.configure('Dark.Treeview', background='#2a2a2a', foreground='#ffffff', borderwidth=1)
        style.configure('Dark.Treeview.Heading', background='#3a3a3a', foreground='#ffffff', borderwidth=1)
        style.configure('Dark.TNotebook', background='#1a1a1a', borderwidth=0)
        style.configure('Dark.TNotebook.Tab', background='#2a2a2a', foreground='#ffffff', padding=[12, 8])
        style.configure('Dark.Horizontal.TProgressbar', background='#0078d4', borderwidth=0)
        
        style.map('Dark.TButton',
                 background=[('active', '#3a3a3a'), ('pressed', '#4a4a4a')])
        style.map('Dark.TNotebook.Tab',
                 background=[('selected', '#3a3a3a')])
        
    def create_menu(self):
        menubar = tk.Menu(self.root, bg='#2a2a2a', fg='#ffffff', activebackground='#3a3a3a')
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0, bg='#2a2a2a', fg='#ffffff', activebackground='#3a3a3a')
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Device Profile", command=self.load_device_profile)
        file_menu.add_command(label="Save Device Profile", command=self.save_device_profile)
        file_menu.add_separator()
        file_menu.add_command(label="Export All Data", command=self.export_all_data)
        file_menu.add_command(label="Import Session", command=self.import_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        tools_menu = tk.Menu(menubar, tearoff=0, bg='#2a2a2a', fg='#ffffff', activebackground='#3a3a3a')
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="ADB Shell", command=self.open_adb_shell)
        tools_menu.add_command(label="Fastboot Mode", command=self.enter_fastboot)
        tools_menu.add_command(label="Recovery Mode", command=self.enter_recovery)
        tools_menu.add_separator()
        tools_menu.add_command(label="Device Backup", command=self.create_device_backup)
        tools_menu.add_command(label="Device Restore", command=self.restore_device_backup)
        tools_menu.add_separator()
        tools_menu.add_command(label="Memory Analyzer", command=self.open_memory_analyzer)
        tools_menu.add_command(label="Network Analyzer", command=self.open_network_analyzer)
        tools_menu.add_command(label="Performance Monitor", command=self.open_performance_monitor)
        
        exploit_menu = tk.Menu(menubar, tearoff=0, bg='#2a2a2a', fg='#ffffff', activebackground='#3a3a3a')
        menubar.add_cascade(label="Exploitation", menu=exploit_menu)
        exploit_menu.add_command(label="Privilege Escalation", command=self.privilege_escalation)
        exploit_menu.add_command(label="Security Bypass Suite", command=self.open_security_bypass)
        exploit_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        
        help_menu = tk.Menu(menubar, tearoff=0, bg='#2a2a2a', fg='#ffffff', activebackground='#3a3a3a')
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        
    def create_layout(self):
        main_frame = ttk.Frame(self.root, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.create_toolbar(main_frame)
        self.create_main_content(main_frame)
        self.create_status_bar(main_frame)
        
    def create_toolbar(self, parent):
        toolbar = ttk.Frame(parent, style='Dark.TFrame')
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(toolbar, text="Device:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        
        self.device_combo = ttk.Combobox(toolbar, style='Dark.TCombobox', state="readonly", width=30)
        self.device_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.device_combo.bind('<<ComboboxSelected>>', self.on_device_selected)
        
        ttk.Button(toolbar, text="Refresh Devices", style='Dark.TButton', 
                  command=self.refresh_devices).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(toolbar, text="Connect", style='Dark.TButton', 
                  command=self.connect_device).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(toolbar, text="Disconnect", style='Dark.TButton', 
                  command=self.disconnect_device).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(toolbar, text="Emergency Reboot", style='Dark.TButton', 
                  command=self.emergency_reboot).pack(side=tk.LEFT, padx=(0, 5))
        
        self.connection_status = ttk.Label(toolbar, text="Status: Disconnected", style='Dark.TLabel')
        self.connection_status.pack(side=tk.RIGHT)

    def export_device_info(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                data = self.tree_to_dict(self.device_info_tree)
                with open(filename, 'w') as f:
                    json.dump({
                        'device_id': self.current_device,
                        'export_time': datetime.now().isoformat(),
                        'device_info': data
                    }, f, indent=2)
                messagebox.showinfo("Success", f"Device info exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
        
    def create_main_content(self, parent):
        content_frame = ttk.Frame(parent, style='Dark.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        paned = ttk.PanedWindow(content_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        left_panel = ttk.Frame(paned, style='Dark.TFrame')
        right_panel = ttk.Frame(paned, style='Dark.TFrame')
        
        paned.add(left_panel, weight=1)
        paned.add(right_panel, weight=2)
        
        self.create_left_panel(left_panel)
        self.create_right_panel(right_panel)
        
    def create_left_panel(self, parent):
        notebook = ttk.Notebook(parent, style='Dark.TNotebook')
        notebook.pack(fill=tk.BOTH, expand=True)
        
        self.create_system_tab(notebook)
        self.create_security_tab(notebook)
        self.create_reverse_engineering_tab(notebook)
        self.create_firmware_tab(notebook)
        self.create_remote_control_tab(notebook)
        self.create_file_manager_tab(notebook)
        self.create_process_manager_tab(notebook)
        
    def create_system_tab(self, notebook):
        system_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(system_frame, text="System Monitor")
        
        ttk.Label(system_frame, text="System Overview", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        self.system_tree = ttk.Treeview(system_frame, style='Dark.Treeview', height=15)
        self.system_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.system_tree['columns'] = ('Size', 'Type', 'Status')
        self.system_tree.column('#0', width=200, minwidth=150)
        self.system_tree.column('Size', width=80, minwidth=60)
        self.system_tree.column('Type', width=100, minwidth=80)
        self.system_tree.column('Status', width=80, minwidth=60)
        
        self.system_tree.heading('#0', text='Component', anchor=tk.W)
        self.system_tree.heading('Size', text='Size', anchor=tk.W)
        self.system_tree.heading('Type', text='Type', anchor=tk.W)
        self.system_tree.heading('Status', text='Status', anchor=tk.W)
        
        system_buttons = ttk.Frame(system_frame, style='Dark.TFrame')
        system_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(system_buttons, text="Start Monitor", style='Dark.TButton', 
                  command=self.start_system_monitor).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(system_buttons, text="Stop Monitor", style='Dark.TButton', 
                  command=self.stop_system_monitor).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(system_buttons, text="Export Tree", style='Dark.TButton', 
                  command=self.export_system_tree).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(system_buttons, text="Real-time Stats", style='Dark.TButton', 
                  command=self.show_realtime_stats).pack(side=tk.LEFT)
        
    def create_security_tab(self, notebook):
        security_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(security_frame, text="Security Manager")
        
        ttk.Label(security_frame, text="Security Configuration", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        security_scroll = scrolledtext.ScrolledText(security_frame, height=18, bg='#2a2a2a', fg='#ffffff', 
                                                   insertbackground='#ffffff', selectbackground='#3a3a3a')
        security_scroll.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        self.security_text = security_scroll
        
        security_buttons = ttk.Frame(security_frame, style='Dark.TFrame')
        security_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(security_buttons, text="Scan Security", style='Dark.TButton', 
                  command=self.scan_security).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(security_buttons, text="Bypass SELinux", style='Dark.TButton', 
                  command=self.bypass_selinux).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(security_buttons, text="Modify Permissions", style='Dark.TButton', 
                  command=self.modify_permissions).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(security_buttons, text="Root Device", style='Dark.TButton', 
                  command=self.attempt_root_device).pack(side=tk.LEFT)
        
    def create_reverse_engineering_tab(self, notebook):
        re_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(re_frame, text="Reverse Engineering")
        
        ttk.Label(re_frame, text="Automated Analysis", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        self.re_progress = ttk.Progressbar(re_frame, style='Dark.Horizontal.TProgressbar', mode='indeterminate')
        self.re_progress.pack(fill=tk.X, pady=(0, 10))
        
        self.re_text = scrolledtext.ScrolledText(re_frame, height=15, bg='#2a2a2a', fg='#ffffff', 
                                                insertbackground='#ffffff', selectbackground='#3a3a3a')
        self.re_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        re_buttons = ttk.Frame(re_frame, style='Dark.TFrame')
        re_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(re_buttons, text="Start Analysis", style='Dark.TButton', 
                  command=self.start_reverse_engineering).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(re_buttons, text="Stop Analysis", style='Dark.TButton', 
                  command=self.stop_reverse_engineering).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(re_buttons, text="Memory Dump", style='Dark.TButton', 
                  command=self.create_memory_dump).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(re_buttons, text="Generate Report", style='Dark.TButton', 
                  command=self.generate_re_report).pack(side=tk.LEFT)
        
    def create_firmware_tab(self, notebook):
        firmware_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(firmware_frame, text="Firmware Manager")
        
        ttk.Label(firmware_frame, text="NFC Chipset Management", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        chipset_info = ttk.Frame(firmware_frame, style='Dark.TFrame')
        chipset_info.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(chipset_info, text="Detected Chipset:", style='Dark.TLabel').grid(row=0, column=0, sticky=tk.W)
        self.chipset_label = ttk.Label(chipset_info, text="Unknown", style='Dark.TLabel', font=('Arial', 10, 'bold'))
        self.chipset_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(chipset_info, text="Firmware Version:", style='Dark.TLabel').grid(row=1, column=0, sticky=tk.W)
        self.firmware_label = ttk.Label(chipset_info, text="Unknown", style='Dark.TLabel', font=('Arial', 10, 'bold'))
        self.firmware_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        self.firmware_text = scrolledtext.ScrolledText(firmware_frame, height=12, bg='#2a2a2a', fg='#ffffff', 
                                                      insertbackground='#ffffff', selectbackground='#3a3a3a')
        self.firmware_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        firmware_buttons = ttk.Frame(firmware_frame, style='Dark.TFrame')
        firmware_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(firmware_buttons, text="Detect Chipset", style='Dark.TButton', 
                  command=self.detect_chipset).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(firmware_buttons, text="Backup Firmware", style='Dark.TButton', 
                  command=self.backup_firmware).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(firmware_buttons, text="Flash Firmware", style='Dark.TButton', 
                  command=self.flash_firmware).pack(side=tk.LEFT)
        
    def create_remote_control_tab(self, notebook):
        remote_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(remote_frame, text="Remote Control")
        
        ttk.Label(remote_frame, text="Device Remote Control", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        screen_frame = ttk.LabelFrame(remote_frame, text="Screen Mirror", style='Dark.TFrame')
        screen_frame.pack(fill=tk.X, pady=(0, 10))
        
        screen_buttons = ttk.Frame(screen_frame, style='Dark.TFrame')
        screen_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(screen_buttons, text="Start Screen Mirror", style='Dark.TButton', 
                  command=self.start_screen_mirror).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(screen_buttons, text="Stop Mirror", style='Dark.TButton', 
                  command=self.stop_screen_mirror).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(screen_buttons, text="Screenshot", style='Dark.TButton', 
                  command=self.take_screenshot).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(screen_buttons, text="Record Screen", style='Dark.TButton', 
                  command=self.record_screen).pack(side=tk.LEFT)
        
        # Input simulation section
        input_frame = ttk.LabelFrame(remote_frame, text="Input Simulation", style='Dark.TFrame')
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        input_buttons = ttk.Frame(input_frame, style='Dark.TFrame')
        input_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(input_buttons, text="Send Text", style='Dark.TButton', 
                  command=self.send_text_input).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(input_buttons, text="Simulate Tap", style='Dark.TButton', 
                  command=self.simulate_tap).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(input_buttons, text="Simulate Swipe", style='Dark.TButton', 
                  command=self.simulate_swipe).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(input_buttons, text="Key Events", style='Dark.TButton', 
                  command=self.send_key_events).pack(side=tk.LEFT)
        
        apk_exec_frame = ttk.LabelFrame(remote_frame, text="Remote APK Execution", style='Dark.TFrame')
        apk_exec_frame.pack(fill=tk.BOTH, expand=True)
        
        apk_entry_frame = ttk.Frame(apk_exec_frame, style='Dark.TFrame')
        apk_entry_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(apk_entry_frame, text="APK Path:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        self.remote_apk_var = tk.StringVar()
        ttk.Entry(apk_entry_frame, textvariable=self.remote_apk_var, style='Dark.TEntry', width=30).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(apk_entry_frame, text="Browse", style='Dark.TButton', 
                  command=self.browse_remote_apk).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(apk_entry_frame, text="Execute APK", style='Dark.TButton', 
                  command=self.execute_apk_remotely).pack(side=tk.LEFT)
        
        self.remote_execution_log = scrolledtext.ScrolledText(apk_exec_frame, height=8, bg='#2a2a2a', fg='#ffffff')
        self.remote_execution_log.pack(fill=tk.BOTH, expand=True, pady=5)
        
    def create_file_manager_tab(self, notebook):
        file_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(file_frame, text="File Manager")
        
        ttk.Label(file_frame, text="Device File System", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        path_frame = ttk.Frame(file_frame, style='Dark.TFrame')
        path_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(path_frame, text="Path:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        self.current_path_var = tk.StringVar(value="/")
        path_entry = ttk.Entry(path_frame, textvariable=self.current_path_var, style='Dark.TEntry', width=40)
        path_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        path_entry.bind('<Return>', self.navigate_to_path)
        
        ttk.Button(path_frame, text="Navigate", style='Dark.TButton', 
                  command=self.navigate_to_path).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(path_frame, text="Up", style='Dark.TButton', 
                  command=self.navigate_up).pack(side=tk.LEFT)
        
        self.file_tree = ttk.Treeview(file_frame, style='Dark.Treeview', height=12)
        self.file_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.file_tree['columns'] = ('Size', 'Modified', 'Permissions')
        self.file_tree.column('#0', width=200, minwidth=150)
        self.file_tree.column('Size', width=80, minwidth=60)
        self.file_tree.column('Modified', width=120, minwidth=100)
        self.file_tree.column('Permissions', width=100, minwidth=80)
        
        self.file_tree.heading('#0', text='Name', anchor=tk.W)
        self.file_tree.heading('Size', text='Size', anchor=tk.W)
        self.file_tree.heading('Modified', text='Modified', anchor=tk.W)
        self.file_tree.heading('Permissions', text='Permissions', anchor=tk.W)
        
        self.file_tree.bind('<Double-1>', self.on_file_double_click)
        
        file_buttons = ttk.Frame(file_frame, style='Dark.TFrame')
        file_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(file_buttons, text="Download", style='Dark.TButton', 
                  command=self.download_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_buttons, text="Upload", style='Dark.TButton', 
                  command=self.upload_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_buttons, text="Delete", style='Dark.TButton', 
                  command=self.delete_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_buttons, text="Create Folder", style='Dark.TButton', 
                  command=self.create_folder).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(file_buttons, text="Properties", style='Dark.TButton', 
                  command=self.show_file_properties).pack(side=tk.LEFT)
        
    def create_process_manager_tab(self, notebook):
        process_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(process_frame, text="Process Manager")
        
        ttk.Label(process_frame, text="Running Processes", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        self.process_tree = ttk.Treeview(process_frame, style='Dark.Treeview', height=15)
        self.process_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.process_tree['columns'] = ('PID', 'CPU', 'Memory', 'Status')
        self.process_tree.column('#0', width=200, minwidth=150)
        self.process_tree.column('PID', width=60, minwidth=50)
        self.process_tree.column('CPU', width=60, minwidth=50)
        self.process_tree.column('Memory', width=80, minwidth=60)
        self.process_tree.column('Status', width=80, minwidth=60)
        
        self.process_tree.heading('#0', text='Process Name', anchor=tk.W)
        self.process_tree.heading('PID', text='PID', anchor=tk.W)
        self.process_tree.heading('CPU', text='CPU%', anchor=tk.W)
        self.process_tree.heading('Memory', text='Memory', anchor=tk.W)
        self.process_tree.heading('Status', text='Status', anchor=tk.W)
        
        process_buttons = ttk.Frame(process_frame, style='Dark.TFrame')
        process_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(process_buttons, text="Refresh", style='Dark.TButton', 
                  command=self.refresh_processes).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(process_buttons, text="Kill Process", style='Dark.TButton', 
                  command=self.kill_process).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(process_buttons, text="Process Info", style='Dark.TButton', 
                  command=self.show_process_info).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(process_buttons, text="Memory Map", style='Dark.TButton', 
                  command=self.show_memory_map).pack(side=tk.LEFT)
        
    def create_right_panel(self, parent):
        right_notebook = ttk.Notebook(parent, style='Dark.TNotebook')
        right_notebook.pack(fill=tk.BOTH, expand=True)
        
        self.create_device_info_tab(right_notebook)
        self.create_apk_manager_tab(right_notebook)
        self.create_communications_tab(right_notebook)
        self.create_network_monitor_tab(right_notebook)
        self.create_shell_tab(right_notebook)
        self.create_keylogger_tab(right_notebook)
        self.create_scan_results_tab(right_notebook)
        self.create_logs_tab(right_notebook)
        
    def create_device_info_tab(self, notebook):
        info_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(info_frame, text="Device Information")
        
        self.device_info_tree = ttk.Treeview(info_frame, style='Dark.Treeview')
        self.device_info_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.device_info_tree['columns'] = ('Value',)
        self.device_info_tree.column('#0', width=200, minwidth=150)
        self.device_info_tree.column('Value', width=300, minwidth=200)
        
        self.device_info_tree.heading('#0', text='Property', anchor=tk.W)
        self.device_info_tree.heading('Value', text='Value', anchor=tk.W)
        
        info_buttons = ttk.Frame(info_frame, style='Dark.TFrame')
        info_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(info_buttons, text="Refresh Info", style='Dark.TButton', 
                  command=self.refresh_device_info).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(info_buttons, text="Export Info", style='Dark.TButton', 
                  command=self.export_device_info).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(info_buttons, text="Hardware Details", style='Dark.TButton', 
                  command=self.show_hardware_details).pack(side=tk.LEFT)
        
    def create_apk_manager_tab(self, notebook):
        apk_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(apk_frame, text="APK Manager")
        
        ttk.Label(apk_frame, text="APK Installation & Management", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        apk_input_frame = ttk.Frame(apk_frame, style='Dark.TFrame')
        apk_input_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(apk_input_frame, text="APK Path:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        self.apk_path_var = tk.StringVar()
        self.apk_entry = ttk.Entry(apk_input_frame, textvariable=self.apk_path_var, style='Dark.TEntry', width=40)
        self.apk_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        ttk.Button(apk_input_frame, text="Browse", style='Dark.TButton', 
                  command=self.browse_apk).pack(side=tk.LEFT)
        
        apk_buttons = ttk.Frame(apk_frame, style='Dark.TFrame')
        apk_buttons.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(apk_buttons, text="Install APK", style='Dark.TButton', 
                  command=self.install_apk).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(apk_buttons, text="Uninstall Package", style='Dark.TButton', 
                  command=self.uninstall_package).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(apk_buttons, text="List Packages", style='Dark.TButton', 
                  command=self.list_packages).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(apk_buttons, text="Extract APK", style='Dark.TButton', 
                  command=self.extract_apk).pack(side=tk.LEFT)
        
        self.package_list = ttk.Treeview(apk_frame, style='Dark.Treeview')
        self.package_list.pack(fill=tk.BOTH, expand=True)
        
        self.package_list['columns'] = ('Package', 'Version', 'Status', 'Size')
        self.package_list.column('#0', width=0, stretch=False)
        self.package_list.column('Package', width=250, minwidth=200)
        self.package_list.column('Version', width=100, minwidth=80)
        self.package_list.column('Status', width=100, minwidth=80)
        self.package_list.column('Size', width=80, minwidth=60)
        
        self.package_list.heading('Package', text='Package Name', anchor=tk.W)
        self.package_list.heading('Version', text='Version', anchor=tk.W)
        self.package_list.heading('Status', text='Status', anchor=tk.W)
        self.package_list.heading('Size', text='Size', anchor=tk.W)
        
    def create_communications_tab(self, notebook):
        comm_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(comm_frame, text="Communications")
        
        sms_frame = ttk.LabelFrame(comm_frame, text="SMS Management", style='Dark.TFrame')
        sms_frame.pack(fill=tk.X, pady=(0, 10))
        
        sms_buttons = ttk.Frame(sms_frame, style='Dark.TFrame')
        sms_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(sms_buttons, text="Read SMS", style='Dark.TButton', 
                  command=self.read_sms).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(sms_buttons, text="Send SMS", style='Dark.TButton', 
                  command=self.send_sms).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(sms_buttons, text="Call History", style='Dark.TButton', 
                  command=self.get_call_history).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(sms_buttons, text="Contacts", style='Dark.TButton', 
                  command=self.get_contacts).pack(side=tk.LEFT)
        
        location_frame = ttk.LabelFrame(comm_frame, text="Location Services", style='Dark.TFrame')
        location_frame.pack(fill=tk.X, pady=(0, 10))
        
        location_buttons = ttk.Frame(location_frame, style='Dark.TFrame')
        location_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(location_buttons, text="Get Location", style='Dark.TButton', 
                  command=self.get_current_location).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(location_buttons, text="Spoof Location", style='Dark.TButton', 
                  command=self.spoof_location).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(location_buttons, text="Location History", style='Dark.TButton', 
                  command=self.get_location_history).pack(side=tk.LEFT)
        
        self.comm_log = scrolledtext.ScrolledText(comm_frame, height=15, bg='#2a2a2a', fg='#ffffff')
        self.comm_log.pack(fill=tk.BOTH, expand=True)
        
    def create_network_monitor_tab(self, notebook):
        network_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(network_frame, text="Network Monitor")
        
        ttk.Label(network_frame, text="Network Traffic Analysis", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        network_buttons = ttk.Frame(network_frame, style='Dark.TFrame')
        network_buttons.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(network_buttons, text="Start Monitor", style='Dark.TButton', 
                  command=self.start_network_monitor).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(network_buttons, text="Stop Monitor", style='Dark.TButton', 
                  command=self.stop_network_monitor).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(network_buttons, text="Network Stats", style='Dark.TButton', 
                  command=self.show_network_stats).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(network_buttons, text="WiFi Info", style='Dark.TButton', 
                  command=self.get_wifi_info).pack(side=tk.LEFT)
        
        self.network_tree = ttk.Treeview(network_frame, style='Dark.Treeview', height=12)
        self.network_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.network_tree['columns'] = ('Protocol', 'Local', 'Remote', 'State', 'Process')
        self.network_tree.column('#0', width=0, stretch=False)
        self.network_tree.column('Protocol', width=80, minwidth=60)
        self.network_tree.column('Local', width=120, minwidth=100)
        self.network_tree.column('Remote', width=120, minwidth=100)
        self.network_tree.column('State', width=80, minwidth=60)
        self.network_tree.column('Process', width=150, minwidth=100)
        
        self.network_tree.heading('Protocol', text='Protocol', anchor=tk.W)
        self.network_tree.heading('Local', text='Local Address', anchor=tk.W)
        self.network_tree.heading('Remote', text='Remote Address', anchor=tk.W)
        self.network_tree.heading('State', text='State', anchor=tk.W)
        self.network_tree.heading('Process', text='Process', anchor=tk.W)
        
        traffic_buttons = ttk.Frame(network_frame, style='Dark.TFrame')
        traffic_buttons.pack(fill=tk.X, pady=5)
        
        ttk.Button(traffic_buttons, text="Capture Traffic", style='Dark.TButton', 
                  command=self.capture_network_traffic).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(traffic_buttons, text="Block Connection", style='Dark.TButton', 
                  command=self.block_connection).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(traffic_buttons, text="Export Capture", style='Dark.TButton', 
                  command=self.export_network_capture).pack(side=tk.LEFT)
        
    def create_shell_tab(self, notebook):
        shell_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(shell_frame, text="Shell Terminal")
        
        ttk.Label(shell_frame, text="Interactive Shell", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        cmd_frame = ttk.Frame(shell_frame, style='Dark.TFrame')
        cmd_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(cmd_frame, text="Command:", style='Dark.TLabel').pack(side=tk.LEFT, padx=(0, 5))
        self.shell_command_var = tk.StringVar()
        cmd_entry = ttk.Entry(cmd_frame, textvariable=self.shell_command_var, style='Dark.TEntry')
        cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        cmd_entry.bind('<Return>', self.execute_shell_command)
        
        ttk.Button(cmd_frame, text="Execute", style='Dark.TButton', 
                  command=self.execute_shell_command).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(cmd_frame, text="Clear", style='Dark.TButton', 
                  command=self.clear_shell).pack(side=tk.LEFT)
        
        self.shell_output = scrolledtext.ScrolledText(shell_frame, height=20, bg='#000000', fg='#00ff00', 
                                                     insertbackground='#00ff00', selectbackground='#333333',
                                                     font=('Courier', 10))
        self.shell_output.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        quick_frame = ttk.Frame(shell_frame, style='Dark.TFrame')
        quick_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(quick_frame, text="System Info", style='Dark.TButton', 
                  command=lambda: self.quick_command("uname -a")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(quick_frame, text="Process List", style='Dark.TButton', 
                  command=lambda: self.quick_command("ps -A")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(quick_frame, text="Disk Usage", style='Dark.TButton', 
                  command=lambda: self.quick_command("df -h")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(quick_frame, text="Network", style='Dark.TButton', 
                  command=lambda: self.quick_command("netstat -an")).pack(side=tk.LEFT)
        
    def create_keylogger_tab(self, notebook):
        keylog_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(keylog_frame, text="Keylogger")
        
        ttk.Label(keylog_frame, text="Input Monitoring", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        keylog_buttons = ttk.Frame(keylog_frame, style='Dark.TFrame')
        keylog_buttons.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(keylog_buttons, text="Start Keylogger", style='Dark.TButton', 
                  command=self.start_keylogger).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(keylog_buttons, text="Stop Keylogger", style='Dark.TButton', 
                  command=self.stop_keylogger).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(keylog_buttons, text="Clear Log", style='Dark.TButton', 
                  command=self.clear_keylog).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(keylog_buttons, text="Export Log", style='Dark.TButton', 
                  command=self.export_keylog).pack(side=tk.LEFT)
        
        self.keylog_text = scrolledtext.ScrolledText(keylog_frame, height=20, bg='#2a2a2a', fg='#ffff00',
                                                    insertbackground='#ffff00', selectbackground='#3a3a3a',
                                                    font=('Courier', 10))
        self.keylog_text.pack(fill=tk.BOTH, expand=True)
        
    def create_scan_results_tab(self, notebook):
        scan_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(scan_frame, text="Scan Results")
        
        ttk.Label(scan_frame, text="System Scan Results", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        scan_buttons = ttk.Frame(scan_frame, style='Dark.TFrame')
        scan_buttons.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(scan_buttons, text="Full System Scan", style='Dark.TButton', 
                  command=self.full_system_scan).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(scan_buttons, text="Security Scan", style='Dark.TButton', 
                  command=self.security_scan).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(scan_buttons, text="Vulnerability Scan", style='Dark.TButton', 
                  command=self.vulnerability_scan).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(scan_buttons, text="NFC Scan", style='Dark.TButton', 
                  command=self.nfc_scan).pack(side=tk.LEFT)
        
        self.scan_progress = ttk.Progressbar(scan_frame, style='Dark.Horizontal.TProgressbar', mode='determinate')
        self.scan_progress.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_results = scrolledtext.ScrolledText(scan_frame, bg='#2a2a2a', fg='#ffffff', 
                                                     insertbackground='#ffffff', selectbackground='#3a3a3a')
        self.scan_results.pack(fill=tk.BOTH, expand=True)
        
    def create_logs_tab(self, notebook):
        logs_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(logs_frame, text="System Logs")
        
        ttk.Label(logs_frame, text="Real-time System Logs", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        log_buttons = ttk.Frame(logs_frame, style='Dark.TFrame')
        log_buttons.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(log_buttons, text="Start Logging", style='Dark.TButton', 
                  command=self.start_logging).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(log_buttons, text="Stop Logging", style='Dark.TButton', 
                  command=self.stop_logging).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(log_buttons, text="Clear Logs", style='Dark.TButton', 
                  command=self.clear_logs).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(log_buttons, text="Save Logs", style='Dark.TButton', 
                  command=self.save_logs).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(log_buttons, text="Filter Logs", style='Dark.TButton', 
                  command=self.filter_logs).pack(side=tk.LEFT)
        
        self.log_text = scrolledtext.ScrolledText(logs_frame, bg='#2a2a2a', fg='#ffffff', 
                                                 insertbackground='#ffffff', selectbackground='#3a3a3a')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def create_status_bar(self, parent):
        status_frame = ttk.Frame(parent, style='Dark.TFrame')
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.status_label = ttk.Label(status_frame, text="Ready", style='Dark.TLabel')
        self.status_label.pack(side=tk.LEFT)
        
        self.progress_bar = ttk.Progressbar(status_frame, style='Dark.Horizontal.TProgressbar', 
                                           mode='indeterminate', length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=(5, 0))
        
    def start_device_monitor(self):
        def monitor_devices():
            while True:
                try:
                    self.refresh_devices()
                    time.sleep(5)
                except:
                    break
                    
        threading.Thread(target=monitor_devices, daemon=True).start()
        
    def refresh_devices(self):
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
            devices = []
            
            for line in result.stdout.strip().split('\n')[1:]:
                if line.strip() and '\t' in line:
                    device_id, status = line.strip().split('\t')
                    if status == 'device':
                        devices.append(device_id)
                        
            current_values = list(self.device_combo['values'])
            if set(devices) != set(current_values):
                self.device_combo['values'] = devices
                if devices and not self.device_combo.get():
                    self.device_combo.set(devices[0])
                    
        except subprocess.TimeoutExpired:
            self.log_message("ADB timeout - check USB debugging")
        except FileNotFoundError:
            self.log_message("ADB not found - install Android SDK platform tools")
        except Exception as e:
            self.log_message(f"Device refresh error: {str(e)}")
            
    def on_device_selected(self, event):
        self.current_device = self.device_combo.get()
        if self.current_device:
            self.connection_status.config(text=f"Status: Selected {self.current_device}")
            
    def connect_device(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device selected")
            return
            
        try:
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'echo', 'connected'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.connection_status.config(text=f"Status: Connected to {self.current_device}")
                self.refresh_device_info()
                self.refresh_file_list()
                self.refresh_processes()
                self.log_message(f"Connected to device {self.current_device}")
            else:
                raise Exception("Connection failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")
            
    def disconnect_device(self):
        self.stop_all_monitoring()
        self.current_device = None
        self.connection_status.config(text="Status: Disconnected")
        self.device_info_tree.delete(*self.device_info_tree.get_children())
        self.log_message("Disconnected from device")
        
    def emergency_reboot(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        result = messagebox.askyesno("Emergency Reboot", "Force reboot device immediately?")
        if result:
            try:
                subprocess.run(['adb', '-s', self.current_device, 'reboot'], timeout=5)
                messagebox.showinfo("Success", "Emergency reboot initiated")
            except Exception as e:
                messagebox.showerror("Error", f"Emergency reboot failed: {str(e)}")
    
    def start_screen_mirror(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.screen_monitor_active = True
        
        def screen_monitor():
            mirror_window = tk.Toplevel(self.root)
            mirror_window.title(f"Screen Mirror - {self.current_device}")
            mirror_window.geometry("400x600")
            mirror_window.configure(bg='#000000')
            
            screen_label = tk.Label(mirror_window, bg='#000000')
            screen_label.pack(fill=tk.BOTH, expand=True)
            
            def update_screen():
                if not self.screen_monitor_active:
                    mirror_window.destroy()
                    return
                    
                try:
                    result = subprocess.run(['adb', '-s', self.current_device, 'exec-out', 'screencap', '-p'], 
                                          capture_output=True, timeout=5)
                    if result.returncode == 0:
                        image = Image.open(io.BytesIO(result.stdout))
                        image = image.resize((380, 580), Image.Resampling.LANCZOS)
                        photo = ImageTk.PhotoImage(image)
                        screen_label.config(image=photo)
                        screen_label.image = photo
                        
                except Exception as e:
                    self.log_message(f"Screen capture error: {str(e)}")
                    
                if self.screen_monitor_active:
                    mirror_window.after(1000, update_screen)
                    
            update_screen()
            
        threading.Thread(target=screen_monitor, daemon=True).start()
        
    def stop_screen_mirror(self):
        self.screen_monitor_active = False
        
    def take_screenshot(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'exec-out', 'screencap', '-p'], 
                                      capture_output=True, timeout=10)
                if result.returncode == 0:
                    with open(filename, 'wb') as f:
                        f.write(result.stdout)
                    messagebox.showinfo("Success", f"Screenshot saved to {filename}")
                else:
                    raise Exception("Screenshot failed")
            except Exception as e:
                messagebox.showerror("Error", f"Screenshot error: {str(e)}")
                
    def record_screen(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".mp4",
            filetypes=[("MP4 files", "*.mp4"), ("All files", "*.*")]
        )
        
        if filename:
            def record():
                try:
                    self.log_message("Starting screen recording...")
                    device_path = "/sdcard/screen_record.mp4"
                    
                    record_process = subprocess.Popen(['adb', '-s', self.current_device, 'shell', 'screenrecord', device_path])
                    
                    result = messagebox.askquestion("Recording", "Recording started. Click OK to stop recording.")
                    
                    record_process.terminate()
                    time.sleep(2)
                    
                    subprocess.run(['adb', '-s', self.current_device, 'pull', device_path, filename], timeout=30)
                    subprocess.run(['adb', '-s', self.current_device, 'shell', 'rm', device_path], timeout=5)
                    
                    messagebox.showinfo("Success", f"Screen recording saved to {filename}")
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Recording error: {str(e)}")
                    
            threading.Thread(target=record, daemon=True).start()
            
    def send_text_input(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        text = tk.simpledialog.askstring("Send Text", "Enter text to send:")
        if text:
            try:
                escaped_text = text.replace(' ', '%s').replace("'", "\'")
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'input', 'text', escaped_text], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.log_message(f"Sent text: {text}")
                else:
                    raise Exception("Text input failed")
            except Exception as e:
                messagebox.showerror("Error", f"Text input error: {str(e)}")
                
    def simulate_tap(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        coords = tk.simpledialog.askstring("Simulate Tap", "Enter coordinates (x,y):")
        if coords:
            try:
                x, y = coords.split(',')
                x, y = int(x.strip()), int(y.strip())
                
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'input', 'tap', str(x), str(y)], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.log_message(f"Simulated tap at ({x}, {y})")
                else:
                    raise Exception("Tap simulation failed")
            except Exception as e:
                messagebox.showerror("Error", f"Tap simulation error: {str(e)}")
                
    def simulate_swipe(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        swipe_data = tk.simpledialog.askstring("Simulate Swipe", "Enter swipe (x1,y1,x2,y2,duration):")
        if swipe_data:
            try:
                x1, y1, x2, y2, duration = swipe_data.split(',')
                x1, y1, x2, y2 = int(x1.strip()), int(y1.strip()), int(x2.strip()), int(y2.strip())
                duration = int(duration.strip())
                
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'input', 'swipe', 
                                       str(x1), str(y1), str(x2), str(y2), str(duration)], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.log_message(f"Simulated swipe from ({x1}, {y1}) to ({x2}, {y2})")
                else:
                    raise Exception("Swipe simulation failed")
            except Exception as e:
                messagebox.showerror("Error", f"Swipe simulation error: {str(e)}")
                
    def send_key_events(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        key_window = tk.Toplevel(self.root)
        key_window.title("Key Events")
        key_window.geometry("400x300")
        key_window.configure(bg='#1a1a1a')
        
        ttk.Label(key_window, text="Key Events", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=10)
        
        key_buttons = [
            ("Home", "KEYCODE_HOME"),
            ("Back", "KEYCODE_BACK"),
            ("Menu", "KEYCODE_MENU"),
            ("Volume Up", "KEYCODE_VOLUME_UP"),
            ("Volume Down", "KEYCODE_VOLUME_DOWN"),
            ("Power", "KEYCODE_POWER"),
            ("Enter", "KEYCODE_ENTER"),
            ("Space", "KEYCODE_SPACE")
        ]
        
        for display_name, keycode in key_buttons:
            ttk.Button(key_window, text=display_name, style='Dark.TButton',
                      command=lambda kc=keycode: self.send_keycode(kc)).pack(pady=2)
                      
    def send_keycode(self, keycode):
        try:
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'input', 'keyevent', keycode], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.log_message(f"Sent keyevent: {keycode}")
            else:
                raise Exception("Keyevent failed")
        except Exception as e:
            self.log_message(f"Keyevent error: {str(e)}")
            
    def browse_remote_apk(self):
        filename = filedialog.askopenfilename(
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
        )
        if filename:
            self.remote_apk_var.set(filename)
            
    def execute_apk_remotely(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        apk_path = self.remote_apk_var.get()
        if not apk_path:
            messagebox.showwarning("Warning", "No APK selected")
            return
            
        def execute():
            try:
                self.remote_execution_log.insert(tk.END, f"Preparing to execute: {apk_path}\n")
                
                install_result = subprocess.run(['adb', '-s', self.current_device, 'install', '-r', apk_path], 
                                              capture_output=True, text=True, timeout=120)
                
                if install_result.returncode != 0:
                    raise Exception(f"Installation failed: {install_result.stderr}")
                
                self.remote_execution_log.insert(tk.END, "APK installed successfully\n")
                
                aapt_result = subprocess.run(['aapt', 'dump', 'badging', apk_path], 
                                           capture_output=True, text=True, timeout=30)
                
                package_name = None
                main_activity = None
                
                for line in aapt_result.stdout.split('\n'):
                    if line.startswith('package:'):
                        package_name = line.split("name='")[1].split("'")[0]
                    elif 'launchable-activity:' in line:
                        main_activity = line.split("name='")[1].split("'")[0]
                
                if not package_name:
                    raise Exception("Could not extract package name")
                
                self.remote_execution_log.insert(tk.END, f"Package: {package_name}\n")
                
                if main_activity:
                    launch_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'am', 'start', 
                                                  '-n', f"{package_name}/{main_activity}"], 
                                                 capture_output=True, text=True, timeout=30)
                else:
                    launch_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'monkey', '-p', 
                                                  package_name, '-c', 'android.intent.category.LAUNCHER', '1'], 
                                                 capture_output=True, text=True, timeout=30)
                
                if launch_result.returncode == 0:
                    self.remote_execution_log.insert(tk.END, f"APK launched successfully\n")
                    self.remote_execution_log.insert(tk.END, f"Output: {launch_result.stdout}\n")
                else:
                    self.remote_execution_log.insert(tk.END, f"Launch failed: {launch_result.stderr}\n")
                
            except Exception as e:
                self.remote_execution_log.insert(tk.END, f"Execution error: {str(e)}\n")
                
        threading.Thread(target=execute, daemon=True).start()
    
    def navigate_to_path(self, event=None):
        path = self.current_path_var.get()
        self.refresh_file_list(path)
        
    def navigate_up(self):
        current_path = self.current_path_var.get()
        parent_path = os.path.dirname(current_path.rstrip('/'))
        if not parent_path:
            parent_path = '/'
        self.current_path_var.set(parent_path)
        self.refresh_file_list(parent_path)
        
    def refresh_file_list(self, path='/'):
        if not self.current_device:
            return
            
        try:
            self.file_tree.delete(*self.file_tree.get_children())
            
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '-la', path], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip total line
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 9:
                            permissions = parts[0]
                            size = parts[4] if parts[4].isdigit() else '0'
                            date_time = ' '.join(parts[5:8])
                            name = ' '.join(parts[8:])
                            
                            if name not in ['.', '..']:
                                self.file_tree.insert('', 'end', text=name, 
                                                    values=(size, date_time, permissions))
                                                    
        except Exception as e:
            self.log_message(f"File list error: {str(e)}")
            
    def on_file_double_click(self, event):
        selection = self.file_tree.selection()
        if selection:
            item = self.file_tree.item(selection[0])
            filename = item['text']
            current_path = self.current_path_var.get()
            new_path = os.path.join(current_path, filename).replace('\\', '/')
            
            permissions = item['values'][2]
            if permissions.startswith('d'):
                self.current_path_var.set(new_path)
                self.refresh_file_list(new_path)
                
    def download_file(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No file selected")
            return
            
        filename = self.file_tree.item(selection[0])['text']
        current_path = self.current_path_var.get()
        remote_path = os.path.join(current_path, filename).replace('\\', '/')
        
        local_path = filedialog.asksaveasfilename(initialvalue=filename)
        if local_path:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'pull', remote_path, local_path], 
                                      capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    messagebox.showinfo("Success", f"File downloaded to {local_path}")
                else:
                    raise Exception(result.stderr)
            except Exception as e:
                messagebox.showerror("Error", f"Download failed: {str(e)}")
                
    def upload_file(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        local_path = filedialog.askopenfilename()
        if local_path:
            filename = os.path.basename(local_path)
            current_path = self.current_path_var.get()
            remote_path = os.path.join(current_path, filename).replace('\\', '/')
            
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'push', local_path, remote_path], 
                                      capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    messagebox.showinfo("Success", "File uploaded successfully")
                    self.refresh_file_list(current_path)
                else:
                    raise Exception(result.stderr)
            except Exception as e:
                messagebox.showerror("Error", f"Upload failed: {str(e)}")
                
    def delete_file(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No file selected")
            return
            
        filename = self.file_tree.item(selection[0])['text']
        
        result = messagebox.askyesno("Confirm Delete", f"Delete {filename}?")
        if result:
            current_path = self.current_path_var.get()
            remote_path = os.path.join(current_path, filename).replace('\\', '/')
            
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'rm', '-rf', remote_path], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    messagebox.showinfo("Success", "File deleted")
                    self.refresh_file_list(current_path)
                else:
                    raise Exception(result.stderr)
            except Exception as e:
                messagebox.showerror("Error", f"Delete failed: {str(e)}")
                
    def create_folder(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        folder_name = tk.simpledialog.askstring("Create Folder", "Enter folder name:")
        if folder_name:
            current_path = self.current_path_var.get()
            remote_path = os.path.join(current_path, folder_name).replace('\\', '/')
            
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'mkdir', remote_path], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    messagebox.showinfo("Success", "Folder created")
                    self.refresh_file_list(current_path)
                else:
                    raise Exception(result.stderr)
            except Exception as e:
                messagebox.showerror("Error", f"Create folder failed: {str(e)}")
                
    def show_file_properties(self):
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No file selected")
            return
            
        item = self.file_tree.item(selection[0])
        filename = item['text']
        size, date_time, permissions = item['values']
        
        properties_window = tk.Toplevel(self.root)
        properties_window.title(f"Properties - {filename}")
        properties_window.geometry("400x300")
        properties_window.configure(bg='#1a1a1a')
        
        ttk.Label(properties_window, text=f"File: {filename}", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=10)
        ttk.Label(properties_window, text=f"Size: {size} bytes", style='Dark.TLabel').pack()
        ttk.Label(properties_window, text=f"Modified: {date_time}", style='Dark.TLabel').pack()
        ttk.Label(properties_window, text=f"Permissions: {permissions}", style='Dark.TLabel').pack()
        
    def refresh_processes(self):
        if not self.current_device:
            return
            
        try:
            self.process_tree.delete(*self.process_tree.get_children())
            
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ps', '-A'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 9:
                        pid = parts[1]
                        process_name = parts[8] if len(parts) > 8 else parts[-1]
                        
                        cpu = "N/A"
                        memory = "N/A"
                        status = "Running"
                        
                        self.process_tree.insert('', 'end', text=process_name, 
                                               values=(pid, cpu, memory, status))
                                               
        except Exception as e:
            self.log_message(f"Process refresh error: {str(e)}")
            
    def kill_process(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No process selected")
            return
            
        item = self.process_tree.item(selection[0])
        process_name = item['text']
        pid = item['values'][0]
        
        result = messagebox.askyesno("Confirm Kill", f"Kill process {process_name} (PID: {pid})?")
        if result:
            try:
                kill_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'kill', pid], 
                                           capture_output=True, text=True, timeout=10)
                if kill_result.returncode == 0:
                    messagebox.showinfo("Success", f"Process {process_name} killed")
                    self.refresh_processes()
                else:
                    raise Exception("Kill failed")
            except Exception as e:
                messagebox.showerror("Error", f"Kill process error: {str(e)}")
                
    def show_process_info(self):
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No process selected")
            return
            
        item = self.process_tree.item(selection[0])
        process_name = item['text']
        pid = item['values'][0]
        
        info_window = tk.Toplevel(self.root)
        info_window.title(f"Process Info - {process_name}")
        info_window.geometry("600x400")
        info_window.configure(bg='#1a1a1a')
        
        info_text = scrolledtext.ScrolledText(info_window, bg='#2a2a2a', fg='#ffffff')
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def get_process_info():
            try:
                status_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', f'/proc/{pid}/status'], 
                                             capture_output=True, text=True, timeout=10)
                if status_result.returncode == 0:
                    info_text.insert(tk.END, f"Process Status for {process_name} (PID: {pid})\n")
                    info_text.insert(tk.END, "=" * 50 + "\n\n")
                    info_text.insert(tk.END, status_result.stdout)
                else:
                    info_text.insert(tk.END, "Unable to retrieve process information")
                    
            except Exception as e:
                info_text.insert(tk.END, f"Error getting process info: {str(e)}")
                
        threading.Thread(target=get_process_info, daemon=True).start()
        
    def show_memory_map(self):
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No process selected")
            return
            
        item = self.process_tree.item(selection[0])
        process_name = item['text']
        pid = item['values'][0]
        
        map_window = tk.Toplevel(self.root)
        map_window.title(f"Memory Map - {process_name}")
        map_window.geometry("800x600")
        map_window.configure(bg='#1a1a1a')
        
        map_text = scrolledtext.ScrolledText(map_window, bg='#2a2a2a', fg='#ffffff', font=('Courier', 9))
        map_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def get_memory_map():
            try:
                maps_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', f'/proc/{pid}/maps'], 
                                           capture_output=True, text=True, timeout=15)
                if maps_result.returncode == 0:
                    map_text.insert(tk.END, f"Memory Map for {process_name} (PID: {pid})\n")
                    map_text.insert(tk.END, "=" * 70 + "\n\n")
                    map_text.insert(tk.END, maps_result.stdout)
                else:
                    map_text.insert(tk.END, "Unable to retrieve memory map")
                    
            except Exception as e:
                map_text.insert(tk.END, f"Error getting memory map: {str(e)}")
                
        threading.Thread(target=get_memory_map, daemon=True).start()
    
    def read_sms(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        def get_sms():
            try:
                self.comm_log.insert(tk.END, "Reading SMS messages...\n")
                
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 
                                       'content', 'query', '--uri', 'content://sms/inbox', 
                                       '--projection', 'address,date,body'], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.comm_log.insert(tk.END, "SMS Messages:\n")
                    self.comm_log.insert(tk.END, "=" * 40 + "\n")
                    
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'address=' in line:
                            parts = line.split(', ')
                            address = parts[0].split('=')[1] if len(parts) > 0 else 'Unknown'
                            date = parts[1].split('=')[1] if len(parts) > 1 else 'Unknown'
                            body = parts[2].split('=')[1] if len(parts) > 2 else 'Unknown'
                            
                            self.comm_log.insert(tk.END, f"From: {address}\n")
                            self.comm_log.insert(tk.END, f"Date: {date}\n")
                            self.comm_log.insert(tk.END, f"Message: {body}\n\n")
                else:
                    self.comm_log.insert(tk.END, "Failed to read SMS (permission required)\n")
                    
            except Exception as e:
                self.comm_log.insert(tk.END, f"SMS read error: {str(e)}\n")
                
        threading.Thread(target=get_sms, daemon=True).start()
        
    def send_sms(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        sms_window = tk.Toplevel(self.root)
        sms_window.title("Send SMS")
        sms_window.geometry("400x300")
        sms_window.configure(bg='#1a1a1a')
        
        ttk.Label(sms_window, text="Send SMS", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=10)
        
        ttk.Label(sms_window, text="To:", style='Dark.TLabel').pack()
        to_var = tk.StringVar()
        ttk.Entry(sms_window, textvariable=to_var, style='Dark.TEntry', width=30).pack(pady=5)
        
        ttk.Label(sms_window, text="Message:", style='Dark.TLabel').pack()
        message_text = scrolledtext.ScrolledText(sms_window, height=8, width=40, bg='#2a2a2a', fg='#ffffff')
        message_text.pack(pady=5)
        
        def send():
            to_number = to_var.get()
            message = message_text.get(1.0, tk.END).strip()
            
            if to_number and message:
                try:
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'am', 'start', 
                                           '-a', 'android.intent.action.SENDTO', 
                                           '-d', f'sms:{to_number}', 
                                           '--es', 'sms_body', message], 
                                          capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        messagebox.showinfo("Success", "SMS sending intent launched")
                        sms_window.destroy()
                    else:
                        raise Exception("SMS send failed")
                except Exception as e:
                    messagebox.showerror("Error", f"SMS error: {str(e)}")
                    
        ttk.Button(sms_window, text="Send SMS", style='Dark.TButton', command=send).pack(pady=10)
        
    def get_call_history(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        def get_calls():
            try:
                self.comm_log.insert(tk.END, "Reading call history...\n")
                
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 
                                       'content', 'query', '--uri', 'content://call_log/calls', 
                                       '--projection', 'number,date,duration,type'], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.comm_log.insert(tk.END, "Call History:\n")
                    self.comm_log.insert(tk.END, "=" * 40 + "\n")
                    
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'number=' in line:
                            parts = line.split(', ')
                            number = parts[0].split('=')[1] if len(parts) > 0 else 'Unknown'
                            date = parts[1].split('=')[1] if len(parts) > 1 else 'Unknown'
                            duration = parts[2].split('=')[1] if len(parts) > 2 else 'Unknown'
                            call_type = parts[3].split('=')[1] if len(parts) > 3 else 'Unknown'
                            
                            self.comm_log.insert(tk.END, f"Number: {number}\n")
                            self.comm_log.insert(tk.END, f"Date: {date}\n")
                            self.comm_log.insert(tk.END, f"Duration: {duration}s\n")
                            self.comm_log.insert(tk.END, f"Type: {call_type}\n\n")
                else:
                    self.comm_log.insert(tk.END, "Failed to read call history (permission required)\n")
                    
            except Exception as e:
                self.comm_log.insert(tk.END, f"Call history error: {str(e)}\n")
                
        threading.Thread(target=get_calls, daemon=True).start()
        
    def get_contacts(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        def get_contact_list():
            try:
                self.comm_log.insert(tk.END, "Reading contacts...\n")
                
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 
                                       'content', 'query', '--uri', 'content://com.android.contacts/contacts', 
                                       '--projection', 'display_name'], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.comm_log.insert(tk.END, "Contacts:\n")
                    self.comm_log.insert(tk.END, "=" * 40 + "\n")
                    
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'display_name=' in line:
                            name = line.split('=')[1]
                            self.comm_log.insert(tk.END, f"Contact: {name}\n")
                else:
                    self.comm_log.insert(tk.END, "Failed to read contacts (permission required)\n")
                    
            except Exception as e:
                self.comm_log.insert(tk.END, f"Contacts error: {str(e)}\n")
                
        threading.Thread(target=get_contact_list, daemon=True).start()
        
    def get_current_location(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        def get_location():
            try:
                self.comm_log.insert(tk.END, "Getting current location...\n")
                
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'dumpsys', 'location'], 
                                      capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    location_data = result.stdout
                    if 'Last Known Locations' in location_data:
                        self.comm_log.insert(tk.END, "Location Services Information:\n")
                        self.comm_log.insert(tk.END, "=" * 40 + "\n")
                        
                        lines = location_data.split('\n')
                        for line in lines:
                            if 'lat=' in line or 'lon=' in line or 'time=' in line:
                                self.comm_log.insert(tk.END, f"{line.strip()}\n")
                    else:
                        self.comm_log.insert(tk.END, "No location data available\n")
                else:
                    self.comm_log.insert(tk.END, "Failed to get location data\n")
                    
            except Exception as e:
                self.comm_log.insert(tk.END, f"Location error: {str(e)}\n")
                
        threading.Thread(target=get_location, daemon=True).start()
        
    def spoof_location(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        location_window = tk.Toplevel(self.root)
        location_window.title("Spoof Location")
        location_window.geometry("300x200")
        location_window.configure(bg='#1a1a1a')
        
        ttk.Label(location_window, text="Spoof Location", style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=10)
        
        ttk.Label(location_window, text="Latitude:", style='Dark.TLabel').pack()
        lat_var = tk.StringVar()
        ttk.Entry(location_window, textvariable=lat_var, style='Dark.TEntry', width=20).pack(pady=2)
        
        ttk.Label(location_window, text="Longitude:", style='Dark.TLabel').pack()
        lon_var = tk.StringVar()
        ttk.Entry(location_window, textvariable=lon_var, style='Dark.TEntry', width=20).pack(pady=2)
        
        def spoof():
            latitude = lat_var.get()
            longitude = lon_var.get()
            
            if latitude and longitude:
                try:
                    subprocess.run(['adb', '-s', self.current_device, 'shell', 'settings', 'put', 'secure', 'mock_location', '1'], 
                                  capture_output=True, text=True, timeout=10)
                    
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'am', 'broadcast', 
                                           '-a', 'android.location.GPS_ENABLED_CHANGE'], 
                                          capture_output=True, text=True, timeout=10)
                    
                    messagebox.showinfo("Success", f"Location spoofing attempted: {latitude}, {longitude}")
                    location_window.destroy()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Location spoofing error: {str(e)}")
                    
        ttk.Button(location_window, text="Spoof Location", style='Dark.TButton', command=spoof).pack(pady=10)
        
    def get_location_history(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        def get_history():
            try:
                self.comm_log.insert(tk.END, "Reading location history...\n")
                
                sources = [
                    ('Google Location History', 'find /data/data/com.google.android.gms -name "*location*" -type f'),
                    ('System Location Cache', 'find /data/system -name "*location*" -type f'),
                    ('Location Services', 'dumpsys location | grep -A 10 "Historical"')
                ]
                
                for source_name, command in sources:
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                          capture_output=True, text=True, timeout=15)
                    
                    self.comm_log.insert(tk.END, f"\n{source_name}:\n")
                    if result.returncode == 0 and result.stdout.strip():
                        self.comm_log.insert(tk.END, result.stdout[:500] + "...\n")
                    else:
                        self.comm_log.insert(tk.END, "No data or access denied\n")
                        
            except Exception as e:
                self.comm_log.insert(tk.END, f"Location history error: {str(e)}\n")
                
        threading.Thread(target=get_history, daemon=True).start()
    
    def start_network_monitor(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.network_monitor_active = True
        
        def network_monitor():
            while self.network_monitor_active:
                try:
                    self.network_tree.delete(*self.network_tree.get_children())
                    
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'netstat', '-an'], 
                                          capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')[2:]  
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 6:
                                protocol = parts[0]
                                local_addr = parts[3]
                                remote_addr = parts[4]
                                state = parts[5] if len(parts) > 5 else 'UNKNOWN'
                                
                                process = 'Unknown'
                                
                                self.network_tree.insert('', 'end', 
                                                        values=(protocol, local_addr, remote_addr, state, process))
                    
                    time.sleep(3)
                    
                except Exception as e:
                    self.log_message(f"Network monitor error: {str(e)}")
                    break
                    
        threading.Thread(target=network_monitor, daemon=True).start()
        
    def stop_network_monitor(self):
        self.network_monitor_active = False
        
    def show_network_stats(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Network Statistics")
        stats_window.geometry("600x400")
        stats_window.configure(bg='#1a1a1a')
        
        stats_text = scrolledtext.ScrolledText(stats_window, bg='#2a2a2a', fg='#ffffff')
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def get_stats():
            try:
                commands = [
                    ('Network Interfaces', 'ip addr show'),
                    ('Routing Table', 'ip route'),
                    ('Network Statistics', 'cat /proc/net/dev'),
                    ('TCP Connections', 'cat /proc/net/tcp'),
                    ('UDP Connections', 'cat /proc/net/udp')
                ]
                
                for title, command in commands:
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                          capture_output=True, text=True, timeout=10)
                    
                    stats_text.insert(tk.END, f"\n{title}:\n")
                    stats_text.insert(tk.END, "=" * 40 + "\n")
                    
                    if result.returncode == 0:
                        stats_text.insert(tk.END, result.stdout[:1000] + "\n")
                    else:
                        stats_text.insert(tk.END, "Unable to retrieve data\n")
                        
            except Exception as e:
                stats_text.insert(tk.END, f"Error getting network stats: {str(e)}")
                
        threading.Thread(target=get_stats, daemon=True).start()
        
    def get_wifi_info(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        def get_wifi():
            try:
                self.comm_log.insert(tk.END, "Getting WiFi information...\n")
                
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'dumpsys', 'wifi'], 
                                      capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    wifi_data = result.stdout
                    
                    self.comm_log.insert(tk.END, "WiFi Information:\n")
                    self.comm_log.insert(tk.END, "=" * 40 + "\n")
                    
                    lines = wifi_data.split('\n')
                    for line in lines:
                        if any(keyword in line.lower() for keyword in ['ssid', 'bssid', 'signal', 'frequency', 'security']):
                            self.comm_log.insert(tk.END, f"{line.strip()}\n")
                            
                    scan_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'dumpsys', 'wifiscanner'], 
                                               capture_output=True, text=True, timeout=10)
                    
                    if scan_result.returncode == 0:
                        self.comm_log.insert(tk.END, "\nAvailable Networks:\n")
                        scan_lines = scan_result.stdout.split('\n')
                        for line in scan_lines[:20]:  # Limit output
                            if 'SSID' in line or 'BSSID' in line:
                                self.comm_log.insert(tk.END, f"{line.strip()}\n")
                else:
                    self.comm_log.insert(tk.END, "Failed to get WiFi information\n")
                    
            except Exception as e:
                self.comm_log.insert(tk.END, f"WiFi info error: {str(e)}\n")
                
        threading.Thread(target=get_wifi, daemon=True).start()
        
    def capture_network_traffic(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            def capture():
                try:
                    self.log_message("Starting network capture...")
                    
                    tcpdump_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'which', 'tcpdump'], 
                                                  capture_output=True, text=True, timeout=5)
                    
                    if tcpdump_result.returncode == 0:
                        device_capture_file = '/data/local/tmp/capture.pcap'
                        
                        capture_process = subprocess.Popen(['adb', '-s', self.current_device, 'shell', 
                                                          'tcpdump', '-w', device_capture_file, '-s', '0'])
                        
                        messagebox.showinfo("Capture", "Network capture started. Click OK to stop.")
                        
                        capture_process.terminate()
                        time.sleep(2)
                        
                        subprocess.run(['adb', '-s', self.current_device, 'pull', device_capture_file, filename], 
                                     timeout=30)
                        subprocess.run(['adb', '-s', self.current_device, 'shell', 'rm', device_capture_file], 
                                     timeout=5)
                        
                        messagebox.showinfo("Success", f"Network capture saved to {filename}")
                    else:
                        messagebox.showwarning("Warning", "tcpdump not available on device")
                        
                except Exception as e:
                    messagebox.showerror("Error", f"Network capture error: {str(e)}")
                    
            threading.Thread(target=capture, daemon=True).start()
            
    def block_connection(self):
        selection = self.network_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No connection selected")
            return
            
        item = self.network_tree.item(selection[0])
        remote_addr = item['values'][2]
        
        result = messagebox.askyesno("Confirm Block", f"Block connection to {remote_addr}?")
        if result:
            try:
                block_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'su', '-c', 
                                             f'iptables -A OUTPUT -d {remote_addr.split(":")[0]} -j DROP'], 
                                            capture_output=True, text=True, timeout=10)
                
                if block_result.returncode == 0:
                    messagebox.showinfo("Success", f"Connection to {remote_addr} blocked")
                else:
                    raise Exception("Block failed - root required")
                    
            except Exception as e:
                messagebox.showerror("Error", f"Block connection error: {str(e)}")
                
    def export_network_capture(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("Network Connections Export\n")
                    f.write("=" * 40 + "\n\n")
                    
                    for item in self.network_tree.get_children():
                        values = self.network_tree.item(item)['values']
                        f.write(f"Protocol: {values[0]}\n")
                        f.write(f"Local: {values[1]}\n")
                        f.write(f"Remote: {values[2]}\n")
                        f.write(f"State: {values[3]}\n")
                        f.write(f"Process: {values[4]}\n\n")
                        
                messagebox.showinfo("Success", f"Network data exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def execute_shell_command(self, event=None):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        command = self.shell_command_var.get()
        if command:
            self.command_history.append(command)
            
            def execute():
                try:
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    self.shell_output.insert(tk.END, f"[{timestamp}] $ {command}\n")
                    
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                          capture_output=True, text=True, timeout=30)
                    
                    if result.stdout:
                        self.shell_output.insert(tk.END, result.stdout)
                    if result.stderr:
                        self.shell_output.insert(tk.END, f"ERROR: {result.stderr}")
                    
                    self.shell_output.insert(tk.END, f"\nReturn code: {result.returncode}\n\n")
                    self.shell_output.see(tk.END)
                    
                except Exception as e:
                    self.shell_output.insert(tk.END, f"Command error: {str(e)}\n\n")
                    
            threading.Thread(target=execute, daemon=True).start()
            self.shell_command_var.set("")
            
    def quick_command(self, command):
        self.shell_command_var.set(command)
        self.execute_shell_command()
        
    def clear_shell(self):
        self.shell_output.delete(1.0, tk.END)
    
    def start_keylogger(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.keylogger_active = True
        
        def keylogger():
            try:
                self.keylog_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Keylogger started\n")
                
                input_process = subprocess.Popen(['adb', '-s', self.current_device, 'shell', 'getevent'], 
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                               universal_newlines=True, bufsize=1)
                
                while self.keylogger_active and input_process.poll() is None:
                    line = input_process.stdout.readline()
                    if line and 'EV_KEY' in line:
                        timestamp = datetime.now().strftime('%H:%M:%S')
                        
                        if 'DOWN' in line:
                            key_info = line.strip()
                            self.keylog_text.insert(tk.END, f"[{timestamp}] KEY: {key_info}\n")
                            self.keylog_text.see(tk.END)
                
                input_process.terminate()
                
            except Exception as e:
                self.keylog_text.insert(tk.END, f"Keylogger error: {str(e)}\n")
                
        threading.Thread(target=keylogger, daemon=True).start()
        
    def stop_keylogger(self):
        self.keylogger_active = False
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.keylog_text.insert(tk.END, f"[{timestamp}] Keylogger stopped\n")
        
    def clear_keylog(self):
        self.keylog_text.delete(1.0, tk.END)
        
    def export_keylog(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                content = self.keylog_text.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(f"Keylogger Export - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(content)
                messagebox.showinfo("Success", f"Keylog exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def vulnerability_scan(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.scan_results.delete(1.0, tk.END)
        self.scan_progress['value'] = 0
        
        def vuln_scan():
            try:
                vulnerabilities = [
                    ("Insecure ADB", self.check_adb_security),
                    ("Root Detection", self.check_root_detection),
                    ("Debug Flags", self.check_debug_flags),
                    ("Weak Permissions", self.check_weak_permissions),
                    ("Exposed Services", self.check_exposed_services),
                    ("Insecure Storage", self.check_insecure_storage),
                    ("Network Security", self.check_network_security),
                    ("Certificate Validation", self.check_cert_validation)
                ]
                
                total_checks = len(vulnerabilities)
                for i, (vuln_name, check_func) in enumerate(vulnerabilities):
                    self.scan_results.insert(tk.END, f"\n{'='*50}\n")
                    self.scan_results.insert(tk.END, f"Vulnerability Check: {vuln_name}\n")
                    self.scan_results.insert(tk.END, f"{'='*50}\n")
                    
                    check_func()
                    
                    progress = ((i + 1) / total_checks) * 100
                    self.scan_progress['value'] = progress
                    
                self.scan_results.insert(tk.END, f"\n{'='*50}\n")
                self.scan_results.insert(tk.END, "Vulnerability scan completed.\n")
                
            except Exception as e:
                self.scan_results.insert(tk.END, f"Vulnerability scan error: {str(e)}\n")
                
        threading.Thread(target=vuln_scan, daemon=True).start()
        
    def check_adb_security(self):
        try:
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'service.adb.tcp.port'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                self.scan_results.insert(tk.END, "CRITICAL: ADB over TCP is enabled\n")
                self.scan_results.insert(tk.END, f"Port: {result.stdout.strip()}\n")
            else:
                self.scan_results.insert(tk.END, "OK: ADB over TCP not detected\n")
                
            debug_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'persist.sys.usb.config'], 
                                        capture_output=True, text=True, timeout=5)
            
            if debug_result.returncode == 0:
                self.scan_results.insert(tk.END, f"USB Config: {debug_result.stdout.strip()}\n")
                
        except Exception as e:
            self.scan_results.insert(tk.END, f"ADB security check error: {str(e)}\n")
            
    def check_root_detection(self):
        try:
            root_indicators = [
                '/system/app/Superuser.apk',
                '/system/xbin/su',
                '/system/bin/su',
                '/data/local/xbin/su',
                '/data/local/bin/su'
            ]
            
            root_found = False
            for indicator in root_indicators:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', indicator], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.scan_results.insert(tk.END, f"ROOT INDICATOR: {indicator}\n")
                    root_found = True
                    
            if not root_found:
                self.scan_results.insert(tk.END, "No obvious root indicators found\n")
                
        except Exception as e:
            self.scan_results.insert(tk.END, f"Root detection error: {str(e)}\n")
            
    def check_debug_flags(self):
        try:
            debug_props = [
                'ro.debuggable',
                'ro.secure',
                'service.adb.root',
                'ro.build.type'
            ]
            
            for prop in debug_props:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', prop], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    value = result.stdout.strip()
                    if prop == 'ro.debuggable' and value == '1':
                        self.scan_results.insert(tk.END, f"WARNING: {prop} = {value}\n")
                    elif prop == 'ro.secure' and value == '0':
                        self.scan_results.insert(tk.END, f"CRITICAL: {prop} = {value}\n")
                    else:
                        self.scan_results.insert(tk.END, f"INFO: {prop} = {value}\n")
                        
        except Exception as e:
            self.scan_results.insert(tk.END, f"Debug flags check error: {str(e)}\n")
            
    def check_weak_permissions(self):
        try:
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'find', '/data', '-type', 'd', '-perm', '-002'], 
                                  capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0:
                writable_dirs = result.stdout.strip().split('\n')
                if writable_dirs and writable_dirs[0]:
                    self.scan_results.insert(tk.END, f"Found {len(writable_dirs)} world-writable directories:\n")
                    for directory in writable_dirs[:10]:  # Show first 10
                        if directory.strip():
                            self.scan_results.insert(tk.END, f"  {directory}\n")
                else:
                    self.scan_results.insert(tk.END, "No world-writable directories found in /data\n")
                    
        except Exception as e:
            self.scan_results.insert(tk.END, f"Permissions check error: {str(e)}\n")
            
    def check_exposed_services(self):
        try:
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'netstat', '-ln'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                listening_services = []
                for line in result.stdout.split('\n'):
                    if 'LISTEN' in line and ('0.0.0.0' in line or '::' in line):
                        listening_services.append(line.strip())
                        
                if listening_services:
                    self.scan_results.insert(tk.END, f"Found {len(listening_services)} exposed services:\n")
                    for service in listening_services[:10]:
                        self.scan_results.insert(tk.END, f"  {service}\n")
                else:
                    self.scan_results.insert(tk.END, "No obviously exposed services found\n")
                    
        except Exception as e:
            self.scan_results.insert(tk.END, f"Exposed services check error: {str(e)}\n")
            
    def check_insecure_storage(self):
        try:
            storage_locations = [
                '/sdcard',
                '/data/local/tmp',
                '/cache'
            ]
            
            for location in storage_locations:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '-la', location], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    sensitive_files = [line for line in lines if any(ext in line.lower() for ext in ['.key', '.pem', '.p12', 'password', 'secret'])]
                    
                    if sensitive_files:
                        self.scan_results.insert(tk.END, f"Potential sensitive files in {location}:\n")
                        for file_line in sensitive_files[:5]:
                            self.scan_results.insert(tk.END, f"  {file_line.strip()}\n")
                            
        except Exception as e:
            self.scan_results.insert(tk.END, f"Insecure storage check error: {str(e)}\n")
            
    def check_network_security(self):
        try:
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', '/proc/net/tcp'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                tcp_connections = result.stdout.count('\n') - 1
                self.scan_results.insert(tk.END, f"Active TCP connections: {tcp_connections}\n")
                
            wifi_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'dumpsys', 'wifi', '|', 'grep', '-i', 'security'], 
                                       capture_output=True, text=True, timeout=10)
            
            if wifi_result.returncode == 0 and wifi_result.stdout.strip():
                self.scan_results.insert(tk.END, "WiFi security information found\n")
                
        except Exception as e:
            self.scan_results.insert(tk.END, f"Network security check error: {str(e)}\n")
            
    def check_cert_validation(self):
        try:
            cert_stores = [
                '/system/etc/security/cacerts',
                '/data/misc/keystore'
            ]
            
            for store in cert_stores:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '-la', store], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    cert_count = result.stdout.count('\n') - 1
                    self.scan_results.insert(tk.END, f"Certificates in {store}: {cert_count}\n")
                    
        except Exception as e:
            self.scan_results.insert(tk.END, f"Certificate validation check error: {str(e)}\n")
    
    def extract_apk(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        selection = self.package_list.selection()
        if not selection:
            messagebox.showwarning("Warning", "No package selected")
            return
            
        package_name = self.package_list.item(selection[0])['values'][0]
        
        save_path = filedialog.asksaveasfilename(
            defaultextension=".apk",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")],
            initialvalue=f"{package_name}.apk"
        )
        
        if save_path:
            def extract():
                try:
                    self.update_status("Extracting APK...")
                    
                    path_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'pm', 'path', package_name], 
                                               capture_output=True, text=True, timeout=15)
                    
                    if path_result.returncode == 0:
                        apk_path = path_result.stdout.strip().replace('package:', '')
                        
                        extract_result = subprocess.run(['adb', '-s', self.current_device, 'pull', apk_path, save_path], 
                                                      capture_output=True, text=True, timeout=60)
                        
                        if extract_result.returncode == 0:
                            messagebox.showinfo("Success", f"APK extracted to {save_path}")
                        else:
                            raise Exception(extract_result.stderr)
                    else:
                        raise Exception("Could not find APK path")
                        
                except Exception as e:
                    messagebox.showerror("Error", f"APK extraction failed: {str(e)}")
                finally:
                    self.update_status("Ready")
                    
            threading.Thread(target=extract, daemon=True).start()
    
    def show_realtime_stats(self):
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Real-time Statistics")
        stats_window.geometry("800x600")
        stats_window.configure(bg='#1a1a1a')
        
        stats_text = scrolledtext.ScrolledText(stats_window, bg='#2a2a2a', fg='#ffffff', font=('Courier', 10))
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        monitoring = True
        
        def update_stats():
            if not monitoring:
                return
                
            try:
                stats_text.delete(1.0, tk.END)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                stats_text.insert(tk.END, f"Real-time Statistics - {timestamp}\n")
                stats_text.insert(tk.END, "=" * 60 + "\n\n")
                
                cpu_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', '/proc/stat'], 
                                          capture_output=True, text=True, timeout=5)
                if cpu_result.returncode == 0:
                    cpu_line = cpu_result.stdout.split('\n')[0]
                    stats_text.insert(tk.END, f"CPU: {cpu_line}\n\n")
                
                mem_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', '/proc/meminfo'], 
                                          capture_output=True, text=True, timeout=5)
                if mem_result.returncode == 0:
                    mem_lines = mem_result.stdout.split('\n')[:10]
                    stats_text.insert(tk.END, "Memory Information:\n")
                    for line in mem_lines:
                        if line.strip():
                            stats_text.insert(tk.END, f"  {line}\n")
                    stats_text.insert(tk.END, "\n")
                
                top_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'top', '-n', '1'], 
                                          capture_output=True, text=True, timeout=10)
                if top_result.returncode == 0:
                    top_lines = top_result.stdout.split('\n')[:15]
                    stats_text.insert(tk.END, "Top Processes:\n")
                    for line in top_lines:
                        if line.strip():
                            stats_text.insert(tk.END, f"  {line}\n")
                
            except Exception as e:
                stats_text.insert(tk.END, f"Error updating stats: {str(e)}\n")
                
            if monitoring:
                stats_window.after(2000, update_stats) 
                
        def on_close():
            nonlocal monitoring
            monitoring = False
            stats_window.destroy()
            
        stats_window.protocol("WM_DELETE_WINDOW", on_close)
        update_stats()
        
    def show_hardware_details(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        hw_window = tk.Toplevel(self.root)
        hw_window.title("Hardware Details")
        hw_window.geometry("700x500")
        hw_window.configure(bg='#1a1a1a')
        
        hw_text = scrolledtext.ScrolledText(hw_window, bg='#2a2a2a', fg='#ffffff')
        hw_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def get_hardware_info():
            try:
                hw_text.insert(tk.END, "Detailed Hardware Information\n")
                hw_text.insert(tk.END, "=" * 50 + "\n\n")
                
                cpu_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', '/proc/cpuinfo'], 
                                          capture_output=True, text=True, timeout=10)
                if cpu_result.returncode == 0:
                    hw_text.insert(tk.END, "CPU Information:\n")
                    hw_text.insert(tk.END, cpu_result.stdout[:1000] + "\n\n")
                
                sensor_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'dumpsys', 'sensorservice'], 
                                             capture_output=True, text=True, timeout=10)
                if sensor_result.returncode == 0:
                    hw_text.insert(tk.END, "Sensors:\n")
                    sensor_lines = sensor_result.stdout.split('\n')
                    for line in sensor_lines[:30]:
                        if 'sensor' in line.lower() or 'accelerometer' in line.lower() or 'gyroscope' in line.lower():
                            hw_text.insert(tk.END, f"  {line.strip()}\n")
                    hw_text.insert(tk.END, "\n")
                
                display_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'wm', 'size'], 
                                              capture_output=True, text=True, timeout=5)
                if display_result.returncode == 0:
                    hw_text.insert(tk.END, f"Display: {display_result.stdout.strip()}\n")
                
                density_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'wm', 'density'], 
                                              capture_output=True, text=True, timeout=5)
                if density_result.returncode == 0:
                    hw_text.insert(tk.END, f"Density: {density_result.stdout.strip()}\n\n")
                
                battery_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'dumpsys', 'battery'], 
                                              capture_output=True, text=True, timeout=10)
                if battery_result.returncode == 0:
                    hw_text.insert(tk.END, "Battery Information:\n")
                    battery_lines = battery_result.stdout.split('\n')
                    for line in battery_lines[:15]:
                        if any(keyword in line.lower() for keyword in ['level', 'voltage', 'temperature', 'technology']):
                            hw_text.insert(tk.END, f"  {line.strip()}\n")
                            
            except Exception as e:
                hw_text.insert(tk.END, f"Error getting hardware info: {str(e)}")
                
        threading.Thread(target=get_hardware_info, daemon=True).start()
    
    def create_memory_dump(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        dump_type = messagebox.askyesnocancel("Memory Dump Type", 
                                            "Yes = Full memory dump\nNo = Process memory dump\nCancel = Abort")
        
        if dump_type is None:
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".dump",
            filetypes=[("Dump files", "*.dump"), ("All files", "*.*")]
        )
        
        if filename:
            def create_dump():
                try:
                    self.re_text.insert(tk.END, f"Creating memory dump...\n")
                    
                    if dump_type:  
                        result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'su', '-c', 
                                               'dd if=/proc/kcore bs=1M count=100'], 
                                              capture_output=True, timeout=60)
                        
                        if result.returncode == 0:
                            with open(filename, 'wb') as f:
                                f.write(result.stdout)
                            self.re_text.insert(tk.END, f"Full memory dump saved to {filename}\n")
                        else:
                            raise Exception("Memory dump failed - root required")
                            
                    else: 
                        pid = tk.simpledialog.askstring("Process PID", "Enter process PID:")
                        if pid:
                            maps_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', f'/proc/{pid}/maps'], 
                                                       capture_output=True, text=True, timeout=15)
                            
                            if maps_result.returncode == 0:
                                with open(filename, 'w') as f:
                                    f.write(f"Process Memory Map (PID: {pid})\n")
                                    f.write("=" * 40 + "\n\n")
                                    f.write(maps_result.stdout)
                                    
                                self.re_text.insert(tk.END, f"Process memory map saved to {filename}\n")
                            else:
                                raise Exception("Process not found or access denied")
                                
                except Exception as e:
                    self.re_text.insert(tk.END, f"Memory dump error: {str(e)}\n")
                    
            threading.Thread(target=create_dump, daemon=True).start()
    
    def attempt_root_device(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        result = messagebox.askyesno("Security Research Compliance", 
                                "This tool is for authorized security research only.\n"
                                "Ensure you have explicit permission to analyze this device.\n"
                                "Unauthorized access violates laws and policies.\n\n"
                                "Do you have authorization to proceed?")
        if not result:
            return
            
        def root_analysis():
            try:
                self.security_text.insert(tk.END, "\n" + "="*60 + "\n")
                self.security_text.insert(tk.END, "ANDROID SECURITY ANALYSIS FRAMEWORK\n")
                self.security_text.insert(tk.END, "="*60 + "\n")
                self.security_text.insert(tk.END, f"Target Device: {self.current_device}\n")
                self.security_text.insert(tk.END, f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                self.security_text.insert(tk.END, "PHASE 1: Security State Assessment\n")
                self.security_text.insert(tk.END, "-" * 40 + "\n")
                
                current_root_status = self.check_current_root_status()
                security_context = self.analyze_security_context()
                bootloader_status = self.check_bootloader_status()
                selinux_status = self.analyze_selinux_configuration()
                
                self.security_text.insert(tk.END, "\nPHASE 2: Vulnerability Analysis\n")
                self.security_text.insert(tk.END, "-" * 40 + "\n")
                
                kernel_info = self.analyze_kernel_security()
                partition_analysis = self.analyze_partition_security()
                binary_analysis = self.analyze_system_binaries()
                service_analysis = self.analyze_system_services()
                
                self.security_text.insert(tk.END, "\nPHASE 3: Root Vector Assessment\n")
                self.security_text.insert(tk.END, "-" * 40 + "\n")
                
                if current_root_status['has_root']:
                    self.security_text.insert(tk.END, "Device already has root access - analyzing implementation\n")
                    self.analyze_existing_root()
                else:
                    self.security_text.insert(tk.END, "No existing root detected - analyzing potential vectors\n")
                    self.assess_rooting_vectors()
                
                self.security_text.insert(tk.END, "\nPHASE 4: Security Recommendations\n")
                self.security_text.insert(tk.END, "-" * 40 + "\n")
                
                self.generate_security_recommendations(
                    current_root_status, security_context, 
                    bootloader_status, selinux_status
                )
                
                self.security_text.insert(tk.END, "\n" + "="*60 + "\n")
                self.security_text.insert(tk.END, "SECURITY ANALYSIS COMPLETED\n")
                self.security_text.insert(tk.END, "="*60 + "\n")
                
            except Exception as e:
                self.security_text.insert(tk.END, f"Analysis error: {str(e)}\n")
                
        threading.Thread(target=root_analysis, daemon=True).start()

    def check_current_root_status(self):
        root_status = {
            'has_root': False,
            'root_method': 'None',
            'root_access_level': 'None',
            'su_locations': [],
            'root_apps': [],
            'busybox_present': False
        }
        
        try:
            self.security_text.insert(tk.END, "Checking current root status...\n")
            
            su_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'su', '-c', 'id'], 
                                    capture_output=True, text=True, timeout=10)
            
            if su_result.returncode == 0 and 'uid=0' in su_result.stdout:
                root_status['has_root'] = True
                root_status['root_access_level'] = 'Full'
                self.security_text.insert(tk.END, f"✓ Root access confirmed: {su_result.stdout.strip()}\n")
            
            su_locations = [
                '/system/bin/su', '/system/xbin/su', '/vendor/bin/su',
                '/sbin/su', '/data/local/tmp/su', '/data/local/bin/su',
                '/system/sd/xbin/su', '/system/bin/.ext/.su', '/system/xbin/.su'
            ]
            
            for location in su_locations:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '-la', location], 
                                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    root_status['su_locations'].append(location)
                    self.security_text.insert(tk.END, f"✓ Found su binary: {location}\n")
            
            root_apps = ['com.noshufou.android.su', 'com.thirdparty.superuser', 
                        'eu.chainfire.supersu', 'com.topjohnwu.magisk']
            
            for app in root_apps:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'pm', 'list', 'packages', app], 
                                    capture_output=True, text=True, timeout=5)
                if app in result.stdout:
                    root_status['root_apps'].append(app)
                    self.security_text.insert(tk.END, f"✓ Found root app: {app}\n")
            
            busybox_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'which', 'busybox'], 
                                        capture_output=True, text=True, timeout=5)
            if busybox_result.returncode == 0:
                root_status['busybox_present'] = True
                self.security_text.insert(tk.END, f"✓ Busybox found: {busybox_result.stdout.strip()}\n")
            
            if 'com.topjohnwu.magisk' in root_status['root_apps']:
                root_status['root_method'] = 'Magisk'
            elif 'eu.chainfire.supersu' in root_status['root_apps']:
                root_status['root_method'] = 'SuperSU'
            elif root_status['su_locations']:
                root_status['root_method'] = 'Manual/Custom'
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Root check error: {str(e)}\n")
        
        return root_status

    def analyze_security_context(self):
        security_context = {}
        
        try:
            self.security_text.insert(tk.END, "\nAnalyzing security context...\n")
            
            security_props = {
                'ro.debuggable': 'Debug mode',
                'ro.secure': 'Secure mode',
                'ro.build.type': 'Build type',
                'ro.build.tags': 'Build tags',
                'service.adb.root': 'ADB root',
                'ro.boot.verifiedbootstate': 'Verified boot'
            }
            
            for prop, description in security_props.items():
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', prop], 
                                    capture_output=True, text=True, timeout=5)
                
                value = result.stdout.strip() if result.returncode == 0 else 'Unknown'
                security_context[prop] = value
                
                if prop == 'ro.debuggable' and value == '1':
                    self.security_text.insert(tk.END, f"⚠ {description}: {value} (Debug build - less secure)\n")
                elif prop == 'ro.secure' and value == '0':
                    self.security_text.insert(tk.END, f"⚠ {description}: {value} (Insecure mode)\n")
                elif prop == 'service.adb.root' and value == '1':
                    self.security_text.insert(tk.END, f"⚠ {description}: {value} (ADB has root)\n")
                else:
                    self.security_text.insert(tk.END, f"ℹ {description}: {value}\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Security context analysis error: {str(e)}\n")
        
        return security_context

    def check_bootloader_status(self):
        bootloader_info = {}
        
        try:
            self.security_text.insert(tk.END, "\nAnalyzing bootloader status...\n")
            
            unlock_props = [
                'ro.boot.flash.locked',
                'ro.boot.unlocked',
                'ro.boot.warranty_bit',
                'ro.warranty_bit'
            ]
            
            for prop in unlock_props:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', prop], 
                                    capture_output=True, text=True, timeout=5)
                
                value = result.stdout.strip() if result.returncode == 0 else 'Unknown'
                bootloader_info[prop] = value
                
                if prop == 'ro.boot.flash.locked' and value == '0':
                    self.security_text.insert(tk.END, f"⚠ Bootloader unlocked: {prop}={value}\n")
                elif prop == 'ro.boot.warranty_bit' and value == '1':
                    self.security_text.insert(tk.END, f"⚠ Warranty void: {prop}={value}\n")
                else:
                    self.security_text.insert(tk.END, f"ℹ Bootloader property: {prop}={value}\n")
            
            fastboot_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.bootmode'], 
                                        capture_output=True, text=True, timeout=5)
            if fastboot_result.returncode == 0:
                bootloader_info['bootmode'] = fastboot_result.stdout.strip()
                self.security_text.insert(tk.END, f"ℹ Boot mode: {fastboot_result.stdout.strip()}\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Bootloader analysis error: {str(e)}\n")
        
        return bootloader_info

    def analyze_selinux_configuration(self):
        selinux_info = {}
        
        try:
            self.security_text.insert(tk.END, "\nAnalyzing SELinux configuration...\n")
            
            enforce_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getenforce'], 
                                        capture_output=True, text=True, timeout=5)
            
            if enforce_result.returncode == 0:
                selinux_status = enforce_result.stdout.strip()
                selinux_info['enforcement'] = selinux_status
                
                if selinux_status == 'Permissive':
                    self.security_text.insert(tk.END, f"⚠ SELinux: {selinux_status} (Security reduced)\n")
                elif selinux_status == 'Enforcing':
                    self.security_text.insert(tk.END, f"✓ SELinux: {selinux_status} (Security active)\n")
                else:
                    self.security_text.insert(tk.END, f"? SELinux: {selinux_status}\n")
            
            policy_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', '/sys/fs/selinux/policyvers'], 
                                        capture_output=True, text=True, timeout=5)
            if policy_result.returncode == 0:
                selinux_info['policy_version'] = policy_result.stdout.strip()
                self.security_text.insert(tk.END, f"ℹ SELinux policy version: {policy_result.stdout.strip()}\n")
            
            context_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'id', '-Z'], 
                                        capture_output=True, text=True, timeout=5)
            if context_result.returncode == 0:
                selinux_info['current_context'] = context_result.stdout.strip()
                self.security_text.insert(tk.END, f"ℹ Current SELinux context: {context_result.stdout.strip()}\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"SELinux analysis error: {str(e)}\n")
        
        return selinux_info

    def analyze_kernel_security(self):
        kernel_info = {}
        
        try:
            self.security_text.insert(tk.END, "\nAnalyzing kernel security features...\n")
            
            version_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'uname', '-r'], 
                                        capture_output=True, text=True, timeout=5)
            if version_result.returncode == 0:
                kernel_info['version'] = version_result.stdout.strip()
                self.security_text.insert(tk.END, f"ℹ Kernel version: {version_result.stdout.strip()}\n")
            
            security_features = [
                ('/proc/config.gz', 'Kernel config'),
                ('/sys/kernel/security', 'Security modules'),
                ('/proc/sys/kernel/kptr_restrict', 'Kernel pointer restriction'),
                ('/proc/sys/kernel/dmesg_restrict', 'dmesg restriction')
            ]
            
            for path, description in security_features:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '-la', path], 
                                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.security_text.insert(tk.END, f"✓ {description} available: {path}\n")
                else:
                    self.security_text.insert(tk.END, f"✗ {description} not accessible: {path}\n")
            
            aslr_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', '/proc/sys/kernel/randomize_va_space'], 
                                    capture_output=True, text=True, timeout=5)
            if aslr_result.returncode == 0:
                aslr_value = aslr_result.stdout.strip()
                kernel_info['aslr'] = aslr_value
                if aslr_value == '2':
                    self.security_text.insert(tk.END, f"✓ ASLR: Full randomization enabled\n")
                elif aslr_value == '1':
                    self.security_text.insert(tk.END, f"⚠ ASLR: Partial randomization\n")
                else:
                    self.security_text.insert(tk.END, f"⚠ ASLR: Disabled\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Kernel analysis error: {str(e)}\n")
        
        return kernel_info

    def analyze_partition_security(self):
        partition_info = {}
        
        try:
            self.security_text.insert(tk.END, "\nAnalyzing partition security...\n")
            
            mount_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'mount'], 
                                        capture_output=True, text=True, timeout=10)
            
            if mount_result.returncode == 0:
                critical_partitions = ['/system', '/vendor', '/data', '/boot']
                
                for partition in critical_partitions:
                    for line in mount_result.stdout.split('\n'):
                        if f' {partition} ' in line:
                            if 'ro,' in line:
                                self.security_text.insert(tk.END, f"✓ {partition}: Read-only mount\n")
                            elif 'rw,' in line:
                                self.security_text.insert(tk.END, f"⚠ {partition}: Read-write mount\n")
                            
                            if 'nodev' in line:
                                self.security_text.insert(tk.END, f"✓ {partition}: Device files disabled\n")
                            if 'nosuid' in line:
                                self.security_text.insert(tk.END, f"✓ {partition}: SUID disabled\n")
                            break
            
            verity_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.boot.veritymode'], 
                                        capture_output=True, text=True, timeout=5)
            if verity_result.returncode == 0:
                verity_status = verity_result.stdout.strip()
                partition_info['dm_verity'] = verity_status
                if verity_status == 'enforcing':
                    self.security_text.insert(tk.END, f"✓ dm-verity: Enforcing (tamper protection active)\n")
                else:
                    self.security_text.insert(tk.END, f"⚠ dm-verity: {verity_status}\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Partition analysis error: {str(e)}\n")
        
        return partition_info

    def analyze_system_binaries(self):
        binary_info = {}
        
        try:
            self.security_text.insert(tk.END, "\nAnalyzing system binaries...\n")
            
            critical_binaries = [
                '/system/bin/su',
                '/system/xbin/su', 
                '/system/bin/busybox',
                '/system/bin/sh',
                '/system/bin/mount'
            ]
            
            for binary in critical_binaries:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '-la', binary], 
                                    capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    permissions = result.stdout.split()[0] if result.stdout.split() else 'unknown'
                    
                    if 's' in permissions:
                        self.security_text.insert(tk.END, f"⚠ SUID binary found: {binary} ({permissions})\n")
                    else:
                        self.security_text.insert(tk.END, f"ℹ Binary found: {binary} ({permissions})\n")
                        
                    binary_info[binary] = {'exists': True, 'permissions': permissions}
                else:
                    binary_info[binary] = {'exists': False}
            
            suspicious_paths = ['/system/xbin/', '/system/bin/', '/vendor/bin/']
            
            for path in suspicious_paths:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'find', path, '-name', '*su*', '-o', '-name', '*root*'], 
                                    capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    self.security_text.insert(tk.END, f"⚠ Suspicious binaries in {path}:\n")
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            self.security_text.insert(tk.END, f"  {line}\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Binary analysis error: {str(e)}\n")
        
        return binary_info

    def analyze_system_services(self):
        service_info = {}
        
        try:
            self.security_text.insert(tk.END, "\nAnalyzing system services...\n")
            
            root_services = ['su', 'daemon', 'magisk', 'supersu']
            
            ps_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ps', '-A'], 
                                    capture_output=True, text=True, timeout=10)
            
            if ps_result.returncode == 0:
                for service in root_services:
                    service_found = False
                    for line in ps_result.stdout.split('\n'):
                        if service in line.lower():
                            self.security_text.insert(tk.END, f"⚠ Root-related service: {line.strip()}\n")
                            service_found = True
                            
                    service_info[service] = service_found
            
            init_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', '|', 'grep', 'init.svc'], 
                                    capture_output=True, text=True, timeout=10)
            
            if init_result.returncode == 0:
                suspicious_services = []
                for line in init_result.stdout.split('\n'):
                    if any(keyword in line.lower() for keyword in ['su', 'root', 'magisk', 'supersu']):
                        suspicious_services.append(line.strip())
                
                if suspicious_services:
                    self.security_text.insert(tk.END, f"⚠ Suspicious init services found:\n")
                    for service in suspicious_services:
                        self.security_text.insert(tk.END, f"  {service}\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Service analysis error: {str(e)}\n")
        
        return service_info

    def analyze_existing_root(self):
        try:
            self.security_text.insert(tk.END, "\nAnalyzing existing root implementation...\n")
            
            magisk_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'magisk', '--version'], 
                                        capture_output=True, text=True, timeout=5)
            
            if magisk_result.returncode == 0:
                self.security_text.insert(tk.END, f"✓ Magisk detected: {magisk_result.stdout.strip()}\n")
                
                modules_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '/data/adb/modules/'], 
                                            capture_output=True, text=True, timeout=5)
                if modules_result.returncode == 0:
                    modules = modules_result.stdout.strip().split('\n')
                    self.security_text.insert(tk.END, f"ℹ Magisk modules installed: {len(modules)}\n")
                    for module in modules[:10]:  
                        if module.strip():
                            self.security_text.insert(tk.END, f"  - {module}\n")
            
            supersu_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'su', '--version'], 
                                        capture_output=True, text=True, timeout=5)
            
            if supersu_result.returncode == 0:
                self.security_text.insert(tk.END, f"ℹ SuperSU detected: {supersu_result.stdout.strip()}\n")
            
            capabilities = [
                ('File system write access', 'mount -o rw,remount /system'),
                ('Process manipulation', 'kill -0 1'),
                ('Network raw sockets', 'ping -c 1 8.8.8.8'),
                ('Hardware access', 'ls /dev/'),
                ('Kernel module loading', 'lsmod')
            ]
            
            for capability, test_cmd in capabilities:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'su', '-c', test_cmd], 
                                    capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    self.security_text.insert(tk.END, f"✓ Root capability verified: {capability}\n")
                else:
                    self.security_text.insert(tk.END, f"✗ Root capability limited: {capability}\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Root analysis error: {str(e)}\n")

    def assess_rooting_vectors(self):
        try:
            self.security_text.insert(tk.END, "\nAssessing potential security vectors (educational analysis)...\n")
            
            vectors = {
                'Bootloader Unlock': self.assess_bootloader_vector,
                'Known CVE Analysis': self.assess_cve_vector,
                'ADB Escalation': self.assess_adb_vector,
                'Development Build': self.assess_dev_build_vector,
                'Third-party Tools': self.assess_tool_compatibility
            }
            
            for vector_name, assessment_func in vectors.items():
                self.security_text.insert(tk.END, f"\n--- {vector_name} Assessment ---\n")
                try:
                    assessment_func()
                except Exception as e:
                    self.security_text.insert(tk.END, f"Assessment error: {str(e)}\n")
            
            self.security_text.insert(tk.END, "\nNote: This analysis is for educational and security research purposes.\n")
            self.security_text.insert(tk.END, "Actual exploitation requires proper authorization and legal compliance.\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Vector assessment error: {str(e)}\n")

    def assess_bootloader_vector(self):
        try:
            manufacturer = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.product.manufacturer'], 
                                        capture_output=True, text=True, timeout=5).stdout.strip()
            model = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.product.model'], 
                                capture_output=True, text=True, timeout=5).stdout.strip()
            
            self.security_text.insert(tk.END, f"Device: {manufacturer} {model}\n")
            
            bootloader_policies = {
                'Google': 'Official unlock available via fastboot',
                'OnePlus': 'Official unlock available',
                'Xiaomi': 'Official unlock with waiting period',
                'Samsung': 'Limited official unlock, Knox triggered',
                'Huawei': 'Unlock support discontinued',
                'Sony': 'Official unlock available',
                'LG': 'Official unlock for some models'
            }
            
            policy = bootloader_policies.get(manufacturer, 'Unknown policy')
            self.security_text.insert(tk.END, f"Bootloader policy: {policy}\n")
            
            lock_state = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.boot.flash.locked'], 
                                    capture_output=True, text=True, timeout=5).stdout.strip()
            
            if lock_state == '0':
                self.security_text.insert(tk.END, "Status: Bootloader already unlocked\n")
            elif lock_state == '1':
                self.security_text.insert(tk.END, "Status: Bootloader locked\n")
            else:
                self.security_text.insert(tk.END, f"Status: Unknown ({lock_state})\n")
                
        except Exception as e:
            self.security_text.insert(tk.END, f"Bootloader assessment error: {str(e)}\n")

    def assess_cve_vector(self):
        try:
            android_version = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.build.version.release'], 
                                        capture_output=True, text=True, timeout=5).stdout.strip()
            security_patch = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.build.version.security_patch'], 
                                        capture_output=True, text=True, timeout=5).stdout.strip()
            sdk_version = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.build.version.sdk'], 
                                    capture_output=True, text=True, timeout=5).stdout.strip()
            
            self.security_text.insert(tk.END, f"Android version: {android_version} (SDK {sdk_version})\n")
            self.security_text.insert(tk.END, f"Security patch level: {security_patch}\n")
            
            cve_database = {
                'CVE-2019-2215': {'affects': 'Android < 2019-10', 'type': 'Kernel privilege escalation'},
                'CVE-2020-0041': {'affects': 'Android < 2020-03', 'type': 'Kernel use-after-free'},
                'CVE-2021-0920': {'affects': 'Android < 2021-11', 'type': 'Kernel socket vulnerability'},
                'CVE-2022-20186': {'affects': 'Android < 2022-06', 'type': 'Framework privilege escalation'}
            }
            
            self.security_text.insert(tk.END, "\nCVE Analysis (reference only):\n")
            
            try:
                if security_patch:
                    patch_year = int(security_patch.split('-')[0])
                    patch_month = int(security_patch.split('-')[1])
                    
                    for cve, info in cve_database.items():
                        affects_date = info['affects'].split('< ')[1]
                        affects_year = int(affects_date.split('-')[0])
                        affects_month = int(affects_date.split('-')[1])
                        
                        if patch_year < affects_year or (patch_year == affects_year and patch_month < affects_month):
                            self.security_text.insert(tk.END, f"⚠ Potentially affected: {cve} - {info['type']}\n")
                        else:
                            self.security_text.insert(tk.END, f"✓ Patched: {cve} - {info['type']}\n")
            except:
                self.security_text.insert(tk.END, "Unable to parse security patch date for CVE analysis\n")
                
        except Exception as e:
            self.security_text.insert(tk.END, f"CVE assessment error: {str(e)}\n")

    def assess_adb_vector(self):
        try:
            adb_secure = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.adb.secure'], 
                                    capture_output=True, text=True, timeout=5).stdout.strip()
            
            if adb_secure == '0':
                self.security_text.insert(tk.END, "⚠ ADB secure mode disabled\n")
            else:
                self.security_text.insert(tk.END, f"ℹ ADB secure mode: {adb_secure}\n")
            
            adb_root = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'service.adb.root'], 
                                    capture_output=True, text=True, timeout=5).stdout.stdout.strip()
            
            if adb_root == '1':
                self.security_text.insert(tk.END, "⚠ ADB running with root privileges\n")
            else:
                self.security_text.insert(tk.END, "ℹ ADB running in user mode\n")
            
            self.security_text.insert(tk.END, "Testing ADB capabilities:\n")
            
            system_write = subprocess.run(['adb', '-s', self.current_device, 'shell', 'touch', '/system/test_write'], 
                                        capture_output=True, text=True, timeout=5)
            
            if system_write.returncode == 0:
                self.security_text.insert(tk.END, "⚠ ADB can write to /system\n")
                subprocess.run(['adb', '-s', self.current_device, 'shell', 'rm', '/system/test_write'], 
                            capture_output=True, text=True, timeout=5)
            else:
                self.security_text.insert(tk.END, "✓ ADB cannot write to /system\n")
                
        except Exception as e:
            self.security_text.insert(tk.END, f"ADB assessment error: {str(e)}\n")

    def assess_dev_build_vector(self):
        try:
            build_type = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.build.type'], 
                                    capture_output=True, text=True, timeout=5).stdout.strip()
            build_tags = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.build.tags'], 
                                    capture_output=True, text=True, timeout=5).stdout.strip()
            debuggable = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.debuggable'], 
                                    capture_output=True, text=True, timeout=5).stdout.strip()
            
            self.security_text.insert(tk.END, f"Build type: {build_type}\n")
            self.security_text.insert(tk.END, f"Build tags: {build_tags}\n")
            self.security_text.insert(tk.END, f"Debuggable: {debuggable}\n")
            
            if build_type == 'eng':
                self.security_text.insert(tk.END, "⚠ Engineering build - reduced security\n")
            elif build_type == 'userdebug':
                self.security_text.insert(tk.END, "⚠ User-debug build - debug features enabled\n")
            elif build_type == 'user':
                self.security_text.insert(tk.END, "✓ User build - production security level\n")
            
            if debuggable == '1':
                self.security_text.insert(tk.END, "⚠ Debug mode enabled - applications debuggable\n")
            
            if 'test-keys' in build_tags:
                self.security_text.insert(tk.END, "⚠ Signed with test keys - custom ROM or debug build\n")
                
        except Exception as e:
            self.security_text.insert(tk.END, f"Development build assessment error: {str(e)}\n")

    def assess_tool_compatibility(self):
        try:
            manufacturer = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.product.manufacturer'], 
                                        capture_output=True, text=True, timeout=5).stdout.strip().lower()
            model = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.product.model'], 
                                capture_output=True, text=True, timeout=5).stdout.strip()
            android_version = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.build.version.release'], 
                                        capture_output=True, text=True, timeout=5).stdout.strip()
            
            self.security_text.insert(tk.END, "Tool compatibility assessment:\n")
            
            tools = {
                'Magisk': {
                    'requirements': 'Unlocked bootloader + custom recovery',
                    'compatibility': 'Universal (Android 5.0+)',
                    'method': 'Boot image patching'
                },
                'SuperSU': {
                    'requirements': 'Root access or custom recovery',
                    'compatibility': 'Legacy (Android 4.0-9.0)',
                    'method': 'System partition modification'
                },
                'KingRoot': {
                    'requirements': 'Exploit-based',
                    'compatibility': 'Limited (Android 4.0-6.0)',
                    'method': 'Automatic exploitation'
                },
                'TWRP': {
                    'requirements': 'Unlocked bootloader',
                    'compatibility': 'Device-specific',
                    'method': 'Custom recovery installation'
                }
            }
            
            for tool, info in tools.items():
                self.security_text.insert(tk.END, f"\n{tool}:\n")
                self.security_text.insert(tk.END, f"  Requirements: {info['requirements']}\n")
                self.security_text.insert(tk.END, f"  Compatibility: {info['compatibility']}\n")
                self.security_text.insert(tk.END, f"  Method: {info['method']}\n")
            
            manufacturer_notes = {
                'samsung': 'Knox security, may trigger warranty void',
                'huawei': 'Bootloader unlock support discontinued',
                'xiaomi': 'Bootloader unlock requires account verification',
                'google': 'Official fastboot unlock available',
                'oneplus': 'Generally root-friendly manufacturer'
            }
            
            note = manufacturer_notes.get(manufacturer, 'No specific notes')
            self.security_text.insert(tk.END, f"\nManufacturer note: {note}\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Tool compatibility assessment error: {str(e)}\n")

    def generate_security_recommendations(self, root_status, security_context, bootloader_status, selinux_status):
        try:
            self.security_text.insert(tk.END, "Security recommendations:\n")
            
            if root_status['has_root']:
                self.security_text.insert(tk.END, "\n⚠ DEVICE IS ROOTED - Security Implications:\n")
                self.security_text.insert(tk.END, "• Compromised security model\n")
                self.security_text.insert(tk.END, "• Potential for privilege escalation attacks\n")
                self.security_text.insert(tk.END, "• Banking/payment apps may not function\n")
                self.security_text.insert(tk.END, "• OTA updates may be blocked\n")
                
                if root_status['root_method'] == 'Magisk':
                    self.security_text.insert(tk.END, "• Consider Magisk Hide for app compatibility\n")
                
            else:
                self.security_text.insert(tk.END, "\n✓ NO ROOT DETECTED - Maintain Security:\n")
                self.security_text.insert(tk.END, "• Keep security patches updated\n")
                self.security_text.insert(tk.END, "• Avoid installing unknown APKs\n")
                self.security_text.insert(tk.END, "• Use official app stores only\n")
            
            if security_context.get('ro.debuggable') == '1':
                self.security_text.insert(tk.END, "\n⚠ DEBUG BUILD DETECTED:\n")
                self.security_text.insert(tk.END, "• Switch to production build for security\n")
                self.security_text.insert(tk.END, "• Disable developer options\n")
            
            if selinux_status.get('enforcement') == 'Permissive':
                self.security_text.insert(tk.END, "\n⚠ SELINUX IN PERMISSIVE MODE:\n")
                self.security_text.insert(tk.END, "• Security policies not enforced\n")
                self.security_text.insert(tk.END, "• Consider switching to enforcing mode\n")
            
            self.security_text.insert(tk.END, "\n📋 GENERAL SECURITY RECOMMENDATIONS:\n")
            self.security_text.insert(tk.END, "• Regular security patch updates\n")
            self.security_text.insert(tk.END, "• Enable screen lock with strong authentication\n")
            self.security_text.insert(tk.END, "• Review and limit app permissions\n")
            self.security_text.insert(tk.END, "• Enable Find My Device functionality\n")
            self.security_text.insert(tk.END, "• Use encryption for sensitive data\n")
            self.security_text.insert(tk.END, "• Regular backup of important data\n")
            
            self.security_text.insert(tk.END, "\n🔧 FOR SECURITY RESEARCHERS:\n")
            self.security_text.insert(tk.END, "• Use isolated testing environment\n")
            self.security_text.insert(tk.END, "• Document all modifications\n")
            self.security_text.insert(tk.END, "• Follow responsible disclosure practices\n")
            self.security_text.insert(tk.END, "• Maintain clean backup before testing\n")
            self.security_text.insert(tk.END, "• Use dedicated test devices\n")
            
        except Exception as e:
            self.security_text.insert(tk.END, f"Recommendation generation error: {str(e)}\n")
        
    def try_su_installation(self):
        try:
            su_locations = ['/system/xbin/su', '/system/bin/su', '/data/local/tmp/su']
            
            for location in su_locations:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'echo', '#!/system/bin/sh\nid', '>', location], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    chmod_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'chmod', '755', location], 
                                                capture_output=True, text=True, timeout=5)
                    
                    if chmod_result.returncode == 0:
                        test_result = subprocess.run(['adb', '-s', self.current_device, 'shell', location], 
                                                   capture_output=True, text=True, timeout=5)
                        
                        if test_result.returncode == 0 and 'uid=0' in test_result.stdout:
                            return True
                            
            return False
            
        except:
            return False
            
    def try_kernel_exploit(self):
        try:
            exploits = [
                'dirtycow',
                'towelroot',
                'kingroot'
            ]
            
            for exploit in exploits:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'echo', f'Attempting {exploit}'], 
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    check_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'id'], 
                                                capture_output=True, text=True, timeout=5)
                    
                    if check_result.returncode == 0 and 'uid=0' in check_result.stdout:
                        return True
                        
            return False
            
        except:
            return False
            
    def try_privilege_escalation(self):
        try:
            techniques = [
                'setuid manipulation',
                'capability exploitation',
                'mount namespace escape'
            ]
            
            for technique in techniques:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'whoami'], 
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0 and 'root' in result.stdout:
                    return True
                    
            return False
            
        except:
            return False
            
    def try_bootloader_unlock(self):
        try:
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.boot.flash.locked'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                locked_status = result.stdout.strip()
                if locked_status == '0':
                    self.security_text.insert(tk.END, "Bootloader is unlocked\n")
                    return True
                else:
                    self.security_text.insert(tk.END, "Bootloader is locked\n")
                    return False
                    
            return False
            
        except:
            return False
    
    def stop_all_monitoring(self):
        self.system_monitor_active = False
        self.screen_monitor_active = False
        self.keylogger_active = False
        self.network_monitor_active = False
        
    def create_device_backup(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        backup_path = filedialog.asksaveasfilename(
            defaultextension=".ab",
            filetypes=[("Android Backup", "*.ab"), ("All files", "*.*")]
        )
        
        if backup_path:
            def backup():
                try:
                    self.update_status("Creating device backup...")
                    result = subprocess.run(['adb', '-s', self.current_device, 'backup', '-all', '-f', backup_path], 
                                          capture_output=True, text=True, timeout=300)
                    
                    if result.returncode == 0:
                        messagebox.showinfo("Success", f"Device backup created: {backup_path}")
                    else:
                        raise Exception("Backup failed")
                        
                except Exception as e:
                    messagebox.showerror("Error", f"Backup error: {str(e)}")
                finally:
                    self.update_status("Ready")
                    
            threading.Thread(target=backup, daemon=True).start()
            
    def restore_device_backup(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        backup_path = filedialog.askopenfilename(
            filetypes=[("Android Backup", "*.ab"), ("All files", "*.*")]
        )
        
        if backup_path:
            result = messagebox.askyesno("Confirm Restore", 
                                       "This will restore the device from backup. "
                                       "This may overwrite existing data. Continue?")
            if result:
                def restore():
                    try:
                        self.update_status("Restoring device backup...")
                        result = subprocess.run(['adb', '-s', self.current_device, 'restore', backup_path], 
                                              capture_output=True, text=True, timeout=300)
                        
                        if result.returncode == 0:
                            messagebox.showinfo("Success", "Device backup restored")
                        else:
                            raise Exception("Restore failed")
                            
                    except Exception as e:
                        messagebox.showerror("Error", f"Restore error: {str(e)}")
                    finally:
                        self.update_status("Ready")
                        
                threading.Thread(target=restore, daemon=True).start()
    
    def export_all_data(self):
        export_dir = filedialog.askdirectory()
        if export_dir:
            try:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                
                device_info_file = os.path.join(export_dir, f"device_info_{timestamp}.json")
                device_data = self.tree_to_dict(self.device_info_tree)
                with open(device_info_file, 'w') as f:
                    json.dump(device_data, f, indent=2)
                
                scan_file = os.path.join(export_dir, f"scan_results_{timestamp}.txt")
                with open(scan_file, 'w') as f:
                    f.write(self.scan_results.get(1.0, tk.END))
                
                log_file = os.path.join(export_dir, f"system_logs_{timestamp}.log")
                with open(log_file, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                
                if self.keylog_text.get(1.0, tk.END).strip():
                    keylog_file = os.path.join(export_dir, f"keylog_{timestamp}.log")
                    with open(keylog_file, 'w') as f:
                        f.write(self.keylog_text.get(1.0, tk.END))
                
                messagebox.showinfo("Success", f"All data exported to {export_dir}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def import_session(self):
        session_file = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if session_file:
            try:
                with open(session_file, 'r') as f:
                    session_data = json.load(f)
                    
                messagebox.showinfo("Success", "Session data imported")
                
            except Exception as e:
                messagebox.showerror("Error", f"Import failed: {str(e)}")
    
    def filter_logs(self):
        filter_text = tk.simpledialog.askstring("Filter Logs", "Enter filter text:")
        if filter_text:
            try:
                all_logs = self.log_text.get(1.0, tk.END)
                filtered_lines = [line for line in all_logs.split('\n') if filter_text.lower() in line.lower()]
                
                filter_window = tk.Toplevel(self.root)
                filter_window.title(f"Filtered Logs - {filter_text}")
                filter_window.geometry("800x600")
                filter_window.configure(bg='#1a1a1a')
                
                filtered_text = scrolledtext.ScrolledText(filter_window, bg='#2a2a2a', fg='#ffffff')
                filtered_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                for line in filtered_lines:
                    filtered_text.insert(tk.END, line + '\n')
                    
            except Exception as e:
                messagebox.showerror("Error", f"Filter failed: {str(e)}")
    
    def privilege_escalation(self):
        self.attempt_root_device()
        
    def open_security_bypass(self):
        bypass_window = tk.Toplevel(self.root)
        bypass_window.title("Security Bypass Suite")
        bypass_window.geometry("600x400")
        bypass_window.configure(bg='#1a1a1a')
        
        ttk.Label(bypass_window, text="Security Bypass Suite", style='Dark.TLabel', font=('Arial', 14, 'bold')).pack(pady=10)
        
        bypass_text = scrolledtext.ScrolledText(bypass_window, bg='#2a2a2a', fg='#ffffff')
        bypass_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        bypass_text.insert(tk.END, "Security Bypass Suite - Available Methods\n")
        bypass_text.insert(tk.END, "=" * 50 + "\n\n")
        bypass_text.insert(tk.END, "1. SELinux Enforcement Bypass\n")
        bypass_text.insert(tk.END, "2. Application Signature Verification Bypass\n")
        bypass_text.insert(tk.END, "3. Certificate Pinning Bypass\n")
        bypass_text.insert(tk.END, "4. Root Detection Bypass\n")
        bypass_text.insert(tk.END, "5. Debug Detection Bypass\n")
        bypass_text.insert(tk.END, "6. Anti-Emulation Bypass\n")
        bypass_text.insert(tk.END, "7. Tamper Detection Bypass\n")
        bypass_text.insert(tk.END, "8. Dynamic Analysis Evasion\n")
        
    def open_vulnerability_scanner(self):
        self.vulnerability_scan()
        
    def open_memory_analyzer(self):
        self.create_memory_dump()
        
    def open_network_analyzer(self):
        self.start_network_monitor()
        
    def open_performance_monitor(self):
        self.show_realtime_stats()
    
    def start_system_monitor(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.system_monitor_active = True
        self.update_status("Starting system monitor...")
        
        def monitor_system():
            self.system_tree.delete(*self.system_tree.get_children())
            
            try:
                storage_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'df', '-h'], 
                                              capture_output=True, text=True, timeout=10)
                
                storage_root = self.system_tree.insert('', 'end', text='Storage', values=('', 'Category', 'Active'))
                
                for line in storage_result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        filesystem = parts[0]
                        size = parts[1]
                        used = parts[2]
                        available = parts[3]
                        use_percent = parts[4]
                        mountpoint = parts[5]
                        
                        self.system_tree.insert(storage_root, 'end', 
                                              text=f"{mountpoint} ({filesystem})",
                                              values=(f"{used}/{size}", 'Filesystem', use_percent))
                
                process_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ps'], 
                                              capture_output=True, text=True, timeout=10)
                
                process_root = self.system_tree.insert('', 'end', text='Processes', values=('', 'Category', 'Active'))
                
                process_count = 0
                for line in process_result.stdout.strip().split('\n')[1:]:
                    if process_count >= 20:
                        break
                    parts = line.split()
                    if len(parts) >= 9:
                        pid = parts[1]
                        process_name = parts[8]
                        
                        self.system_tree.insert(process_root, 'end', 
                                              text=f"{process_name} (PID: {pid})",
                                              values=('', 'Process', 'Running'))
                        process_count += 1
                
                packages_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'pm', 'list', 'packages'], 
                                                capture_output=True, text=True, timeout=15)
                
                packages_root = self.system_tree.insert('', 'end', text='Installed Packages', values=('', 'Category', 'Active'))
                
                package_count = 0
                for line in packages_result.stdout.strip().split('\n'):
                    if package_count >= 50:
                        break
                    if line.startswith('package:'):
                        package_name = line.replace('package:', '').strip()
                        self.system_tree.insert(packages_root, 'end', 
                                              text=package_name,
                                              values=('', 'Package', 'Installed'))
                        package_count += 1
                
                self.system_tree.item(storage_root, open=True)
                self.system_tree.item(process_root, open=True)
                self.system_tree.item(packages_root, open=True)
                
                self.update_status("System monitor completed")
                
            except Exception as e:
                self.log_message(f"System monitor error: {str(e)}")
                self.update_status("System monitor failed")
                
        threading.Thread(target=monitor_system, daemon=True).start()
        
    def stop_system_monitor(self):
        self.system_monitor_active = False
        self.update_status("System monitor stopped")
        
    def export_system_tree(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                data = self.tree_to_dict(self.system_tree)
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                messagebox.showinfo("Success", f"System tree exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
                
    def tree_to_dict(self, tree):
        def item_to_dict(item):
            children = tree.get_children(item)
            result = {
                'text': tree.item(item, 'text'),
                'values': tree.item(item, 'values'),
                'children': [item_to_dict(child) for child in children]
            }
            return result
            
        root_items = tree.get_children('')
        return [item_to_dict(item) for item in root_items]
        
    def scan_security(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.security_text.delete(1.0, tk.END)
        self.security_text.insert(tk.END, "Starting security scan...\n\n")
        
        def security_scan():
            try:
                self.security_text.insert(tk.END, "Checking SELinux status...\n")
                selinux_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getenforce'], 
                                              capture_output=True, text=True, timeout=10)
                self.security_text.insert(tk.END, f"SELinux: {selinux_result.stdout.strip()}\n\n")
                
                self.security_text.insert(tk.END, "Checking root access...\n")
                root_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'su', '-c', 'id'], 
                                           capture_output=True, text=True, timeout=10)
                if root_result.returncode == 0:
                    self.security_text.insert(tk.END, f"Root access: Available\n{root_result.stdout}\n\n")
                else:
                    self.security_text.insert(tk.END, "Root access: Not available\n\n")
                
                self.security_text.insert(tk.END, "Checking security patch level...\n")
                patch_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.build.version.security_patch'], 
                                            capture_output=True, text=True, timeout=5)
                self.security_text.insert(tk.END, f"Security patch: {patch_result.stdout.strip()}\n\n")
                
                self.security_text.insert(tk.END, "Checking dm-verity status...\n")
                verity_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.boot.veritymode'], 
                                             capture_output=True, text=True, timeout=5)
                self.security_text.insert(tk.END, f"Dm-verity: {verity_result.stdout.strip()}\n\n")
                
                self.security_text.insert(tk.END, "Checking bootloader status...\n")
                bootloader_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.boot.verifiedbootstate'], 
                                                  capture_output=True, text=True, timeout=5)
                self.security_text.insert(tk.END, f"Verified boot: {bootloader_result.stdout.strip()}\n\n")
                
                self.security_text.insert(tk.END, "Security scan completed.\n")
                
            except Exception as e:
                self.security_text.insert(tk.END, f"Security scan error: {str(e)}\n")
                
        threading.Thread(target=security_scan, daemon=True).start()
        
    def bypass_selinux(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        result = messagebox.askyesno("Warning", 
                                   "This will attempt to modify SELinux settings. This could potentially damage your device. Continue?")
        if not result:
            return
            
        def bypass():
            try:
                self.security_text.insert(tk.END, "\nAttempting SELinux bypass...\n")
                
                commands = [
                    'su -c "setenforce 0"',
                    'su -c "echo 0 > /sys/fs/selinux/enforce"',
                    'su -c "mount -o rw,remount /system"'
                ]
                
                for cmd in commands:
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', cmd], 
                                          capture_output=True, text=True, timeout=10)
                    self.security_text.insert(tk.END, f"Command: {cmd}\n")
                    self.security_text.insert(tk.END, f"Result: {result.returncode}\n")
                    if result.stdout:
                        self.security_text.insert(tk.END, f"Output: {result.stdout}\n")
                    self.security_text.insert(tk.END, "\n")
                
                self.security_text.insert(tk.END, "SELinux bypass attempt completed.\n")
                
            except Exception as e:
                self.security_text.insert(tk.END, f"SELinux bypass error: {str(e)}\n")
                
        threading.Thread(target=bypass, daemon=True).start()
        
    def modify_permissions(self):
        permission_window = tk.Toplevel(self.root)
        permission_window.title("Permission Manager")
        permission_window.geometry("600x400")
        permission_window.configure(bg='#1a1a1a')
        
        ttk.Label(permission_window, text="Permission Modification", style='Dark.TLabel', 
                 font=('Arial', 12, 'bold')).pack(pady=10)
        
        perm_frame = ttk.Frame(permission_window, style='Dark.TFrame')
        perm_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(perm_frame, text="Package:", style='Dark.TLabel').grid(row=0, column=0, sticky=tk.W, pady=5)
        package_entry = ttk.Entry(perm_frame, style='Dark.TEntry', width=40)
        package_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        ttk.Label(perm_frame, text="Permission:", style='Dark.TLabel').grid(row=1, column=0, sticky=tk.W, pady=5)
        permission_entry = ttk.Entry(perm_frame, style='Dark.TEntry', width=40)
        permission_entry.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        button_frame = ttk.Frame(perm_frame, style='Dark.TFrame')
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        def grant_permission():
            package = package_entry.get()
            permission = permission_entry.get()
            if package and permission:
                try:
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'pm', 'grant', package, permission], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        messagebox.showinfo("Success", f"Permission granted to {package}")
                    else:
                        messagebox.showerror("Error", f"Failed to grant permission: {result.stderr}")
                except Exception as e:
                    messagebox.showerror("Error", f"Permission error: {str(e)}")
                    
        def revoke_permission():
            package = package_entry.get()
            permission = permission_entry.get()
            if package and permission:
                try:
                    result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'pm', 'revoke', package, permission], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        messagebox.showinfo("Success", f"Permission revoked from {package}")
                    else:
                        messagebox.showerror("Error", f"Failed to revoke permission: {result.stderr}")
                except Exception as e:
                    messagebox.showerror("Error", f"Permission error: {str(e)}")
        
        ttk.Button(button_frame, text="Grant Permission", style='Dark.TButton', 
                  command=grant_permission).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Revoke Permission", style='Dark.TButton', 
                  command=revoke_permission).pack(side=tk.LEFT, padx=5)
        
    def start_reverse_engineering(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.reverse_engineering_active = True
        self.re_progress.start()
        self.re_text.delete(1.0, tk.END)
        self.re_text.insert(tk.END, "Starting automated reverse engineering analysis...\n\n")
        
        def reverse_engineer():
            try:
                stages = [
                    ("Binary Analysis", self.analyze_binaries),
                    ("Memory Mapping", self.analyze_memory),
                    ("System Call Tracing", self.trace_syscalls),
                    ("NFC Stack Analysis", self.analyze_nfc_stack),
                    ("Security Implementation Scan", self.scan_security_implementations),
                    ("Firmware Extraction", self.extract_firmware),
                    ("Vulnerability Assessment", self.assess_vulnerabilities)
                ]
                
                total_stages = len(stages)
                for i, (stage_name, stage_func) in enumerate(stages):
                    if not self.reverse_engineering_active:
                        break
                        
                    self.re_text.insert(tk.END, f"Stage {i+1}/{total_stages}: {stage_name}\n")
                    self.re_text.insert(tk.END, "=" * 50 + "\n")
                    
                    stage_func()
                    
                    self.re_text.insert(tk.END, f"\nStage {i+1} completed.\n\n")
                    time.sleep(1)
                
                if self.reverse_engineering_active:
                    self.re_text.insert(tk.END, "Reverse engineering analysis completed successfully.\n")
                else:
                    self.re_text.insert(tk.END, "Reverse engineering analysis stopped by user.\n")
                    
            except Exception as e:
                self.re_text.insert(tk.END, f"Reverse engineering error: {str(e)}\n")
            finally:
                self.re_progress.stop()
                self.reverse_engineering_active = False
                
        threading.Thread(target=reverse_engineer, daemon=True).start()
        
    def stop_reverse_engineering(self):
        self.reverse_engineering_active = False
        self.re_progress.stop()
        self.re_text.insert(tk.END, "\nStopping reverse engineering analysis...\n")
        
    def analyze_binaries(self):
        self.re_text.insert(tk.END, "Analyzing system binaries...\n")
        
        binaries_to_analyze = [
            '/system/bin/nfc',
            '/system/lib/libnfc-nci.so',
            '/system/lib/hw/nfc_nci.*.so',
            '/vendor/lib/libpn*.so',
            '/system/bin/se_nq_extn_client'
        ]
        
        for binary in binaries_to_analyze:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '-la', binary], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.re_text.insert(tk.END, f"Found: {binary}\n")
                    
                    file_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'file', binary], 
                                                capture_output=True, text=True, timeout=5)
                    if file_result.returncode == 0:
                        self.re_text.insert(tk.END, f"  Type: {file_result.stdout.strip()}\n")
                        
                    size_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'stat', '-c', '%s', binary], 
                                                capture_output=True, text=True, timeout=5)
                    if size_result.returncode == 0:
                        size = int(size_result.stdout.strip())
                        self.re_text.insert(tk.END, f"  Size: {size} bytes\n")
                        
            except Exception as e:
                self.re_text.insert(tk.END, f"Error analyzing {binary}: {str(e)}\n")
                
    def analyze_memory(self):
        self.re_text.insert(tk.END, "Analyzing memory mappings...\n")
        
        try:
            maps_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', '/proc/1/maps'], 
                                       capture_output=True, text=True, timeout=10)
            if maps_result.returncode == 0:
                lines = maps_result.stdout.strip().split('\n')
                nfc_related = [line for line in lines if 'nfc' in line.lower()]
                
                self.re_text.insert(tk.END, f"Found {len(nfc_related)} NFC-related memory mappings:\n")
                for mapping in nfc_related[:10]:
                    self.re_text.insert(tk.END, f"  {mapping}\n")
                    
        except Exception as e:
            self.re_text.insert(tk.END, f"Memory analysis error: {str(e)}\n")
            
    def trace_syscalls(self):
        self.re_text.insert(tk.END, "Tracing system calls...\n")
        
        try:
            strace_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ps', '|', 'grep', 'nfc'], 
                                         capture_output=True, text=True, timeout=10)
            if strace_result.returncode == 0:
                self.re_text.insert(tk.END, "NFC processes found:\n")
                for line in strace_result.stdout.strip().split('\n'):
                    if line.strip():
                        self.re_text.insert(tk.END, f"  {line}\n")
            else:
                self.re_text.insert(tk.END, "No NFC processes currently running.\n")
                
        except Exception as e:
            self.re_text.insert(tk.END, f"Syscall tracing error: {str(e)}\n")
            
    def analyze_nfc_stack(self):
        self.re_text.insert(tk.END, "Analyzing NFC stack implementation...\n")
        
        nfc_components = [
            '/sys/class/nfc',
            '/dev/nfc*',
            '/proc/nfc',
            '/sys/kernel/debug/nfc',
            '/data/vendor/nfc'
        ]
        
        for component in nfc_components:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ls', '-la', component], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.re_text.insert(tk.END, f"NFC component found: {component}\n")
                    self.re_text.insert(tk.END, f"  {result.stdout.strip()}\n")
                    
            except Exception as e:
                self.re_text.insert(tk.END, f"Error checking {component}: {str(e)}\n")
                
    def scan_security_implementations(self):
        self.re_text.insert(tk.END, "Scanning security implementations...\n")
        
        security_checks = [
            ('SELinux policies', 'ls /sepolicy'),
            ('Security contexts', 'ls -Z /system/bin/nfc*'),
            ('Capabilities', 'getcap /system/bin/nfc*'),
            ('Permissions', 'ls -la /dev/nfc*'),
            ('Group memberships', 'groups nfc')
        ]
        
        for check_name, command in security_checks:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                      capture_output=True, text=True, timeout=5)
                self.re_text.insert(tk.END, f"{check_name}:\n")
                if result.returncode == 0:
                    self.re_text.insert(tk.END, f"  {result.stdout.strip()}\n")
                else:
                    self.re_text.insert(tk.END, f"  Not accessible or not found\n")
                    
            except Exception as e:
                self.re_text.insert(tk.END, f"  Error: {str(e)}\n")
                
    def extract_firmware(self):
        self.re_text.insert(tk.END, "Attempting firmware extraction...\n")
        
        firmware_locations = [
            '/vendor/firmware/nfc*',
            '/system/etc/firmware/nfc*',
            '/firmware/image/nfc*',
            '/data/vendor/firmware/nfc*'
        ]
        
        for location in firmware_locations:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'find', location.split('*')[0], '-name', '*nfc*'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    self.re_text.insert(tk.END, f"Firmware files found in {location}:\n")
                    for file in result.stdout.strip().split('\n'):
                        if file.strip():
                            self.re_text.insert(tk.END, f"  {file}\n")
                            
            except Exception as e:
                self.re_text.insert(tk.END, f"Error scanning {location}: {str(e)}\n")
                
    def assess_vulnerabilities(self):
        self.re_text.insert(tk.END, "Assessing potential vulnerabilities...\n")
        
        vulnerability_checks = [
            ('Writable system directories', 'find /system -type d -perm -002'),
            ('SUID binaries', 'find /system -perm -4000'),
            ('World-writable files', 'find /data -perm -002 -type f'),
            ('Unprotected sockets', 'netstat -an | grep LISTEN'),
            ('Debug interfaces', 'ls /sys/kernel/debug/')
        ]
        
        for check_name, command in vulnerability_checks:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                      capture_output=True, text=True, timeout=15)
                self.re_text.insert(tk.END, f"{check_name}:\n")
                if result.returncode == 0:
                    output_lines = result.stdout.strip().split('\n')
                    lines = output_lines[:5]
                    for line in lines:
                        if line.strip():
                            self.re_text.insert(tk.END, f"  {line}\n")
                    if len(output_lines) > 5:
                        remaining_count = len(output_lines) - 5
                        self.re_text.insert(tk.END, f"  ... and {remaining_count} more\n")
                else:
                    self.re_text.insert(tk.END, f"  No results or access denied\n")
                    
            except Exception as e:
                self.re_text.insert(tk.END, f"  Error: {str(e)}\n")
                
    def generate_re_report(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                content = self.re_text.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(f"POOPIEFART62 Reverse Engineering Report\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Device: {self.current_device}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(content)
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")
                
    def detect_chipset(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.firmware_text.delete(1.0, tk.END)
        self.firmware_text.insert(tk.END, "Detecting NFC chipset...\n\n")
        
        def detect():
            try:
                chip_id_locations = [
                    '/sys/class/nfc/nfc*/device/chip_id',
                    '/proc/nfc/chip_id',
                    '/sys/kernel/debug/nfc/chip_info'
                ]
                
                chipset_detected = False
                for location in chip_id_locations:
                    try:
                        result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', location], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            chip_id = result.stdout.strip()
                            self.firmware_text.insert(tk.END, f"Chip ID found at {location}: {chip_id}\n")
                            
                            chipset_mapping = {
                                '0x544C': 'NXP PN544',
                                '0x547C': 'NXP PN547',
                                '0x548C': 'NXP PN548',
                                '0x2079': 'Broadcom BCM20791',
                                '0x2080': 'Broadcom BCM20795',
                                '0x6595': 'Qualcomm QCA6595'
                            }
                            
                            chipset = chipset_mapping.get(chip_id, f"Unknown chipset (ID: {chip_id})")
                            self.chipset_label.config(text=chipset)
                            self.firmware_text.insert(tk.END, f"Detected chipset: {chipset}\n\n")
                            chipset_detected = True
                            break
                            
                    except:
                        continue
                
                if not chipset_detected:
                    hardware_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', 'ro.hardware'], 
                                                   capture_output=True, text=True, timeout=5)
                    if hardware_result.returncode == 0:
                        hardware = hardware_result.stdout.strip().lower()
                        if 'pn5' in hardware:
                            chipset = 'NXP PN5XX Series'
                        elif 'bcm' in hardware:
                            chipset = 'Broadcom BCM Series'
                        elif 'qca' in hardware:
                            chipset = 'Qualcomm QCA Series'
                        else:
                            chipset = f'Unknown ({hardware})'
                            
                        self.chipset_label.config(text=chipset)
                        self.firmware_text.insert(tk.END, f"Chipset inferred from hardware: {chipset}\n\n")
                
                firmware_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'cat', '/sys/class/nfc/nfc*/device/firmware_version'], 
                                               capture_output=True, text=True, timeout=5)
                if firmware_result.returncode == 0:
                    firmware_version = firmware_result.stdout.strip()
                    self.firmware_label.config(text=firmware_version)
                    self.firmware_text.insert(tk.END, f"Firmware version: {firmware_version}\n")
                else:
                    self.firmware_label.config(text="Unknown")
                    self.firmware_text.insert(tk.END, "Firmware version: Unable to determine\n")
                
                self.firmware_text.insert(tk.END, "\nChipset detection completed.\n")
                
            except Exception as e:
                self.firmware_text.insert(tk.END, f"Chipset detection error: {str(e)}\n")
                
        threading.Thread(target=detect, daemon=True).start()
        
    def backup_firmware(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        
        if filename:
            def backup():
                try:
                    self.firmware_text.insert(tk.END, f"\nBacking up firmware to {filename}...\n")
                    
                    firmware_partitions = [
                        '/dev/block/bootdevice/by-name/nfc',
                        '/dev/block/platform/*/by-name/nfc_fw',
                        '/vendor/firmware/nfc.bin'
                    ]
                    
                    backup_successful = False
                    for partition in firmware_partitions:
                        try:
                            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'su', '-c', f'dd if={partition} bs=1024'], 
                                                  capture_output=True, timeout=30)
                            if result.returncode == 0 and len(result.stdout) > 0:
                                with open(filename, 'wb') as f:
                                    f.write(result.stdout)
                                self.firmware_text.insert(tk.END, f"Firmware backup successful from {partition}\n")
                                self.firmware_text.insert(tk.END, f"Backup size: {len(result.stdout)} bytes\n")
                                backup_successful = True
                                break
                        except:
                            continue
                    
                    if not backup_successful:
                        self.firmware_text.insert(tk.END, "Unable to backup firmware - partition not found or access denied\n")
                        
                except Exception as e:
                    self.firmware_text.insert(tk.END, f"Firmware backup error: {str(e)}\n")
                    
            threading.Thread(target=backup, daemon=True).start()
            
    def flash_firmware(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        result = messagebox.askyesno("Critical Warning", 
                                   "Flashing firmware can permanently damage your device and void warranties. "
                                   "This operation requires root access and may brick your device. "
                                   "Do you want to continue?")
        if not result:
            return
            
        filename = filedialog.askopenfilename(
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        
        if filename:
            def flash():
                try:
                    self.firmware_text.insert(tk.END, f"\nFlashing firmware from {filename}...\n")
                    
                    with open(filename, 'rb') as f:
                        firmware_data = f.read()
                    
                    self.firmware_text.insert(tk.END, f"Firmware size: {len(firmware_data)} bytes\n")
                    
                    checksum = hashlib.md5(firmware_data).hexdigest()
                    self.firmware_text.insert(tk.END, f"Firmware checksum: {checksum}\n")
                    
                    temp_path = '/data/local/tmp/custom_firmware.bin'
                    
                    upload_result = subprocess.run(['adb', '-s', self.current_device, 'push', filename, temp_path], 
                                                 capture_output=True, text=True, timeout=60)
                    if upload_result.returncode != 0:
                        raise Exception(f"Upload failed: {upload_result.stderr}")
                    
                    self.firmware_text.insert(tk.END, "Firmware uploaded to device\n")
                    
                    flash_commands = [
                        f'su -c "chmod 644 {temp_path}"',
                        f'su -c "dd if={temp_path} of=/dev/block/bootdevice/by-name/nfc bs=1024"',
                        'su -c "sync"',
                        f'su -c "rm {temp_path}"'
                    ]
                    
                    for cmd in flash_commands:
                        result = subprocess.run(['adb', '-s', self.current_device, 'shell', cmd], 
                                              capture_output=True, text=True, timeout=30)
                        self.firmware_text.insert(tk.END, f"Command: {cmd}\n")
                        self.firmware_text.insert(tk.END, f"Result: {result.returncode}\n")
                        if result.stdout:
                            self.firmware_text.insert(tk.END, f"Output: {result.stdout}\n")
                        if result.stderr:
                            self.firmware_text.insert(tk.END, f"Error: {result.stderr}\n")
                        self.firmware_text.insert(tk.END, "\n")
                    
                    self.firmware_text.insert(tk.END, "Firmware flashing completed. Reboot device to activate.\n")
                    
                except Exception as e:
                    self.firmware_text.insert(tk.END, f"Firmware flashing error: {str(e)}\n")
                    
            threading.Thread(target=flash, daemon=True).start()
            
    def browse_apk(self):
        filename = filedialog.askopenfilename(
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
        )
        if filename:
            self.apk_path_var.set(filename)
            
    def install_apk(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        apk_path = self.apk_path_var.get()
        if not apk_path:
            messagebox.showwarning("Warning", "No APK file selected")
            return
            
        def install():
            try:
                self.update_status("Installing APK...")
                result = subprocess.run(['adb', '-s', self.current_device, 'install', '-r', apk_path], 
                                      capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0:
                    messagebox.showinfo("Success", "APK installed successfully")
                    self.list_packages()
                else:
                    messagebox.showerror("Error", f"Installation failed: {result.stderr}")
                    
            except Exception as e:
                messagebox.showerror("Error", f"Installation error: {str(e)}")
            finally:
                self.update_status("Ready")
                
        threading.Thread(target=install, daemon=True).start()
        
    def uninstall_package(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        selection = self.package_list.selection()
        if not selection:
            messagebox.showwarning("Warning", "No package selected")
            return
            
        package_name = self.package_list.item(selection[0])['values'][0]
        
        result = messagebox.askyesno("Confirm", f"Uninstall package {package_name}?")
        if result:
            def uninstall():
                try:
                    self.update_status("Uninstalling package...")
                    result = subprocess.run(['adb', '-s', self.current_device, 'uninstall', package_name], 
                                          capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        messagebox.showinfo("Success", f"Package {package_name} uninstalled")
                        self.list_packages()
                    else:
                        messagebox.showerror("Error", f"Uninstall failed: {result.stderr}")
                        
                except Exception as e:
                    messagebox.showerror("Error", f"Uninstall error: {str(e)}")
                finally:
                    self.update_status("Ready")
                    
            threading.Thread(target=uninstall, daemon=True).start()
            
    def list_packages(self):
        if not self.current_device:
            return
            
        def list_apps():
            try:
                self.package_list.delete(*self.package_list.get_children())
                
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'pm', 'list', 'packages', '-3'], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.startswith('package:'):
                            package_name = line.replace('package:', '').strip()
                            
                            # Get package info
                            version_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'dumpsys', 'package', package_name, '|', 'grep', 'versionName'], 
                                                          capture_output=True, text=True, timeout=5)
                            version = "Unknown"
                            if version_result.returncode == 0:
                                for version_line in version_result.stdout.split('\n'):
                                    if 'versionName=' in version_line:
                                        version = version_line.split('versionName=')[1].strip()
                                        break
                            
                            size_result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'pm', 'path', package_name], 
                                                        capture_output=True, text=True, timeout=5)
                            size = "Unknown"
                            if size_result.returncode == 0:
                                apk_path = size_result.stdout.strip().replace('package:', '')
                                size_check = subprocess.run(['adb', '-s', self.current_device, 'shell', 'stat', '-c', '%s', apk_path], 
                                                          capture_output=True, text=True, timeout=5)
                                if size_check.returncode == 0:
                                    size_bytes = int(size_check.stdout.strip())
                                    size = f"{size_bytes // 1024}KB"
                            
                            self.package_list.insert('', 'end', values=(package_name, version, "Installed", size))
                            
            except Exception as e:
                self.log_message(f"Package listing error: {str(e)}")
                
        threading.Thread(target=list_apps, daemon=True).start()
        
    def full_system_scan(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        self.scan_results.delete(1.0, tk.END)
        self.scan_progress['value'] = 0
        
        def scan():
            try:
                scan_stages = [
                    ("System Information", self.scan_system_info),
                    ("Hardware Analysis", self.scan_hardware),
                    ("Security Assessment", self.scan_security_full),
                    ("Network Configuration", self.scan_network),
                    ("Storage Analysis", self.scan_storage),
                    ("Process Analysis", self.scan_processes),
                    ("NFC Subsystem", self.scan_nfc_subsystem)
                ]
                
                total_stages = len(scan_stages)
                for i, (stage_name, stage_func) in enumerate(scan_stages):
                    self.scan_results.insert(tk.END, f"\n{'='*50}\n")
                    self.scan_results.insert(tk.END, f"Stage {i+1}/{total_stages}: {stage_name}\n")
                    self.scan_results.insert(tk.END, f"{'='*50}\n")
                    
                    stage_func()
                    
                    progress = ((i + 1) / total_stages) * 100
                    self.scan_progress['value'] = progress
                    
                self.scan_results.insert(tk.END, f"\n{'='*50}\n")
                self.scan_results.insert(tk.END, "Full system scan completed.\n")
                
            except Exception as e:
                self.scan_results.insert(tk.END, f"System scan error: {str(e)}\n")
                
        threading.Thread(target=scan, daemon=True).start()
        
    def scan_system_info(self):
        system_props = [
            ('Android Version', 'ro.build.version.release'),
            ('Security Patch', 'ro.build.version.security_patch'),
            ('Kernel Version', 'sys.kernel.version'),
            ('CPU Architecture', 'ro.product.cpu.abi'),
            ('Total RAM', 'ro.config.total_ram'),
            ('Build Type', 'ro.build.type'),
            ('Bootloader', 'ro.bootloader'),
            ('Baseband', 'gsm.version.baseband')
        ]
        
        for prop_name, prop_key in system_props:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', prop_key], 
                                      capture_output=True, text=True, timeout=5)
                value = result.stdout.strip() if result.returncode == 0 else "Unknown"
                self.scan_results.insert(tk.END, f"{prop_name}: {value}\n")
            except:
                self.scan_results.insert(tk.END, f"{prop_name}: Error\n")
                
    def scan_hardware(self):
        hardware_checks = [
            ('CPU Info', 'cat /proc/cpuinfo | head -20'),
            ('Memory Info', 'cat /proc/meminfo | head -10'),
            ('Hardware Features', 'pm list features | grep hardware'),
            ('Block Devices', 'ls -la /dev/block/ | head -10'),
            ('NFC Hardware', 'ls -la /dev/nfc* /sys/class/nfc/')
        ]
        
        for check_name, command in hardware_checks:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                      capture_output=True, text=True, timeout=10)
                self.scan_results.insert(tk.END, f"\n{check_name}:\n")
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[:10]
                    for line in lines:
                        self.scan_results.insert(tk.END, f"  {line}\n")
                else:
                    self.scan_results.insert(tk.END, "  Not accessible\n")
            except:
                self.scan_results.insert(tk.END, f"\n{check_name}: Error\n")
                
    def scan_security_full(self):
        security_checks = [
            ('SELinux Status', 'getenforce'),
            ('Root Access', 'su -c id'),
            ('Encryption Status', 'getprop ro.crypto.state'),
            ('Verified Boot', 'getprop ro.boot.verifiedbootstate'),
            ('Security Services', 'ps | grep security'),
            ('Permission Policies', 'ls /sepolicy*')
        ]
        
        for check_name, command in security_checks:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                      capture_output=True, text=True, timeout=5)
                self.scan_results.insert(tk.END, f"\n{check_name}:\n")
                if result.returncode == 0:
                    self.scan_results.insert(tk.END, f"  {result.stdout.strip()}\n")
                else:
                    self.scan_results.insert(tk.END, "  Access denied or not found\n")
            except:
                self.scan_results.insert(tk.END, f"\n{check_name}: Error\n")
                
    def scan_network(self):
        network_checks = [
            ('Network Interfaces', 'ip addr show'),
            ('Routing Table', 'ip route'),
            ('DNS Configuration', 'getprop | grep dns'),
            ('WiFi State', 'dumpsys wifi | grep "Wi-Fi is"'),
            ('Bluetooth State', 'dumpsys bluetooth_manager | grep enabled')
        ]
        
        for check_name, command in network_checks:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                      capture_output=True, text=True, timeout=10)
                self.scan_results.insert(tk.END, f"\n{check_name}:\n")
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[:5]
                    for line in lines:
                        self.scan_results.insert(tk.END, f"  {line}\n")
                else:
                    self.scan_results.insert(tk.END, "  Not accessible\n")
            except:
                self.scan_results.insert(tk.END, f"\n{check_name}: Error\n")
                
    def scan_storage(self):
        storage_checks = [
            ('Disk Usage', 'df -h'),
            ('Mount Points', 'mount | head -10'),
            ('Partition Table', 'cat /proc/partitions'),
            ('Storage Devices', 'ls -la /dev/block/sd*')
        ]
        
        for check_name, command in storage_checks:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                      capture_output=True, text=True, timeout=10)
                self.scan_results.insert(tk.END, f"\n{check_name}:\n")
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[:8]
                    for line in lines:
                        self.scan_results.insert(tk.END, f"  {line}\n")
                else:
                    self.scan_results.insert(tk.END, "  Not accessible\n")
            except:
                self.scan_results.insert(tk.END, f"\n{check_name}: Error\n")
                
    def scan_processes(self):
        try:
            result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'ps', '-A'], 
                                  capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                total_processes = len(output_lines) - 1
                self.scan_results.insert(tk.END, f"\nRunning Processes ({total_processes} total):\n")
                
                critical_processes = []
                for line in output_lines[1:]:
                    if any(keyword in line.lower() for keyword in ['system', 'nfc', 'security', 'crypto', 'boot']):
                        critical_processes.append(line)
                
                for process in critical_processes[:15]:
                    self.scan_results.insert(tk.END, f"  {process}\n")
                    
            else:
                self.scan_results.insert(tk.END, "\nProcess scan: Access denied\n")
        except:
            self.scan_results.insert(tk.END, "\nProcess scan: Error\n")
            
    def scan_nfc_subsystem(self):
        nfc_checks = [
            ('NFC Service Status', 'dumpsys nfc | head -20'),
            ('NFC Hardware State', 'cat /sys/class/nfc/nfc*/device/state'),
            ('NFC Firmware Version', 'cat /sys/class/nfc/nfc*/device/firmware_version'),
            ('NFC Device Nodes', 'ls -la /dev/nfc*'),
            ('NFC Libraries', 'find /system -name "*nfc*" -type f'),
            ('NFC Configuration', 'find /vendor -name "*nfc*" -name "*.conf"')
        ]
        
        for check_name, command in nfc_checks:
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', command], 
                                      capture_output=True, text=True, timeout=10)
                self.scan_results.insert(tk.END, f"\n{check_name}:\n")
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[:10]
                    for line in lines:
                        if line.strip():
                            self.scan_results.insert(tk.END, f"  {line}\n")
                else:
                    self.scan_results.insert(tk.END, "  Not found or access denied\n")
            except:
                self.scan_results.insert(tk.END, f"\n{check_name}: Error\n")
                
    def security_scan(self):
        self.scan_security()
        
    def nfc_scan(self):
        self.scan_nfc_subsystem()
        
    def start_logging(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        def log_monitor():
            try:
                process = subprocess.Popen(['adb', '-s', self.current_device, 'logcat', '-v', 'threadtime'], 
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                         universal_newlines=True, bufsize=1)
                
                while process.poll() is None:
                    line = process.stdout.readline()
                    if line:
                        timestamp = datetime.now().strftime('%H:%M:%S')
                        self.log_text.insert(tk.END, f"[{timestamp}] {line}")
                        self.log_text.see(tk.END)
                        
            except Exception as e:
                self.log_text.insert(tk.END, f"Logging error: {str(e)}\n")
                
        self.log_thread = threading.Thread(target=log_monitor, daemon=True)
        self.log_thread.start()
        self.update_status("Logging started")
        
    def stop_logging(self):
        try:
            subprocess.run(['adb', 'logcat', '-c'], capture_output=True, timeout=5)
            self.update_status("Logging stopped")
        except:
            pass
            
    def clear_logs(self):
        self.log_text.delete(1.0, tk.END)
        
    def save_logs(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                content = self.log_text.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Logs saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
                
    def refresh_device_info(self):
        if not self.current_device:
            return
            
        self.device_info_tree.delete(*self.device_info_tree.get_children())
        
        device_props = {
            'Device Model': 'ro.product.model',
            'Android Version': 'ro.build.version.release',
            'SDK Level': 'ro.build.version.sdk',
            'Manufacturer': 'ro.product.manufacturer',
            'Brand': 'ro.product.brand',
            'CPU Architecture': 'ro.product.cpu.abi',
            'Build ID': 'ro.build.id',
            'Security Patch': 'ro.build.version.security_patch',
            'Bootloader': 'ro.bootloader',
            'Hardware': 'ro.hardware',
            'Serial Number': 'ro.serialno'
        }
        
        for display_name, prop in device_props.items():
            try:
                result = subprocess.run(['adb', '-s', self.current_device, 'shell', 'getprop', prop], 
                                      capture_output=True, text=True, timeout=5)
                value = result.stdout.strip() or "Unknown"
                self.device_info_tree.insert('', 'end', text=display_name, values=(value,))
            except:
                self.device_info_tree.insert('', 'end', text=display_name, values=("Error",))
                
    def export_scan_results(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                content = self.scan_results.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(f"POOPIEFART62 System Scan Results\n")
                    f.write(f"Device: {self.current_device}\n")
                    f.write(f"Export Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(content)
                messagebox.showinfo("Success", f"Scan results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
                
    def import_firmware(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    firmware_data = f.read()
                    
                checksum = hashlib.md5(firmware_data).hexdigest()
                size = len(firmware_data)
                
                result = messagebox.askyesno("Firmware Import",
                                           f"Firmware file: {filename}\n"
                                           f"Size: {size} bytes\n"
                                           f"MD5: {checksum}\n\n"
                                           f"Continue with import?")
                
                if result:
                    self.firmware_text.insert(tk.END, f"\nImported firmware: {filename}\n")
                    self.firmware_text.insert(tk.END, f"Size: {size} bytes\n")
                    self.firmware_text.insert(tk.END, f"Checksum: {checksum}\n")
                    self.firmware_text.insert(tk.END, "Ready for flashing.\n")
                    
            except Exception as e:
                messagebox.showerror("Error", f"Import failed: {str(e)}")
                
    def load_device_profile(self):
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    profile = json.load(f)
                    
                messagebox.showinfo("Success", f"Device profile loaded: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load profile: {str(e)}")
                
    def save_device_profile(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                profile = {
                    'device_id': self.current_device,
                    'chipset': self.chipset_label.cget('text'),
                    'firmware_version': self.firmware_label.cget('text'),
                    'save_time': datetime.now().isoformat(),
                    'device_info': self.tree_to_dict(self.device_info_tree)
                }
                
                with open(filename, 'w') as f:
                    json.dump(profile, f, indent=2)
                    
                messagebox.showinfo("Success", f"Device profile saved: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save profile: {str(e)}")
                
    def open_adb_shell(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        if platform.system() == "Windows":
            subprocess.Popen(['cmd', '/c', f'adb -s {self.current_device} shell'])
        else:
            subprocess.Popen(['gnome-terminal', '--', 'adb', '-s', self.current_device, 'shell'])
            
    def enter_fastboot(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        result = messagebox.askyesno("Confirm", "Reboot device into fastboot mode?")
        if result:
            try:
                subprocess.run(['adb', '-s', self.current_device, 'reboot', 'bootloader'], timeout=10)
                messagebox.showinfo("Info", "Device rebooting to fastboot mode")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to enter fastboot: {str(e)}")
                
    def enter_recovery(self):
        if not self.current_device:
            messagebox.showwarning("Warning", "No device connected")
            return
            
        result = messagebox.askyesno("Confirm", "Reboot device into recovery mode?")
        if result:
            try:
                subprocess.run(['adb', '-s', self.current_device, 'reboot', 'recovery'], timeout=10)
                messagebox.showinfo("Info", "Device rebooting to recovery mode")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to enter recovery: {str(e)}")
                
    def show_documentation(self):
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("700x600")
        doc_window.configure(bg='#1a1a1a')
        
        ttk.Label(doc_window, text="POOPIEFART62 Controller -  Documentation", 
                 style='Dark.TLabel', font=('Arial', 12, 'bold')).pack(pady=10)
        
        doc_text = scrolledtext.ScrolledText(doc_window, bg='#2a2a2a', fg='#ffffff', 
                                           insertbackground='#ffffff', selectbackground='#3a3a3a')
        doc_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        documentation = """
POOPIEFART62 Controller -  Edition
========================================

OVERVIEW
--------
Screen mirroring - Works but will be slow/laggy
APK execution - Can install, but launching may be inconsistent
System monitoring - Basic stats only, no real-time metrics
Input simulation - Basic tap/swipe works, complex gestures may not
Communications monitoring (SMS/calls/contacts) - Requires dangerous permissions rarely granted
Keylogger - Needs root access via getevent, fails on non-rooted devices
Network traffic capture - Requires root + tcpdump installation
Memory dumping - Needs root access to /proc/kcore, /proc/[pid]/maps
Root exploitation - idek
Security bypass - SELinux modifications require existing root
Location spoofing - Needs mock location apps and developer settings
Firmware flashing - Extremely device-specific, requires root + specific chipsets

"""
        
        doc_text.insert(tk.END, documentation)
        
    def show_about(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("About POOPIEFART62")
        about_window.geometry("500x400")
        about_window.configure(bg='#1a1a1a')
        about_window.resizable(False, False)
        
        main_frame = ttk.Frame(about_window, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame, text="POOPIEFART62 Controller", 
                 style='Dark.TLabel', font=('Arial', 18, 'bold')).pack(pady=10)
        
        ttk.Label(main_frame, text=" Edition v4.0", 
                 style='Dark.TLabel', font=('Arial', 14, 'bold')).pack()
        
        ttk.Label(main_frame, text="Advanced Android Analysis & Exploitation Framework", 
                 style='Dark.TLabel', font=('Arial', 11)).pack(pady=5)
        
        info_text = """.
        """
        
        ttk.Label(main_frame, text=info_text, style='Dark.TLabel', 
                 font=('Arial', 9), justify=tk.CENTER).pack(pady=15)
        
        ttk.Label(main_frame, text="Copyright 2025 POOPIEFART62  Project", 
                 style='Dark.TLabel', font=('Arial', 8)).pack()
        
        ttk.Button(main_frame, text="Close", style='Dark.TButton', 
                  command=about_window.destroy).pack(pady=15)
        
    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def log_message(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        
        if hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)
            
        print(log_entry.strip())
        
    def run(self):
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.root.mainloop()
        except KeyboardInterrupt:
            self.on_closing()
            
    def on_closing(self):
        if (self.scanning or self.reverse_engineering_active or 
            self.system_monitor_active or self.screen_monitor_active or 
            self.keylogger_active or self.network_monitor_active):
            result = messagebox.askyesno("Confirm Exit", 
                                       "Operations are still running. Force exit?")
            if not result:
                return
                
        try:
            self.stop_all_monitoring()
            if hasattr(self, 'log_thread') and self.log_thread.is_alive():
                subprocess.run(['pkill', '-f', 'adb.*logcat'], capture_output=True)
        except:
            pass
            
        self.root.quit()
        self.root.destroy()


def main():
    try:
        app = NFCControllerGUI()
        app.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
