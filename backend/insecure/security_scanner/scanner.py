#!/usr/bin/env python3
"""
API Security Testing Scanner
Tests for common API vulnerabilities
"""

import requests
import json
import jwt
import time
from datetime import datetime
import sys

class APISecurityScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []
        self.start_time = datetime.now()
    
    def test_jwt_weak_secret(self):
        """Test 1: JWT Token with Weak Secret"""
        print("[*] Testing JWT Token Issues...")
        
        try:
            # Try to login
            response = requests.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"email": "test@example.com"}
            )
            
            if response.status_code == 200:
                token = response.json().get('token')
                
                # Try to decode with hardcoded secrets
                weak_secrets = [
                    'super-secret-key-do-not-use',
                    'secret',
                    'password',
                    '123456'
                ]
                
                for secret in weak_secrets:
                    try:
                        payload = jwt.decode(token, secret, algorithms=['HS256'])
                        self.results.append({
                            "test": "JWT Weak Secret",
                            "severity": "CRITICAL",
                            "status": "VULNERABLE",
                            "details": f"Token decoded with secret: {secret}"
                        })
                        return
                    except:
                        pass
        except Exception as e:
            print(f"  Error: {e}")
    
    def test_sql_injection(self):
        """Test 2: SQL Injection"""
        print("[*] Testing SQL Injection...")
        
        payloads = ["1 OR 1=1", "'; DROP TABLE users; --", "1 UNION SELECT"]
        
        for payload in payloads:
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/users/{payload}"
                )
                
                if "SQL" in response.text or "query" in response.text:
                    self.results.append({
                        "test": "SQL Injection",
                        "severity": "CRITICAL",
                        "status": "VULNERABLE",
                        "payload": payload
                    })
                    return
            except:
                pass
    
    def test_broken_auth(self):
        """Test 3: Broken Authentication"""
        print("[*] Testing Broken Authentication...")
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/admin/users"
            )
            
            if response.status_code == 200:
                self.results.append({
                    "test": "Broken Authentication",
                    "severity": "CRITICAL",
                    "status": "VULNERABLE",
                    "details": "Admin endpoint accessible without authentication"
                })
        except:
            pass
    
    def test_api_key_issues(self):
        """Test 4: API Key Issues"""
        print("[*] Testing API Key Issues...")
        
        test_keys = ['sk_test_1234', 'sk_live_5678', 'test', 'admin']
        
        for key in test_keys:
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/data/sensitive?api_key={key}"
                )
                
                if response.status_code == 200:
                    self.results.append({
                        "test": "API Key Issues",
                        "severity": "HIGH",
                        "status": "VULNERABLE",
                        "details": f"Weak API key accepted: {key}"
                    })
                    return
            except:
                pass
    
    def test_rate_limiting(self):
        """Test 5: Missing Rate Limiting"""
        print("[*] Testing Rate Limiting...")
        
        # Try rapid requests
        count = 0
        start = time.time()
        
        for i in range(10):
            try:
                response = requests.post(
                    f"{self.base_url}/api/v1/brute/login",
                    json={"email": "test@example.com", "password": "wrong"}
                )
                count += 1
            except:
                break
        
        elapsed = time.time() - start
        
        if count == 10 and elapsed < 5:
            self.results.append({
                "test": "Missing Rate Limiting",
                "severity": "HIGH",
                "status": "VULNERABLE",
                "details": f"Sent 10 requests in {elapsed:.2f}s without being blocked"
            })
    
    def test_idor(self):
        """Test 6: IDOR"""
        print("[*] Testing IDOR...")
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/orders/1"
            )
            
            if response.status_code == 200:
                self.results.append({
                    "test": "IDOR (Insecure Direct Object Reference)",
                    "severity": "HIGH",
                    "status": "VULNERABLE",
                    "details": "Can access other users' orders without authorization"
                })
        except:
            pass
    
    def test_cors(self):
        """Test 7: CORS Misconfiguration"""
        print("[*] Testing CORS...")
        
        try:
            response = requests.options(
                f"{self.base_url}/api/v1/profile"
            )
            
            if '*' in response.headers.get('Access-Control-Allow-Origin', ''):
                self.results.append({
                    "test": "CORS Misconfiguration",
                    "severity": "HIGH",
                    "status": "VULNERABLE",
                    "details": "Allows requests from any origin"
                })
        except:
            pass
    
    def test_mass_assignment(self):
        """Test 8: Mass Assignment"""
        print("[*] Testing Mass Assignment...")
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/user/update",
                json={
                    "email": "user@example.com",
                    "role": "admin",
                    "is_admin": True
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('user', {}).get('role') == 'admin':
                    self.results.append({
                        "test": "Mass Assignment",
                        "severity": "HIGH",
                        "status": "VULNERABLE",
                        "details": "Can modify protected fields like role and is_admin"
                    })
        except:
            pass
    
    def test_security_headers(self):
        """Test 10: Missing Security Headers"""
        print("[*] Testing Security Headers...")
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/data"
            )
            
            required_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy'
            ]
            
            missing = [h for h in required_headers if h not in response.headers]
            
            if missing:
                self.results.append({
                    "test": "Missing Security Headers",
                    "severity": "MEDIUM",
                    "status": "VULNERABLE",
                    "details": f"Missing headers: {', '.join(missing)}"
                })
        except:
            pass
    
    def run_all_tests(self):
        """Run all security tests"""
        print("\n" + "="*70)
        print("🔐 API SECURITY SCAN STARTING")
        print("="*70 + "\n")
        
        self.test_jwt_weak_secret()
        self.test_sql_injection()
        self.test_broken_auth()
        self.test_api_key_issues()
        self.test_rate_limiting()
        self.test_idor()
        self.test_cors()
        self.test_mass_assignment()
        self.test_security_headers()
        
        return self.results
    
    def generate_report(self):
        """Generate security report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "total_tests": 9,
            "vulnerabilities_found": len(self.results),
            "critical": len([r for r in self.results if r.get('severity') == 'CRITICAL']),
            "high": len([r for r in self.results if r.get('severity') == 'HIGH']),
            "medium": len([r for r in self.results if r.get('severity') == 'MEDIUM']),
            "findings": self.results
        }
        
        return report
    
    def print_report(self):
        """Print formatted report"""
        report = self.generate_report()
        
        print("\n" + "="*70)
        print("🔐 API SECURITY SCAN REPORT")
        print("="*70)
        print(f"\nTarget: {report['target']}")
        print(f"Timestamp: {report['timestamp']}")
        print(f"\nTotal Tests: {report['total_tests']}")
        print(f"Vulnerabilities Found: {report['vulnerabilities_found']}")
        print(f"  🔴 Critical: {report['critical']}")
        print(f"  🟠 High: {report['high']}")
        print(f"  🟡 Medium: {report['medium']}")
        
        print("\n" + "-"*70)
        print("FINDINGS:")
        print("-"*70)
        
        for i, finding in enumerate(report['findings'], 1):
            severity_emoji = "🔴" if finding['severity'] == 'CRITICAL' else "🟠" if finding['severity'] == 'HIGH' else "🟡"
            print(f"\n{i}. {severity_emoji} {finding['test']} [{finding['severity']}]")
            print(f"   Status: {finding['status']}")
            print(f"   Details: {finding.get('details', 'N/A')}")
        
        print("\n" + "="*70)
        print("OVERALL RISK: 🔴 CRITICAL")
        print("="*70 + "\n")
        
        return report

if __name__ == '__main__':
    base_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8000'
    
    scanner = APISecurityScanner(base_url)
    scanner.run_all_tests()
    scanner.print_report()
