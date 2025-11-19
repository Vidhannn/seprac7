#!/usr/bin/env python3
"""
SpEL Injection Scanner with AI-driven payload generation
Autonomous scanner that detects SpEL injection vulnerabilities using LLM-generated payloads
"""

import requests
import json
import time
import re
import sys
import argparse
import subprocess
import signal
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

class SpELScanner:
    def __init__(self, openrouter_api_key: str, model: str = "anthropic/claude-3-haiku"):
        self.api_key = openrouter_api_key
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.timeout = 30
        self.max_retries = 3
        
        # SpEL detection patterns
        self.spel_patterns = [
            r'\$\{.*?\}',
            r'#\{.*?\}',
            r'T\(.*?\)',
            r'@.*?\)',
            r'new\s+\w+\(.*?\)',
        ]
        
        # Safe PoC payloads that don't execute OS commands or modify files
        self.safe_payloads = [
            "${7*7}",  # Arithmetic: should return 49
            "${'test'+'test'}",  # String concatenation: should return "testtest"
            "${1+1}",  # Simple math: should return 2
            "${'hello'.length()}",  # String method: should return 5
            "${T(java.lang.Math).random()}",  # Static method call
        ]

    def generate_spel_payload(self, context: str = "") -> str:
        """Generate SpEL payload using OpenRouter API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        
        prompt = f"""Generate a SpEL (Spring Expression Language) injection payload for testing vulnerabilities.
        
Requirements:
- The payload should be safe for proof-of-concept testing
- No OS command execution
- No file system operations
- Focus on arithmetic, string operations, or method calls
- Use SpEL syntax like ${{expression}}
- Context: {context}

Return ONLY the payload, no explanation."""

        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
            "max_tokens": 100,
        }
        
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.base_url,
                    headers=headers,
                    json=data,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    result = response.json()
                    payload = result["choices"][0]["message"]["content"].strip()
                    return payload
                else:
                    print(f"API request failed: {response.status_code}")
                    if attempt == self.max_retries - 1:
                        return self.safe_payloads[attempt % len(self.safe_payloads)]
                        
            except Exception as e:
                print(f"Error generating payload: {e}")
                if attempt == self.max_retries - 1:
                    return self.safe_payloads[attempt % len(self.safe_payloads)]
            
            time.sleep(2 ** attempt)  # Exponential backoff
        
        return self.safe_payloads[0]

    def parse_curl_command(self, curl_command: str) -> Dict:
        """Parse curl command and extract URL, headers, and data"""
        try:
            # Extract URL
            url_match = re.search(r"curl\s+['\"]?([^'\"]+)['\"]?", curl_command)
            if not url_match:
                raise ValueError("Could not extract URL from curl command")
            url = url_match.group(1)
            
            # Extract headers
            headers = {}
            header_matches = re.findall(r"-H\s+['\"]([^'\"]+)['\"]", curl_command)
            for header in header_matches:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Extract data/method
            data = None
            method = "GET"
            
            # Check for POST/PUT data
            data_match = re.search(r"-d\s+['\"]([^'\"]+)['\"]", curl_command)
            if data_match:
                data = data_match.group(1)
                method = "POST"
            
            # Check for method specification
            method_match = re.search(r"-X\s+(\w+)", curl_command)
            if method_match:
                method = method_match.group(1).upper()
            
            return {
                "url": url,
                "method": method,
                "headers": headers,
                "data": data
            }
            
        except Exception as e:
            print(f"Error parsing curl command: {e}")
            raise

    def substitute_placeholder(self, data: str, payload: str) -> str:
        """Replace <expr> placeholder with actual payload"""
        if "<expr>" in data:
            return data.replace("<expr>", payload)
        return data

    def test_injection(self, url: str, method: str, headers: Dict, data: Optional[str], payload: str) -> Dict:
        """Test SpEL injection with given payload"""
        try:
            test_headers = headers.copy()
            test_headers["User-Agent"] = "SpEL-Scanner/1.0"
            
            test_data = None
            if data:
                test_data = self.substitute_placeholder(data, payload)
            
            if method.upper() == "GET":
                response = requests.get(url, headers=test_headers, timeout=self.timeout)
            elif method.upper() == "POST":
                response = requests.post(url, headers=test_headers, data=test_data, timeout=self.timeout)
            else:
                response = requests.request(method, url, headers=test_headers, data=test_data, timeout=self.timeout)
            
            return {
                "status_code": response.status_code,
                "response_text": response.text,
                "response_headers": dict(response.headers),
                "payload": payload,
                "success": self.detect_spel_execution(response.text)
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "payload": payload,
                "success": False
            }

    def detect_spel_execution(self, response_text: str) -> bool:
        """Detect if SpEL expression was executed based on response patterns"""
        # Look for common SpEL execution results
        execution_indicators = [
            r'\b49\b',  # 7*7 result
            r'\b2\b',   # 1+1 result  
            r'\btesttest\b',  # string concatenation
            r'\b5\b',   # length result
            r'0\.\d+',  # random() result
            r'Error.*expression',  # SpEL parsing errors
            r'SpEL.*Exception',   # SpEL exceptions
        ]
        
        for pattern in execution_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False

    def scan_url(self, url: str, method: str = "GET", headers: Dict = None, data: str = None) -> List[Dict]:
        """Scan URL for SpEL injection vulnerabilities"""
        if headers is None:
            headers = {}
        
        results = []
        
        print(f"Scanning {method} {url}")
        
        # Test with safe payloads first
        for payload in self.safe_payloads:
            print(f"Testing payload: {payload}")
            result = self.test_injection(url, method, headers, data, payload)
            results.append(result)
            
            if result.get("success"):
                print(f"[+] Potential SpEL injection detected with payload: {payload}")
            
            time.sleep(1)  # Rate limiting
        
        # Generate and test AI payloads
        for i in range(3):  # Generate 3 custom payloads
            context = f"Testing {method} request to {url}"
            if data:
                context += f" with data: {data[:100]}"
            
            ai_payload = self.generate_spel_payload(context)
            print(f"Testing AI payload: {ai_payload}")
            
            result = self.test_injection(url, method, headers, data, ai_payload)
            results.append(result)
            
            if result.get("success"):
                print(f"[+] Potential SpEL injection detected with AI payload: {ai_payload}")
            
            time.sleep(2)  # Rate limiting
        
        return results

    def scan_curl_command(self, curl_command: str) -> List[Dict]:
        """Scan a curl command for SpEL injection vulnerabilities"""
        try:
            parsed = self.parse_curl_command(curl_command)
            return self.scan_url(
                parsed["url"],
                parsed["method"],
                parsed["headers"],
                parsed["data"]
            )
        except Exception as e:
            print(f"Error scanning curl command: {e}")
            return [{"error": str(e)}]

def main():
    parser = argparse.ArgumentParser(description="SpEL Injection Scanner with AI payload generation")
    parser.add_argument("--api-key", required=True, help="OpenRouter API key")
    parser.add_argument("--url", help="URL to scan")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--data", help="POST data (use <expr> as placeholder)")
    parser.add_argument("--curl", help="Curl command to test")
    parser.add_argument("--model", default="anthropic/claude-3-haiku", help="OpenRouter model")
    
    args = parser.parse_args()
    
    if not args.url and not args.curl:
        print("Error: Either --url or --curl must be specified")
        sys.exit(1)
    
    scanner = SpELScanner(args.api_key, args.model)
    
    try:
        if args.curl:
            results = scanner.scan_curl_command(args.curl)
        else:
            results = scanner.scan_url(args.url, args.method, {}, args.data)
        
        # Print results
        print("\n" + "="*50)
        print("SCAN RESULTS")
        print("="*50)
        
        vulnerabilities_found = False
        for i, result in enumerate(results, 1):
            print(f"\nTest {i}:")
            print(f"Payload: {result.get('payload', 'N/A')}")
            
            if "error" in result:
                print(f"Error: {result['error']}")
                continue
            
            print(f"Status Code: {result.get('status_code', 'N/A')}")
            print(f"SpEL Execution: {'YES' if result.get('success') else 'NO'}")
            
            if result.get('success'):
                vulnerabilities_found = True
                print("[!] VULNERABILITY DETECTED")
        
        print("\n" + "="*50)
        if vulnerabilities_found:
            print("[!] SPEL INJECTION VULNERABILITIES FOUND")
            sys.exit(1)
        else:
            print("[-] No SpEL injection vulnerabilities detected")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()