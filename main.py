#!/usr/bin/env python3
import sys
import subprocess
import socket
import whois
import requests
from colorama import Fore, init
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
import threading
import re

# تثبيت التبعيات تلقائيًا
def install_dependencies():
    try:
        import requests
        import colorama
        import whois
        import bs4
    except ImportError:
        print("[!] Installing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("[+] Dependencies installed. Please restart.")
        sys.exit()

install_dependencies()

init(autoreset=True)

BANNER = """
\033[91m
  ██████ ▓█████  ███▄    █  ▒█████   ██▀███   ██ ▄█▀
▒██    ▒ ▓█   ▀  ██ ▀█   █ ▒██▒  ██▒▓██ ▒ ██▒ ██▄█▒ 
░ ▓██▄   ▒███   ▓██  ▀█ ██▒▒██░  ██▒▓██ ░▄█ ▒▓███▄░ 
  ▒   ██▒▒▓█  ▄ ▓██▒  ▐▌██▒▒██   ██░▓██▓█▌  ▓██ █▄ 
▒██████▒▒░▒████▒▒██░   ▓██░░ ████▓▒░▒██▒ █▄ ▒██▒ █▄
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ▒ ▒▒ ▓▒ ▒ ▒▒ ▓▒
░ ░▒  ░ ░ ░ ░  ░░ ░░   ░ ▒░  ░ ▒ ▒░ ░ ░▒ ▒░ ░ ░▒ ▒░
░  ░  ░     ░      ░   ░ ░ ░ ░ ░ ▒  ░ ░░ ░  ░ ░░ ░ 
      ░     ░  ░         ░     ░ ░  ░  ░    ░  ░   
\033[0m
"""

class WebScanner:
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.results = {
            "domain_info": {},
            "security_checks": {
                "xss": [], "sqli": [], "lfi": [],
                "open_redirect": [], "csrf": []
            },
            "hidden_files": [],
            "suspicious_content": [],
            "security_headers": {}
        }

    def full_scan(self):
        self.get_domain_info()
        self.check_headers()
        self.scan_vulnerabilities()
        self.find_hidden()
        self.check_malicious_content()

    def get_domain_info(self):
        try:
            ip = socket.gethostbyname(self.url.split("//")[1])
            w = whois.whois(self.url)
            self.results["domain_info"] = {
                "IP": ip,
                "Registrar": w.registrar,
                "Creation Date": w.creation_date[0].strftime("%Y-%m-%d") if w.creation_date else "N/A",
                "Expiration Date": w.expiration_date[0].strftime("%Y-%m-%d") if w.expiration_date else "N/A"
            }
        except Exception as e:
            self.results["domain_info"]["Error"] = str(e)

    def check_headers(self):
        try:
            resp = requests.get(self.url, timeout=10)
            headers = {
                "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options", "Missing"),
                "X-Frame-Options": resp.headers.get("X-Frame-Options", "Missing"),
                "Content-Security-Policy": resp.headers.get("Content-Security-Policy", "Missing"),
                "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security", "Missing")
            }
            self.results["security_headers"] = headers
        except:
            pass

    def scan_vulnerabilities(self):
        threads = []
        for check in [self.check_xss, self.check_sqli, self.check_lfi, self.check_open_redirect]:
            t = threading.Thread(target=check)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def check_xss(self):
        payloads = ["<script>alert('XSS')</script>", "'-alert(1)-'"]
        for payload in payloads:
            test_url = f"{self.url}/?test={payload}"
            try:
                resp = requests.get(test_url, timeout=10)
                if payload.encode() in resp.content:
                    self.results["security_checks"]["xss"].append(test_url)
            except:
                continue

    def check_sqli(self):
        errors = ["SQL syntax", "mysql_fetch", "Unclosed quotation mark"]
        payloads = ["' OR 1=1--", "' UNION SELECT null--"]
        for payload in payloads:
            test_url = f"{self.url}/?id={payload}"
            try:
                resp = requests.get(test_url, timeout=10)
                for error in errors:
                    if error in resp.text:
                        self.results["security_checks"]["sqli"].append(test_url)
            except:
                continue

    def check_lfi(self):
        payloads = ["../../etc/passwd", "../etc/passwd"]
        for payload in payloads:
            test_url = f"{self.url}/?page={payload}"
            try:
                resp = requests.get(test_url, timeout=10)
                if "root:x:0:0" in resp.text:
                    self.results["security_checks"]["lfi"].append(test_url)
            except:
                continue

    def check_open_redirect(self):
        payloads = ["http://evil.com", "https://malicious.site"]
        for payload in payloads:
            test_url = f"{self.url}/redirect?url={payload}"
            try:
                resp = requests.get(test_url, allow_redirects=False, timeout=10)
                if resp.status_code in (301, 302) and "Location" in resp.headers:
                    if payload in resp.headers["Location"]:
                        self.results["security_checks"]["open_redirect"].append(test_url)
            except:
                continue

    def find_hidden(self):
        common_dirs = [".git", "robots.txt", "admin", "backup", "wp-content"]
        for directory in common_dirs:
            test_url = urljoin(self.url, directory)
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200:
                    self.results["hidden_files"].append(test_url)
            except:
                continue

    def check_malicious_content(self):
        suspicious_strings = ["eval(", "base64_decode", "document.write(", "unescape("]
        try:
            resp = requests.get(self.url, timeout=10)
            for string in suspicious_strings:
                if string in resp.text:
                    self.results["suspicious_content"].append(f"Found: {string}")
        except:
            pass

def print_results(results):
    print(f"\n{Fore.GREEN}--- DOMAIN INFORMATION ---")
    for k, v in results["domain_info"].items():
        print(f"{Fore.CYAN}{k}: {Fore.WHITE}{v}")

    print(f"\n{Fore.GREEN}--- SECURITY HEADERS ---")
    for header, value in results["security_headers"].items():
        status = Fore.GREEN + "✓" if value != "Missing" else Fore.RED + "✗"
        print(f"{status} {header}: {value}")

    print(f"\n{Fore.GREEN}--- VULNERABILITIES ---")
    for vuln_type, findings in results["security_checks"].items():
        if findings:
            print(f"{Fore.RED}[!] {vuln_type.upper()} FOUND:")
            for finding in findings:
                print(f"   - {finding}")

    print(f"\n{Fore.GREEN}--- HIDDEN FILES ---")
    for hidden in results["hidden_files"]:
        print(f"   - {hidden}")

    print(f"\n{Fore.GREEN}--- SUSPICIOUS CONTENT ---")
    for content in results["suspicious_content"]:
        print(f"   - {content}")

def main():
    print(BANNER)
    print(f"{Fore.CYAN}Created by: Anonymous Jordan")
    print(f"{Fore.CYAN}Telegram: https://t.me/AnonymousJordan\n")

    target = input("Enter target URL (e.g., example.com): ").strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    scanner = WebScanner(target)
    scanner.full_scan()
    print_results(scanner.results)

if __name__ == "__main__":
    main()
