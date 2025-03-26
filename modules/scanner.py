import requests
from bs4 import BeautifulSoup
from colorama import Fore
import threading
import re

class WebScanner:
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.results = {
            "vulnerabilities": [],
            "hidden_pages": 0,
            "suspicious_files": [],
            "security_headers": {}
        }

    def run_full_scan(self):
        print(f"\n{Fore.GREEN}[+] Starting Full Scan...")
        self.check_headers()
        self.check_xss()
        self.check_sqli()
        self.find_hidden()
        self.check_csrf()

    def check_headers(self):
        print(f"{Fore.YELLOW}[-] Checking Security Headers...")
        headers = requests.get(self.url).headers
        security_headers = {
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "missing"),
            "X-Frame-Options": headers.get("X-Frame-Options", "missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "missing")
        }
        self.results["security_headers"] = security_headers

    def check_xss(self):
        print(f"{Fore.YELLOW}[-] Checking XSS Vulnerabilities...")
        # إضافة المزيد من الـ payloads هنا

    def check_sqli(self):
        print(f"{Fore.YELLOW}[-] Checking SQLi Vulnerabilities...")
        # إضافة المزيد من الـ payloads هنا

    def find_hidden(self):
        print(f"{Fore.YELLOW}[-] Finding Hidden Pages...")
        # إضافة المزيد من الـ wordlists هنا

    def check_csrf(self):
        print(f"{Fore.YELLOW}[-] Checking CSRF Vulnerabilities...")
        # إضافة منطق فحص CSRF هنا
