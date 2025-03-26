import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore
import threading
import re
from .payloads import load_payloads

class WebScanner:
    def __init__(self, url, proxy=None, threads=10):
        self.url = url.rstrip('/')
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.threads = threads
        self.results = {
            "vulnerabilities": [],
            "hidden_files": [],
            "internal_links": []
        }
        self.lock = threading.Lock()
        self.xss_payloads = load_payloads('xss')
        self.sqli_payloads = load_payloads('sqli')
        self.dir_payloads = load_payloads('dirs')

    def run_full_scan(self):
        print(f"{Fore.GREEN}[+] Starting full scan on {self.url}")
        self.crawl_internal_links()
        self.check_xss()
        self.check_sqli()
        self.find_hidden_files()
        self.print_results()

    def check_xss(self):
        print(f"{Fore.YELLOW}[-] Checking for XSS vulnerabilities...")
        for payload in self.xss_payloads:
            test_url = f"{self.url}/?test={payload}"
            try:
                resp = requests.get(test_url, proxies=self.proxy, timeout=10)
                if payload.encode() in resp.content:
                    with self.lock:
                        self.results["vulnerabilities"].append({
                            "type": "XSS",
                            "severity": "High",
                            "endpoint": test_url,
                            "payload": payload
                        })
            except requests.exceptions.RequestException:
                continue

    def check_sqli(self):
        print(f"{Fore.YELLOW}[-] Checking for SQLi vulnerabilities...")
        sqli_errors = [
            re.compile(r"SQL syntax"), 
            re.compile(r"mysql_fetch"),
            re.compile(r"Unclosed quotation mark")
        ]
        
        for payload in self.sqli_payloads:
            test_url = f"{self.url}/?id={payload}"
            try:
                resp = requests.get(test_url, proxies=self.proxy, timeout=10)
                for error in sqli_errors:
                    if error.search(resp.text):
                        with self.lock:
                            self.results["vulnerabilities"].append({
                                "type": "SQLi",
                                "severity": "Critical",
                                "endpoint": test_url,
                                "payload": payload
                            })
            except requests.exceptions.RequestException:
                continue

    def find_hidden_files(self):
        print(f"{Fore.YELLOW}[-] Searching for hidden files/directories...")
        def check_dir(directory):
            test_url = urljoin(self.url, directory)
            try:
                resp = requests.get(test_url, proxies=self.proxy, timeout=10)
                if resp.status_code == 200:
                    with self.lock:
                        self.results["hidden_files"].append(test_url)
            except requests.exceptions.RequestException:
                pass

        threads = []
        for directory in self.dir_payloads:
            t = threading.Thread(target=check_dir, args=(directory,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def crawl_internal_links(self):
        print(f"{Fore.YELLOW}[-] Crawling internal links...")
        try:
            resp = requests.get(self.url, proxies=self.proxy, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_url = urljoin(self.url, link['href'])
                if self.url in full_url and full_url not in self.results["internal_links"]:
                    self.results["internal_links"].append(full_url)
        except requests.exceptions.RequestException:
            pass

    def print_results(self):
        print(f"\n{Fore.GREEN}[+] Scan Results:")
        print(f"{Fore.CYAN}--- Vulnerabilities ---")
        for vuln in self.results["vulnerabilities"]:
            print(f"{Fore.RED}[!] {vuln['type']} ({vuln['severity']})")
            print(f"   URL: {vuln['endpoint']}")
            print(f"   Payload: {vuln['payload']}")

        print(f"\n{Fore.CYAN}--- Hidden Files ---")
        for hidden in self.results["hidden_files"]:
            print(f"   {hidden}")

        print(f"\n{Fore.CYAN}--- Internal Links ---")
        for link in self.results["internal_links"]:
            print(f"   {link}")
