#!/usr/bin/env python3
import sys
import os
import socket
import requests
import whois
import dns.resolver
from colorama import Fore, Style
from datetime import datetime
import threading
import argparse

# Configuration
TIMEOUT = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}

# Logging System
class Logger:
    @staticmethod
    def info(message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.CYAN}[{timestamp}] [INFO] {message}{Style.RESET_ALL}")

    @staticmethod
    def success(message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.GREEN}[{timestamp}] [SUCCESS] {message}{Style.RESET_ALL}")

    @staticmethod
    def error(message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.RED}[{timestamp}] [ERROR] {message}{Style.RESET_ALL}")

    @staticmethod
    def warning(message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.YELLOW}[{timestamp}] [WARNING] {message}{Style.RESET_ALL}")

# Scanner Class
class WebRecon:
    def __init__(self, domain, proxy=None, threads=20, dir_wordlist=None, sub_wordlist=None, ports=None):
        self.domain = domain
        self.proxy = proxy
        self.threads = threads
        self.dir_wordlist = dir_wordlist
        self.sub_wordlist = sub_wordlist
        self.ports = ports or [80, 443]
        self.results = {
            "domain_info": {},
            "subdomains": [],
            "directories": [],
            "vulnerabilities": [],
            "ports": [],
            "security_checks": {}
        }

    def run(self):
        self.get_domain_info()
        self.scan_subdomains()
        self.scan_ports()
        self.scan_directories()
        self.check_vulnerabilities()

    def get_domain_info(self):
        Logger.info("Retrieving domain information")
        try:
            self.results["domain_info"]["ip"] = socket.gethostbyname(self.domain)
            w = whois.whois(self.domain)
            self.results["domain_info"]["whois"] = {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date
            }
            Logger.success("WHOIS Information Retrieved")
        except Exception as e:
            Logger.error(f"Domain information retrieval failed: {str(e)}")

    def scan_subdomains(self):
        if not self.sub_wordlist or not os.path.exists(self.sub_wordlist):
            Logger.error(f"Subdomain wordlist not found: {self.sub_wordlist}")
            return

        Logger.info(f"Starting Subdomain Scan with {sum(1 for _ in open(self.sub_wordlist))} entries")
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT

        def check_subdomain(sub):
            try:
                target = f"{sub}.{self.domain}"
                answers = resolver.resolve(target, 'A')
                if answers:
                    self.results["subdomains"].append(target)
                    Logger.success(f"Subdomain Found: {target}")
            except:
                pass

        with open(self.sub_wordlist) as f:
            subs = [line.strip() for line in f if line.strip()]
        
        threads = []
        for sub in subs:
            t = threading.Thread(target=check_subdomain, args=(sub,))
            t.start()
            threads.append(t)
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []

        for t in threads:
            t.join()

    def scan_ports(self):
        Logger.info(f"Starting Port Scan on {len(self.ports)} ports")
        open_ports = []
        for port in self.ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((self.results["domain_info"].get("ip", self.domain), port))
            if result == 0:
                open_ports.append(port)
                Logger.success(f"Port {port}/TCP Open")
            sock.close()
        self.results["ports"] = open_ports

    def scan_directories(self):
        if not self.dir_wordlist or not os.path.exists(self.dir_wordlist):
            Logger.error(f"Directory wordlist not found: {self.dir_wordlist}")
            return

        Logger.info(f"Starting Directory Scan with {sum(1 for _ in open(self.dir_wordlist))} entries")
        try:
            with open(self.dir_wordlist) as f:
                dirs = [line.strip() for line in f if line.strip()]
            
            for directory in dirs:
                url = f"http://{self.domain}/{directory}"
                try:
                    resp = requests.get(url, headers=HEADERS, proxies=self.proxy, timeout=TIMEOUT)
                    if resp.status_code == 200:
                        self.results["directories"].append(url)
                        Logger.success(f"Directory Found: {url}")
                except requests.exceptions.RequestException as e:
                    Logger.error(f"Directory check failed for {url}: {str(e)}")
        except Exception as e:
            Logger.error(f"Directory scan failed: {str(e)}")

    def check_vulnerabilities(self):
        Logger.info("Starting vulnerability checks")
        # Add your vulnerability checks here
        # Example SQLi check:
        try:
            test_url = f"http://{self.domain}/page?id=1' OR '1'='1"
            resp = requests.get(test_url, headers=HEADERS, proxies=self.proxy, timeout=TIMEOUT)
            if "error" in resp.text.lower():
                self.results["vulnerabilities"].append("Potential SQL Injection vulnerability")
                Logger.success("SQLi Vulnerability Detected")
        except requests.exceptions.RequestException as e:
            Logger.error(f"Vuln check failed: {str(e)}")

# Main Function
def main():
    print(f"""
    ██████╗ ██╗   ██╗███████╗██╗  ██╗██╗   ██╗██████╗ 
    ██╔══██╗╚██╗ ██╔╝██╔════╝██║  ██║██║   ██║██╔══██╗
    ██████╔╝ ╚████╔╝ ███████╗███████║██║   ██║██████╔╝
    ██╔═══╝   ╚██╔╝  ╚════██║██╔══██║██║   ██║██╔═══╝ 
    ██║        ██║   ███████║██║  ██║╚██████╔╝██║     
    ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     
    {Fore.CYAN}Created by: Anonymous Jordan
    {Fore.CYAN}Telegram: https://t.me/AnonymousJordan
    """)

    parser = argparse.ArgumentParser(description="Advanced Web Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-p", "--proxy", help="Proxy (http://user:pass@host:port)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads")
    parser.add_argument("-D", "--dir-wordlist", default="/usr/share/dirb/wordlists/common.txt", help="Directory wordlist")
    parser.add_argument("-s", "--sub-wordlist", default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt", help="Subdomain wordlist")
    parser.add_argument("-P", "--ports", type=lambda x: list(map(int, x.split(','))), default=[80,443], help="Ports to scan (comma-separated)")
    args = parser.parse_args()

    scanner = WebRecon(
        domain=args.domain,
        proxy=args.proxy,
        threads=args.threads,
        dir_wordlist=args.dir_wordlist,
        sub_wordlist=args.sub_wordlist,
        ports=args.ports
    )
    
    scanner.run()

    # Save report
    report_format = input("Choose report format [txt/json]: ").strip().lower() or "txt"
    if report_format == "json":
        import json
        with open(f"webrecon_report_{args.domain}_{int(datetime.now().timestamp())}.json", "w") as f:
            json.dump(scanner.results, f, indent=4)
    else:
        with open(f"webrecon_report_{args.domain}_{int(datetime.now().timestamp())}.txt", "w") as f:
            for key, value in scanner.results.items():
                f.write(f"--- {key.upper()} ---\n")
                f.write(f"{value}\n\n")

    Logger.success(f"Scan completed successfully. Report saved to webrecon_report_{args.domain}_*.{'json' if report_format == 'json' else 'txt'}")

if __name__ == "__main__":
    main()
