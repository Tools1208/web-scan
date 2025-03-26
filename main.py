#!/usr/bin/env python3
import sys
import subprocess
import os

def install_dependencies():
    try:
        import requests
        import colorama
        import bs4
    except ImportError:
        print("[!] Installing required dependencies...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        except subprocess.CalledProcessError:
            print("[!] Failed to install dependencies")
            sys.exit(1)
        print("[+] Dependencies installed successfully. Please restart the tool.")
        sys.exit()

install_dependencies()

import argparse
from colorama import Fore, Style, init
from modules.scanner import WebScanner
from modules.reporter import generate_report

init(autoreset=True)

BANNER = """
███████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗   ██╗ ██████╗ 
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝ 
███████╗██║   ██║██████╔╝█████╗  ██████╔╝ ╚████╔╝ ██║  ███╗
╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗  ╚██╔╝  ██║   ██║
███████║╚██████╔╝██║     ███████╗██║  ██║   ██║   ╚██████╔╝
╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ 
"""

def main():
    print(BANNER)
    print(Fore.CYAN + "Tool Created By: Anonymous Jordan")
    print(Fore.CYAN + "Telegram: https://t.me/AnonymousJordan\n")
    
    parser = argparse.ArgumentParser(description="WebScanner - Advanced Web Vulnerability Scanner")
    parser.add_argument('-u', '--url', help="Target URL (e.g., http://example.com)")
    parser.add_argument('--proxy', help="Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads")
    parser.add_argument('-o', '--output', help="Output file (JSON/TXT)")
    args = parser.parse_args()

    if not args.url:
        show_menu()
        return

    scanner = WebScanner(args.url, args.proxy, args.threads)
    scanner.run_full_scan()
    
    if args.output:
        generate_report(scanner.results, args.output)

def show_menu():
    print(f"{Fore.CYAN}[00] Exit")
    print("[01] Full Scan")
    print("[02] Admin Finder")
    print("[03] Update Project")
    choice = input(f"{Fore.YELLOW}WebScanner> ")
    
    if choice == '00':
        sys.exit()
    elif choice == '01':
        url = input("Enter target URL: ")
        proxy = input("Enter proxy (optional): ")
        threads = int(input("Enter threads (default 10): ") or 10)
        scanner = WebScanner(url, proxy, threads)
        scanner.run_full_scan()
    elif choice == '02':
        print(f"{Fore.RED}Admin Finder coming soon!")
    elif choice == '03':
        os.system("git pull origin main")
    else:
        print(f"{Fore.RED}Invalid choice!")

if __name__ == "__main__":
    main()
