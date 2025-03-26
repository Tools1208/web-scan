#!/usr/bin/env python3
import sys
import subprocess
import os

def install_dependencies():
    try:
        # محاولة استيراد المكتبات المطلوبة
        import requests
        import colorama
        import bs4
    except ImportError:
        # إذا فشل الاستيراد، قم بتثبيت المتطلبات تلقائيًا
        print("[!] جارٍ تثبيت المتطلبات...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        except subprocess.CalledProcessError:
            print("[!] فشل في تثبيت المتطلبات")
            sys.exit(1)
        print("[+] done install , please start the tool anthor.")
        sys.exit()

# التحقق من التبعيات عند التشغيل
install_dependencies()

# استيراد المكتبات بعد التأكد من تثبيتها
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
    parser = argparse.ArgumentParser(description="WebScanner - Advanced Web Vulnerability Scanner")
    parser.add_argument('-u', '--url', help="Target URL (e.g., http://example.com)")
    parser.add_argument('--proxy', help="Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads")
    parser.add_argument('-o', '--output', help="Output file (JSON/TXT)")
    args = parser.parse_args()

    print(BANNER)
    
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
