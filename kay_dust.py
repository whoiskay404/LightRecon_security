from colorama import Fore, init
init(autoreset=True)
from tqdm import tqdm
import re
import requests
import time
from datetime import datetime
import os
import argparse

DOMAIN = ""

def run_step(name, func):
    print(Fore.CYAN + f"\n[+] {name}")
    for _ in tqdm(range(10), desc=name):
        time.sleep(0.05)
    func()

def reflection_scan():
    print(Fore.YELLOW + "[*] Checking for reflected parameters (XSS hints)...")

    payload = "kaysociety123"
    findings = []

    try:
        urls = open("output/params.txt").read().splitlines()
    except:
        urls = []

    for url in urls[:30]:  # limit for safety
        try:
            test_url = url + payload
            r = requests.get(test_url, timeout=5)

            if payload in r.text:
                findings.append(f"Reflection found: {url}")
        except:
            continue

    with open("output/reflections.txt", "w") as f:
        for x in findings:
            f.write(x + "\n")

    print(Fore.GREEN + f"[+] Reflections found: {len(findings)}")

def param_fuzzer():
    print(Fore.YELLOW + "[*] Running parameter discovery...")

    common_params = ["id", "page", "q", "search", "user"]
    base_urls = []

    try:
        base_urls = open("output/live.txt").read().splitlines()
    except:
        pass

    discovered = []

    for base in base_urls:
        for param in common_params:
            test_url = f"{base}?{param}=test"
            try:
                r = requests.get(test_url, timeout=5)
                if r.status_code == 200:
                    discovered.append(test_url)
            except:
                continue

    with open("output/param_fuzz.txt", "w") as f:
        for d in discovered:
            f.write(d + "\n")

    print(Fore.GREEN + f"[+] Parameter endpoints: {len(discovered)}")

def extract_endpoints():
    print(Fore.YELLOW + "[*] Extracting endpoints from JS...")

    endpoints = []

    try:
        js_files = open("output/js.txt").read().splitlines()
    except:
        js_files = []

    pattern = r"https?://[^\s\"']+"

    for js in js_files:
        try:
            r = requests.get(js, timeout=5)
            matches = re.findall(pattern, r.text)

            for m in matches:
                endpoints.append(m)
        except:
            continue

    with open("output/endpoints.txt", "w") as f:
        for e in set(endpoints):
            f.write(e + "\n")

    print(Fore.GREEN + f"[+] Endpoints extracted: {len(endpoints)}")

def high_value_targets():
    print(Fore.YELLOW + "[*] Identifying high-value targets...")

    findings = []

    try:
        urls = open("output/urls.txt").read().splitlines()
    except:
        urls = []

    keywords = ["admin", "login", "dashboard", "portal", "api"]

    for url in urls:
        for k in keywords:
            if k in url.lower():
                findings.append(url)

    with open("output/high_value.txt", "w") as f:
        for h in findings:
            f.write(h + "\n")

    print(Fore.GREEN + f"[+] High-value endpoints: {len(findings)}")

def vuln_hints():
    print(Fore.YELLOW + "[*] Analyzing potential attack surfaces...")

    hints = []

    try:
        urls = open("output/urls.txt").read().splitlines()
    except:
        urls = []

    for url in urls:
        if "=" in url:
            hints.append(f"Possible parameter injection: {url}")
        if "admin" in url.lower():
            hints.append(f"Admin panel hint: {url}")
        if ".php?id=" in url.lower():
            hints.append(f"ID parameter detected: {url}")

    with open("output/hints.txt", "w") as f:
        for h in hints:
            f.write(h + "\n")

    print(Fore.GREEN + f"[+] Vulnerability hints found: {len(hints)}")


def run_cmd(cmd):
    print(f"\n[+] Running: {cmd}")
    os.system(cmd)

import time

def banner_step(text):
    print(Fore.CYAN + "\n>>> " + text)
    time.sleep(0.5)

def scan_js_secrets():
    print(Fore.YELLOW + "[*] Scanning JS intelligence...")

    secrets = []

    try:
        with open("output/js.txt", "r") as f:
            content = f.read()
    except:
        content = ""

    patterns = {
        "AWS Key": r"AKIA[0-9A-Z]{16}",
        "Google API": r"AIza[0-9A-Za-z\-_]{35}",
        "Bearer Token": r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
        "Private Key": r"-----BEGIN PRIVATE KEY-----",
        "Password Field": r"password\s*[:=]\s*[\"'][^\"']+[\"']"
    }

    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        for m in matches:
            secrets.append(f"{name}: {m}")

    os.makedirs("output", exist_ok=True)

    with open("output/secrets.txt", "w") as f:
        for s in secrets:
            f.write(s + "\n")

    print(Fore.GREEN + f"[+] JS Intelligence findings: {len(secrets)}")


def find_parameters():
    print("\n[*] Finding URL parameters...")

    params = []

    try:
        with open("output/urls.txt", "r") as f:
            urls = f.read().splitlines()
    except:
        urls = []

    for url in urls:
        if "?" in url:
            params.append(url)

    with open("output/params.txt", "w") as f:
        for p in params:
            f.write(p + "\n")

    print(f"[+] Parameter URLs found: {len(params)}")

def risk_summary():
    print("\n[*] Generating risk summary...")

    try:
        subdomains = len(open("output/subdomains.txt").readlines())
    except:
        subdomains = 0

    try:
        live = len(open("output/live.txt").readlines())
    except:
        live = 0

    try:
        params = len(open("output/params.txt").readlines())
    except:
        params = 0

    try:
        secrets = len(open("output/secrets.txt").readlines())
    except:
        secrets = 0

    score = (params * 2) + (secrets * 5) + (live * 1)

    if score < 10:
        risk = "LOW"
    elif score < 30:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    print("\n====================")
    print(" RISK SUMMARY")
    print("====================")
    print(f"Subdomains: {subdomains}")
    print(f"Live hosts: {live}")
    print(f"Parameter URLs: {params}")
    print(f"Secrets found: {secrets}")
    print(f"Risk Score: {score}")
    print(f"Risk Level: {risk}")
    print("====================\n")

    with open("output/risk.txt", "w") as f:
        f.write(f"Risk Score: {score}\nRisk Level: {risk}\n")

def subdomain_enum(domain):
    print(Fore.YELLOW + "[*] Subdomain Enumeration Started...")
    run_cmd(f"subfinder -d {domain} -silent -o output/subdomains.txt")

def live_check():
    print(Fore.YELLOW + "[*]  Checking live domains...") 
    run_cmd("httpx -l output/subdomains.txt -silent -o output/live.txt")

def url_crawl():
    print(Fore.YELLOW + "[*] Crawling URLs...")
    run_cmd("katana -list output/live.txt -silent -o output/urls.txt")

def extract_js():
    print(Fore.YELLOW + "[*] Extracting JS files...")
    run_cmd("cat output/urls.txt | grep '.js' > output/js.txt")

from datetime import datetime

def generate_report(domain):
    print(Fore.YELLOW + "[*]  Generating report...") 

    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def safe_read(file):
        try:
            return open(file).read().splitlines()
        except:
            return []

    subdomains = safe_read("output/subdomains.txt")
    live = safe_read("output/live.txt")
    urls = safe_read("output/urls.txt")
    js = safe_read("output/js.txt")

    html = f"""
    <html>
    <head>
        <title>Recon Report - {domain}</title>
        <style>
            body {{ font-family: Arial; background:#0f172a; color:white; padding:20px; }}
            h1 {{ color:#38bdf8; }}
            h2 {{ color:#22c55e; }}
            .box {{ background:#1e293b; padding:10px; margin:10px 0; border-radius:8px; }}
        </style>
    </head>
    <body>

    <h1>ReconX Report</h1>
    <p><b>Target:</b> {domain}</p>
    <p><b>Date:</b> {time}</p>

    <div class="box">
        <h2>Subdomains ({len(subdomains)})</h2>
        <pre>{"\n".join(subdomains)}</pre>
    </div>

    <div class="box">
        <h2>Live Hosts ({len(live)})</h2>
        <pre>{"\n".join(live)}</pre>
    </div>

    <div class="box">
        <h2>URLs ({len(urls)})</h2>
        <pre>{"\n".join(urls[:50])}</pre>
    </div>

    <div class="box">
        <h2>JS Files ({len(js)})</h2>
        <pre>{"\n".join(js)}</pre>
    </div>

    </body>
    </html>
    """

    filename = f"reports/{domain}_report.html"
    os.makedirs("reports", exist_ok=True)

    with open(filename, "w") as f:
        f.write(html)

    print(f"[+] Report saved: {filename}")

def final_dashboard(domain):
    print(Fore.GREEN + "\n==============================")
    print(Fore.GREEN + "     RECONX FINAL DASHBOARD")
    print(Fore.GREEN + "==============================")

    def count(file):
        try:
            return len(open(file).readlines())
        except:
            return 0

    print(Fore.CYAN + f"Target: {domain}")
    print(Fore.YELLOW + f"Subdomains: {count('output/subdomains.txt')}")
    print(f"Live Hosts: {count('output/live.txt')}")
    print(f"URLs: {count('output/urls.txt')}")
    print(f"JS Files: {count('output/js.txt')}")
    print(f"Secrets: {count('output/secrets.txt')}")
    print(f"Hints: {count('output/hints.txt')}")

    print(Fore.GREEN + "==============================\n")


def main():
    parser = argparse.ArgumentParser(description="Kay_recon -  Bug Bounty Recon Tool")
    parser.add_argument("domain", help="Target domain (example.com)")
    args = parser.parse_args()

    global DOMAIN
    DOMAIN = args.domain

    print(Fore.CYAN + "\n============================================")
    print(Fore.GREEN + "   KAY_RECON_PRO - BUG BOUNTY FRAMEWORK")
    print(Fore.YELLOW + "   AUTHOR: KARABO KOSI (KAYSOCIETY)")
    print(Fore.CYAN + "============================================\n")

    os.makedirs("output", exist_ok=True)

    run_step("Subdomain Enumeration", lambda: subdomain_enum(DOMAIN))
    run_step("Live Host Check", live_check)
    run_step("URL Crawling", url_crawl)
    run_step("JS Extraction", extract_js)
    run_step("Parameter Fuzzing", param_fuzzer)
    run_step("Reflection Scan (XSS Hints)", reflection_scan)
    run_step("JS Endpoint Extraction", extract_endpoints)
    run_step("High Value Target Detection", high_value_targets)

    run_step("JS Intelligence Scan", scan_js_secrets)
    run_step("Vulnerability Hint Engine", vuln_hints)

    run_step("Risk Analysis", risk_summary)
    run_step("Report Generation", lambda: generate_report(DOMAIN))

    final_dashboard(DOMAIN)

    print(Fore.GREEN + "\n==============================")
    print(Fore.GREEN + "        RECON COMPLETE")
    print(Fore.GREEN + "==============================")

    print(Fore.CYAN + f"Target: {DOMAIN}")
    print(Fore.YELLOW + "Check folders:")
    print(Fore.WHITE + "- output/") 
    print(Fore.WHITE + "- reports/")

    print(Fore.RED + "\nTip: Open HTML report for full analysis")
    print(Fore.GREEN + "==============================\n")


if __name__ == "__main__":
    main()

