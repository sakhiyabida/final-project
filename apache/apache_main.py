import argparse
from scanner import run_nmap_scan, pathTraversal, RCE
from generate_report_apache import generate_report

def main():
    parser = argparse.ArgumentParser(description="Scan for CVE-2021-41773 and CVE-2021-42013 vulnerabilities and generate report")
    parser.add_argument("-i", "--ip", type=str, required=True, help="Specify the IP address to scan")
    parser.add_argument("-p", "--port", type=str, required=True, help="Specify the port to scan")
    parser.add_argument("-pt", action="store_true", help="Check for Path Traversal vulnerability only")
    parser.add_argument("-rce", action="store_true", help="Check for Remote Code Execution vulnerability only")
    args = parser.parse_args()

    target_ip = args.ip
    target_port = args.port
    target = f"{target_ip}:{target_port}"
    print(f"Running Nmap scan on {target}...")
    run_nmap_scan(target_ip, target_port)

    url = f"http://{target}"

    if args.pt:
        pathTraversal(url)
    if args.rce:
        RCE(url)
    if not args.pt and not args.rce:
        pathTraversal(url)
        RCE(url)

    # Generate the report after the scan
    generate_report()

if __name__ == "__main__":
    main()
