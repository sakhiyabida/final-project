import logging
import re
from flask import Flask, request, render_template, redirect, url_for, send_file
from pfsense.pfsense_module import pfsense_exploit
from mikrotik.wxmenu import winbox_exploit
from apache.scanner import run_nmap_scan, pathTraversal, RCE, find_apache_ports, filter_apache_services, process_targets
from apache.generate_report_apache import generate_report as generate_report_apache
from pfsense.report import generate_report as generate_report_pfsense
from mikrotik.generate_report import generate_report as generate_report_mikrotik
import os
import time
import io
from io import BytesIO

# Set up logging
logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def is_valid_ip(ip):
    """Validate the IP address format."""
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_pattern.match(ip)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/select_tool', methods=['POST'])
def select_tool():
    tool = request.form['tool']
    if tool == 'pfsense':
        return redirect(url_for('pfsense_form'))
    elif tool == 'winbox':
        return redirect(url_for('winbox_form'))
    elif tool == 'apache':
        return redirect(url_for('apache_form'))
    else:
        return "Invalid tool selected."

@app.route('/pfsense_form')
def pfsense_form():
    return render_template('pfsense_form.html')

@app.route('/winbox_form')
def winbox_form():
    return render_template('winbox_form.html')

@app.route('/apache_form')
def apache_form():
    return render_template('apache_form.html')

@app.route('/run_pfsense', methods=['POST'])
def run_pfsense():
    start_time = time.time()
    target_ip = request.form['target_ip']
    if not is_valid_ip(target_ip):
        return render_template('message.html', message="Invalid IP address format.")
    logger.info(f"Running pfsense exploit on {target_ip}")
    result = pfsense_exploit(target_ip)
    if isinstance(result, str) and not os.path.exists(result):
        logger.error(f"Error during pfsense exploit: {result}")
        return render_template('message.html', message=result)

    report_path = generate_report_pfsense(target_ip, "pfsense/scan.txt", "pfsense/poc.txt")
    with open(report_path, 'rb') as report_stream:
        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"Process completed in {elapsed_time} seconds.")
        return send_file(report_stream, as_attachment=True, download_name="pentest_report_pfsense.pdf")

@app.route('/run_winbox', methods=['POST'])
def run_winbox():
    start_time = time.time()
    choice = request.form['choice']
    target_ip = request.form['target_ip']
    if not is_valid_ip(target_ip):
        return render_template('message.html', message="Invalid IP address format.")
    logger.info(f"Running winbox exploit with choice {choice} on {target_ip}")
    result = winbox_exploit(choice, target_ip)
    if isinstance(result, str) and not os.path.exists(result):
        logger.error(f"Error during winbox exploit: {result}")
        return render_template('message.html', message=result)

    report_path = generate_report_mikrotik(target_ip, "mikrotik/scan.txt", "mikrotik/poc.txt")
    with open(report_path, 'rb') as report_stream:
        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"Process completed in {elapsed_time} seconds.")
        return send_file(report_stream, as_attachment=True, download_name="pentest_report_winbox.pdf")

@app.route('/run_apache', methods=['POST'])
def run_apache():
    total_start_time = time.time()
    process_times = {}

    # Initialization
    start_time = time.time()
    vulnerability = request.form['vulnerability']
    target_ip = request.form['target_ip']
    if not is_valid_ip(target_ip):
        return render_template('message.html', message="Invalid IP address format.")
    target_port = request.form.get('target_port', None)
    logger.info(f"Running Apache exploit on {target_ip}:{target_port} with vulnerability {vulnerability}")
    process_times['Initialization'] = time.time() - start_time
    logger.info(f"Initialization time: {process_times['Initialization']} seconds")

    # Nmap Scan
    start_time = time.time()
    scan_result = run_nmap_scan(target_ip, target_port)
    process_times['Nmap Scan'] = time.time() - start_time
    logger.info(f"Nmap scan result: {scan_result}")
    logger.info(f"Nmap Scan time: {process_times['Nmap Scan']} seconds")

    # Filter Apache Services
    start_time = time.time()
    scan_result = filter_apache_services(scan_result)
    process_times['Filter Apache Services'] = time.time() - start_time
    logger.info(f"Filtered Apache scan result: {scan_result}")
    logger.info(f"Filter Apache Services time: {process_times['Filter Apache Services']} seconds")

    # Find Apache Ports
    start_time = time.time()
    apache_ports = find_apache_ports(scan_result)
    process_times['Find Apache Ports'] = time.time() - start_time
    logger.info(f"Found Apache ports: {apache_ports}")
    logger.info(f"Find Apache Ports time: {process_times['Find Apache Ports']} seconds")

    # Vulnerability Check
    start_time = time.time()
    findings = ""
    for port in apache_ports:
        url = f"http://{target_ip}:{port}"
        logger.info(f"Checking vulnerabilities on {url}")
        if vulnerability == 'pt':
            findings += pathTraversal(url)
        elif vulnerability == 'rce':
            findings += RCE(url)
        elif vulnerability == 'both':
            findings += pathTraversal(url)
            findings += RCE(url)
    process_times['Vulnerability Check'] = time.time() - start_time
    logger.info(f"Vulnerability findings: {findings}")
    logger.info(f"Vulnerability Check time: {process_times['Vulnerability Check']} seconds")

    # Generate Report
    start_time = time.time()
    ugm_logo_path = "static/Logo Horizontal.png"
    tri_logo_path = "static/tri.png"
    report_path = generate_report_apache(scan_result, findings, ugm_logo_path, tri_logo_path)
    process_times['Generate Report'] = time.time() - start_time
    logger.info(f"Generate Report time: {process_times['Generate Report']} seconds")

    total_elapsed_time = time.time() - total_start_time
    logger.info(f"Process completed in {total_elapsed_time} seconds.")

    if not report_path:
        logger.error("Error generating report.")
        return render_template('message.html', message="Error generating report.")

    # Construct the success message without individual process times
    success_message = f"Report successfully generated in {total_elapsed_time:.2f} seconds. You can download it below.<br>"

    download_path = url_for('static', filename='output/Penetration_Test_Report_Apache.docx')
    return render_template('message.html', message=success_message, download_path=download_path)

if __name__ == '__main__':
    app.run(debug=True)
