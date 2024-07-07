import os
import re
from docx import Document
from docx.shared import Pt, Cm, Inches
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
from datetime import date
import logging

# Set up logging
logging.basicConfig(
    filename='generate_report.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s'
)

def sanitize_text(text):
    # Replace non-XML-compatible characters with a placeholder
    return re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '?', text)

def add_header(document):
    try:
        # Add Header
        header_section = document.sections[0]
        header = header_section.header
        header_paragraph = header.paragraphs[0]
        header_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT
        # Add the logo
        logo_path = "static/Logo Horizontal.png"  # Ensure the path is correct
        logo_height = Cm(1.5)
        run = header_paragraph.add_run()
        run.add_picture(logo_path, height=logo_height)
        # Add space after header
        header.add_paragraph()
        logging.info("Header added successfully.")
    except Exception as e:
        logging.error(f"Error adding header: {e}")

def create_cover_page(document):
    try:
        add_header(document)
        # Add the logo image
        document.add_picture('static/tri.png', width=Inches(2))  # Ensure the path is correct
        document.paragraphs[-1].alignment = 1  # Center align the image
        # Add spacer
        document.add_paragraph()
        document.paragraphs[-1].add_run().add_break()
        while len(document.paragraphs) % 4 != 0:
            document.add_paragraph()
        title = "Sample Penetration Test Report Apache HTTP Server"
        document.add_heading(title, level=0).alignment = 1  # Center align the text
        # Add spacer
        document.add_paragraph()
        document.paragraphs[-1].add_run().add_break()
        while len(document.paragraphs) % 14 != 0:
            document.add_paragraph()
        # Add details
        text = f"""
        Date: {date.today().strftime('%d %B %Y')}
        Version 1.0"""
        document.add_paragraph(text)
        logging.info("Cover page created successfully.")
    except Exception as e:
        logging.error(f"Error creating cover page: {e}")

def generate_report(scan_result, findings, ugm_logo_path, tri_logo_path):
    try:
        output_dir = os.path.join("static", "output")
        os.makedirs(output_dir, exist_ok=True)
        document = Document()

        create_cover_page(document)

        # Introduction
        document.add_heading('Introduction', level=1)
        introduction = (
            "This is a pentesting report for Apache HTTP Server vulnerabilities. "
            "The vulnerabilities addressed in this report include Path Traversal and Remote Code Execution. "
            "The impact of these vulnerabilities includes unauthorized access to the server, data theft, and potential network compromise. "
            "It is crucial to address these vulnerabilities promptly to protect the security and integrity of the network infrastructure."
        )
        paragraph = document.add_paragraph(introduction)
        paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY

        # Findings
        document.add_heading('Findings', level=1)
        document.add_heading('Nmap Scan Results', level=2)
        document.add_paragraph(sanitize_text(scan_result))

        document.add_heading('Vulnerability Exploitation Results', level=2)
        document.add_paragraph(sanitize_text(findings))

        # Recommendation
        document.add_heading('Recommendation', level=1)
        recommendation = (
            "To mitigate the identified vulnerabilities (CVE-2021-42013 and CVE-2021-41773), it is recommended to take the following steps:\n"
            "1. Update Apache HTTP Server:\n"
            "   - Upgrade to the latest version of Apache HTTP Server where these vulnerabilities have been patched.\n"
            "   - Regularly apply updates and patches from the Apache Software Foundation.\n"
            "2. Configure the Server Securely:\n"
            "   - Disable the use of vulnerable modules such as mod_cgi, unless absolutely necessary.\n"
            "   - Restrict access to the server by configuring the `Directory` settings correctly. For example, use `Options -Indexes` and `Require all denied` to restrict unauthorized access.\n"
            "3. Employ Web Application Firewalls (WAF):\n"
            "   - Use a WAF to detect and block malicious requests that may exploit path traversal and RCE vulnerabilities.\n"
            "4. Regular Security Audits:\n"
            "   - Conduct regular security audits and vulnerability assessments to identify and address potential security issues.\n"
            "5. Logging and Monitoring:\n"
            "   - Enable detailed logging and regularly monitor logs for suspicious activity.\n"
            "   - Use intrusion detection systems (IDS) and intrusion prevention systems (IPS) to monitor and protect against exploits.\n"
            "6. Access Controls:\n"
            "   - Implement strong access controls to limit who can modify the server configuration and execute scripts.\n"
            "7. Input Validation:\n"
            "   - Implement strict input validation to ensure that user input is sanitized and validated before processing.\n"
            "By following these recommendations, the risk associated with CVE-2021-42013 and CVE-2021-41773 can be significantly reduced, helping to ensure the security and integrity of the Apache HTTP Server."
        )
        paragraph = document.add_paragraph(recommendation)
        paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT

        # Save the report as a DOCX
        docx_report_path = os.path.join(output_dir, "Penetration_Test_Report_Apache.docx")
        document.save(docx_report_path)
        logging.info(f"DOCX report saved at {docx_report_path}")

        return docx_report_path
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        return None
