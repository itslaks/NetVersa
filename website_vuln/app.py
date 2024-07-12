from flask import Flask, request, render_template, jsonify
import requests
import base64
import socket
import re
import subprocess
import traceback
import time
import ipaddress
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# VirusTotal configuration
VIRUSTOTAL_API_KEY = '4b4ae68cf38ed487342818091ad6ea879d11207e57049616f55fcd5c869233f9'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls'

# IPinfo configuration
IPINFO_API_KEY = "8e6847c71ee1d7"

# Nmap scan type definitions
SCAN_TYPES = {
    'intense_scan': '-T4 -A -v',
    'ping_scan': '-sn',
    'quick_scan_plus': '-sV -T4 -O -F --version-light',
    'regular_scan': '',
    'slow_scan': '-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"',
    'quick_scan': '-T4 -F',
    'tcp_connect_scan': '-sT',
    'syn_scan': '-sS',
    'udp_scan': '-sU',
    'ack_scan': '-sA',
    'window_scan': '-sW',
    'xmas_scan': '-sX',
    'null_scan': '-sN',
    'idle_scan': '-sI',
    'ip_protocol_scan': '-sO',
    'service_version_scan': '-sV',
    'default_script_scan': '-sC',
    'os_detection_scan': '-O',
    'trace_route_scan': '--traceroute',
    'list_scan': '-sL',
    'dns_scan': '-sS -p 53',
    'fragmentation_scan': '-f',
    'ipv6_scan': '-6',
    'min_rate': '--min-rate <num>',
    'max_rate': '--max-rate <num>'
}

@app.route('/')
def home():
    return render_template('index.html', scan_types=SCAN_TYPES)

# VirusTotal Functions
def scan_with_virustotal(url):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.post(VIRUSTOTAL_URL, headers=headers, data={'url': url})
    if response.status_code == 200:
        analysis_response = requests.get(f"{VIRUSTOTAL_URL}/{url_id}", headers=headers)
        if analysis_response.status_code == 200:
            return analysis_response.json()
        else:
            return {'error': f'Error fetching analysis: {analysis_response.status_code} {analysis_response.reason}'}
    else:
        return {'error': f'Error scanning website: {response.status_code} {response.reason}'}

def optimize_results(results):
    if 'error' in results:
        return {'error': results['error']}

    positives = []
    negatives = []
    scans = results.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
    for scan, result in scans.items():
        if result['category'] == 'malicious':
            positives.append(f"{scan}: {result['result']}")
        else:
            negatives.append(f"{scan}: {result['result']}")

    return {
        'positives': positives,
        'negatives': negatives
    }

@app.route('/virustotal_scan', methods=['POST'])
def virustotal_scan():
    website = request.form['website']
    if not website:
        return jsonify({'error': 'Website URL or domain is required'}), 400

    scan_results = scan_with_virustotal(website)
    if 'error' in scan_results:
        return jsonify(scan_results), 500

    optimized_results = optimize_results(scan_results)
    return jsonify(optimized_results)

# NSLOOKUP Functions
def is_valid_domain(domain):
    regex = re.compile(
        r'^(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)$', re.IGNORECASE)
    return re.match(regex, domain) is not None

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def get_ip_info(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json?token={IPINFO_API_KEY}"
    response = requests.get(url)
    return response.json()

@app.route('/nslookup', methods=['POST'])
def nslookup():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[-1].split("/")[0].split('?')[0]
    
    if is_valid_domain(domain):
        ip_address = get_ip_address(domain)
        if ip_address:
            ip_info = get_ip_info(ip_address)
            return jsonify({
                "message": f"The IP address of {domain} is {ip_address}",
                "ip_info": ip_info
            })
        else:
            return jsonify({"message": f"Could not retrieve the IP address for {domain}"}), 400
    else:
        return jsonify({"message": "Invalid URL or domain. Please enter a valid website URL or domain name."}), 400

# Nmap Functions
def run_nmap_scan(ip_address, scan_types):
    try:
        command = ["nmap"]

        for scan_type in scan_types:
            if scan_type in SCAN_TYPES:
                command.append(SCAN_TYPES[scan_type])

        command.append(ip_address)

        app.logger.info(f"Running command: {' '.join(command)}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        timeout = 60
        start_time = time.time()
        while process.poll() is None:
            if time.time() - start_time > timeout:
                process.kill()
                app.logger.error(f"Process killed due to timeout for IP: {ip_address}")
                return {"error": "Nmap scan timed out after 60 seconds"}
            time.sleep(0.1)

        output, error = process.communicate()

        if process.returncode != 0:
            app.logger.error(f"Nmap command failed with return code {process.returncode}. Error: {error}")
            return {"error": f"Nmap command failed with return code {process.returncode}. Error: {error}"}
        if not output.strip():
            app.logger.error("No output from nmap command")
            return {"error": "No output from nmap command"}

        app.logger.info(f"Nmap scan completed successfully for IP: {ip_address}")
        return {"result": output}
    except subprocess.SubprocessError as e:
        app.logger.error(f"Subprocess error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return {"error": f"A subprocess error occurred: {str(e)}"}
    except Exception as e:
        app.logger.error(f"Exception occurred: {str(e)}")
        app.logger.error(traceback.format_exc())
        return {"error": f"An unexpected error occurred: {str(e)}"}

@app.route('/nmap_scan', methods=['POST'])
def nmap_scan():
    data = request.json
    ip_address = data.get('ip_address')
    scan_types = data.get('scan_types', [])

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        app.logger.error(f"Invalid IP address: {ip_address}")
        return jsonify({"error": "Invalid IP address"}), 400

    if not scan_types:
        app.logger.error("No scan types selected")
        return jsonify({"error": "No scan types selected"}), 400

    app.logger.info(f"Received scan request for IP: {ip_address}, Types: {scan_types}")

    results = run_nmap_scan(ip_address, scan_types)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)