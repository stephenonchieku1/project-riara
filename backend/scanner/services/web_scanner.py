import logging
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
import socket
import requests
from bs4 import BeautifulSoup
import zapv2

# Configure logging
logging.basicConfig(filename='network_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def scan_ip(ip):
    """
    Scan the given IP address for open ports.
    Args:
        ip (str): The IP address to scan.
    Returns:
        dict: A dictionary of open ports and corresponding services.
    """
    open_ports = {}
    try:
        for port in range(1, 1025):  # Scanning ports from 1 to 1024
            pkt = IP(dst=ip) / TCP(dport=port, flags='S')
            response = scapy.sr1(pkt, timeout=1, verbose=0)
            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK received
                try:
                    service = socket.getservbyport(port)
                except socket.error:
                    service = 'Unknown'
                open_ports[port] = service
                logging.info(f'Open port found: {port}, Service: {service}')
            # Send RST to close the connection
            scapy.sr(IP(dst=ip)/TCP(dport=port, flags='R'), timeout=1, verbose=0)
    except Exception as e:
        logging.error(f'Error scanning IP {ip}: {e}')
    return open_ports

def detect_vulnerabilities(ip, open_ports):
    """
    Analyze the open ports and detect potential vulnerabilities.
    Args:
        ip (str): The IP address being scanned.
        open_ports (dict): A dictionary of open ports and services.
    Returns:
        list: A list of potential vulnerabilities detected.
    """
    vulnerabilities = []
    try:
        for port, service in open_ports.items():
            # Example vulnerability detection for demonstration purposes
            if service.lower() in ['ftp', 'telnet', 'http']:  # Known insecure services
                vulnerabilities.append((port, service))
                logging.warning(f'Potential vulnerability detected on {ip} - Port: {port}, Service: {service}')
    except Exception as e:
        logging.error(f'Error detecting vulnerabilities for IP {ip}: {e}')
    return vulnerabilities

def web_scan(target_url):
    """
    Perform web application scanning using Beautiful Soup and OWASP ZAP API.
    Args:
        target_url (str): The target URL to scan.
    Returns:
        list: A list of detected vulnerabilities.
    """
    vulnerabilities = []
    try:
        # Basic XSS detection using Beautiful Soup
        response = requests.get(target_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if '<script>' in script.text.lower():
                vulnerabilities.append('Potential XSS vulnerability found')
                logging.warning(f'Potential XSS vulnerability detected on {target_url}')
        
        # Using OWASP ZAP API for advanced vulnerability scanning
        zap = zapv2.ZAPv2()
        zap.urlopen(target_url)
        zap.ascan.scan(target_url)
        
        while int(zap.ascan.status()) < 100:
            # Wait for the scan to complete
            pass
        
        alerts = zap.core.alerts(baseurl=target_url)
        for alert in alerts:
            vulnerabilities.append(alert['alert'])
            logging.warning(f"OWASP ZAP detected vulnerability: {alert['alert']} on {target_url}")
    except Exception as e:
        logging.error(f'Error performing web scan on {target_url}: {e}')
    return vulnerabilities

def main():
    target_ip = input("Enter the target IP address: ")
    logging.info(f'Starting scan on IP: {target_ip}')
    open_ports = scan_ip(target_ip)
    if open_ports:
        print(f"Open Ports: {open_ports}")
    else:
        print("No open ports detected.")
    
    vulnerabilities = detect_vulnerabilities(target_ip, open_ports)
    if vulnerabilities:
        print("Potential Vulnerabilities Detected:")
        for port, service in vulnerabilities:
            print(f"- Port {port} ({service}) is vulnerable.")
    else:
        print("No vulnerabilities detected.")
    
    # Web scanning
    target_url = input("Enter the target URL for web scanning: ")
    logging.info(f'Starting web scan on URL: {target_url}')
    web_vulnerabilities = web_scan(target_url)
    if web_vulnerabilities:
        print("Web Vulnerabilities Detected:")
        for vulnerability in web_vulnerabilities:
            print(f"- {vulnerability}")
    else:
        print("No web vulnerabilities detected.")

if __name__ == "__main__":
    main()


