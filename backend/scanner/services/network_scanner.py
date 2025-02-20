import logging
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
import socket

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

if __name__ == "__main__":
    main()
