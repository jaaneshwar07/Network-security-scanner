import socket
import sys
from datetime import datetime

# 1. Define common network ports and their associated security risks
VULNERABILITY_DATABASE = {
    21: "FTP (File Transfer Protocol) - Vulnerable to cleartext credential sniffing.",
    22: "SSH (Secure Shell) - Secure, but target for brute-force access attempts.",
    23: "Telnet - Highly insecure! Data and passwords transmitted in cleartext.",
    80: "HTTP - Unencrypted web traffic. Susceptible to MitM (Man-in-the-Middle) attacks.",
    443: "HTTPS - Encrypted web traffic. Generally secure."
}

def scan_host(target_host):
    try:
        # Resolve target hostname to IP address
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"\n[!] Error: Hostname '{target_host}' could not be resolved.")
        sys.exit()

    # Create a unique, clean log file to save results
    log_filename = f"scan_report_{target_ip}.txt"
    
    with open(log_filename, "w") as report:
        # Write Report Header
        report.write("="*60 + "\n")
        report.write(f"DEVSECOPS NETWORK SECURITY SCAN REPORT\n")
        report.write(f"Target Host : {target_host} ({target_ip})\n")
        report.write(f"Scan Time   : {str(datetime.now())}\n")
        report.write("="*60 + "\n\n")
        
        print(f"\n[*] Initiating secure scan on target: {target_ip}")
        print(f"[*] Report will be compiled in: {log_filename}\n")

        # 2. Iterate through the target ports
        for port, risk_description in VULNERABILITY_DATABASE.items():
            # Establish a stream socket connection (TCP)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a tight timeout so the script runs incredibly fast
            s.settimeout(1.0)
            
            # Attempt to connect to the target port
            result = s.connect_ex((target_ip, port))
            
            if result == 0:
                log_line = f"[+] PORT {port}: OPEN | Risk Level: High | Info: {risk_description}\n"
                print(f"\033[91m{log_line.strip()}\033[0m") # Prints in red in terminal
                report.write(log_line)
            else:
                log_line = f"[-] PORT {port}: CLOSED\n"
                report.write(log_line)
                
            s.close()
            
        report.write("\n" + "="*60 + "\n")
        report.write("Scan fully completed. Infrastructure audit successful.\n")

if __name__ == "__main__":
    # Test the scanner safely against localhost or a secure target
    # You can change 'localhost' to any test server IP address
    target = "localhost" 
    scan_host(target)
