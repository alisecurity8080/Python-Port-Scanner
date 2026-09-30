import socket
import requests

# Target domain and core high-risk security ports
target_host = input("Enter target domain or IP (e.g., example.com): ")
ports_to_scan = [
    21,    # FTP (File Transfer)
    22,    # SSH (Remote Terminal)
    80,    # HTTP (Unencrypted Web)
    443,   # HTTPS (Secure Web)
    3306,  # MySQL Database
    5432,  # PostgreSQL Database
    6379,  # Redis Cache (Unauthenticated access risk)
    8000,  # Dev / Staging Web Server
    8080,  # Alternative HTTP / Admin Panels
    8443   # Alternative HTTPS / Management Consoles
]

print(f"\n[+] Starting Reconnaissance on Target: {target_host}")

try:
    # Resolve domain to IP Address (DNS Lookup)
    target_ip = socket.gethostbyname(target_host)
    print(f"[+] Target IP Resolved: {target_ip}\n")
    print("-" * 45)

    # Scan targeted ports
    for port in ports_to_scan:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)  # Timeout if no response
        
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            print(f"[!] Port {port:<5} : OPEN")
        else:
            print(f"[-] Port {port:<5} : CLOSED / FILTERED")
            
        s.close()

except socket.gaierror:
    print("[-] Error: Hostname could not be resolved.")
except Exception as e:
    print(f"[-] Error: {e}")

# Verification test via HTTP Bin
print("\n[+] Checking outbound connectivity via httpbin...")
try:
    response = requests.get("https://httpbin.org/get", timeout=5)
    print(f"[+] HTTP Status: {response.status_code}")
except Exception as e:
    print(f"[-] Request failed: {e}")
