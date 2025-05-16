#!/usr/bin/python3

import nmap

def display_welcome():
    print("""
    ****************************************
    *        Nmap Scanner Project          *
    ****************************************
    """)

def get_ip_address():
    return input("Please Enter the IP Address to Scan: ").strip()

def get_scan_type():
    print('''\nChoose the type of scan to perform:
    1. SYN Scan (TCP)
    2. UDP Scan
    3. Comprehensive Scan''')
    return input("Choose (1/2/3): ").strip()

def perform_scan(ip_addr, scan_type):
    sc = nmap.PortScanner()
    scan_options = {
        '1': ['-sS -sV -Pn', 'tcp'],  # SYN Scan with version detection
        '2': ['-sU -sV -Pn', 'udp'],  # UDP Scan with version detection
        '3': ['-sS -sV -p- -O -sC -Pn', 'tcp']  # Full scan with scripts and OS detection
    }

    if scan_type not in scan_options:
        print("Invalid option. Please restart and choose a valid scan type.")
        return

    print("\n[+] Nmap Version:", sc.nmap_version())
    print("[+] Scanning in progress...")

    try:
        sc.scan(ip_addr, arguments=scan_options[scan_type][0])
        if ip_addr in sc.all_hosts():
            print("\n[+] Host is Up. Scan Results:")
            proto = scan_options[scan_type][1]
            if proto in sc[ip_addr].all_protocols():
                print(f"\n{'Port':<10}{'Service':<20}{'State':<10}")
                print("-" * 40)
                for port, info in sc[ip_addr][proto].items():
                    print(f"{port:<10}{info['name']:<20}{info['state']:<10}")
            else:
                print("[!] No open ports found.")
        else:
            print("[!] Host is down or unreachable.")
    except Exception as e:
        print(f"[!] Error during scan: {e}")

def main():
    display_welcome()
    ip_addr = get_ip_address()
    scan_type = get_scan_type()
    perform_scan(ip_addr, scan_type)

if __name__ == "__main__":
    main()
