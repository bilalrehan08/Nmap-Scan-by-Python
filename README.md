# Nmap-Scan-by-Python
This Python-based Nmap Scanner allows users to perform different types of scans (SYN, UDP, Comprehensive) on a given IP address using the nmap library. It provides port status, service names, and helps in basic network reconnaissance. Ideal for beginners learning about networking and ethical hacking.
# 🔍 Nmap Scanner Tool

A simple and beginner-friendly Python project that uses the `nmap` library to scan networks and gather information about open ports, services, and operating systems. This tool provides an interactive interface to perform different types of scans including:

- SYN Scan
- UDP Scan
- Comprehensive Scan

## 📌 About the Project

This tool is a basic implementation of port scanning using Python and Nmap. It helps users, especially those new to cybersecurity or ethical hacking, to understand how network scanning works. The tool takes an IP address as input and allows the user to select a scan type to identify open ports and services running on the target system.

## ⚙️ Features

- Detects open ports and services.
- Performs TCP SYN scans, UDP scans, and detailed comprehensive scans.
- Uses the `nmap` Python module for easy scanning.
- Simple text-based interface.

## ✅ Requirements

Before running the tool, make sure you have the following installed:

### 1. Python 3
You can download Python from: https://www.python.org/downloads/

### 2. Nmap (must be installed and added to system PATH)
- Download Nmap: https://nmap.org/download.html
- Ensure `nmap` is added to your environment variables so it can be found in the system PATH.

### 3. Python Module: `python-nmap`
Install it using pip:

```bash
pip install python-nmap
🚀 How to Use
Clone or download the repository.

Make sure nmap is installed on your system.

Run the script:

bash
Copy
Edit
python nmap_scanner.py
Enter the target IP address.

Choose the scan type:

1 for SYN Scan

2 for UDP Scan

3 for Comprehensive Scan

Wait for the scan to complete and view the results.

⚠️ Disclaimer
This tool is intended for educational purposes only. Use it only on systems you own or have explicit permission to scan
