#!/bin/bash

# Simple Memory Parser Script
# Description: Extracts unique IPs, emails, and command references from a memory dump using strings and grep.

print_help() {
    echo "Usage: $0 <memory_file.vmem>"
    echo
    echo "Extracts the following from a memory dump:"
    echo "  - IPv4 addresses     -> ipv4_<filename>.txt"
    echo "  - Email addresses    -> email_<filename>.txt"
    echo "  - Command references -> command_<filename>.txt"
    echo
    echo "Example:"
    echo "  $0 /home/user/Win7-2515534d.vmem"
    exit 1
}

# Check arguments
if [[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]]; then
    print_help
fi

MEM_FILE="$1"

if [[ ! -f "$MEM_FILE" ]]; then
    echo "Error: File '$MEM_FILE' not found."
    exit 1
fi

# Get base filename without path or extension
BASENAME=$(basename "$MEM_FILE" .vmem)

echo "[*] Analyzing: $MEM_FILE"

# Extract IPv4 addresses
echo "[+] Extracting IPv4 addresses..."
strings "$MEM_FILE" | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq > "ipv4_${BASENAME}.txt"

# Extract email addresses
echo "[+] Extracting email addresses..."
strings "$MEM_FILE" | grep -oE "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b" | sort | uniq > "email_${BASENAME}.txt"

# Extract command invocations
echo "[+] Extracting command references (cmd, powershell, bash)..."
strings "$MEM_FILE" | grep -E "(cmd|powershell|bash)[^\s]+" | sort | uniq > "command_${BASENAME}.txt"

echo "[✓] Done! Output files:"
echo "    ipv4_${BASENAME}.txt"
echo "    email_${BASENAME}.txt"
echo "    command_${BASENAME}.txt"
