#!/bin/bash

# Cek argumen
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <path_to_memory_raw> <volatility_output_directory> [dump]"
  echo "       'dump' (optional) = yes untuk melakukan dump memory, default no"
  exit 1
fi

MEMORY_FILE="$1"
OUTPUT_DIR="${2%/}"
DUMP_MEMORY="no"
if [[ "$3" == "yes" ]]; then
  DUMP_MEMORY="yes"
fi

REPORT_FILE="$OUTPUT_DIR/report_analisis_memory.txt"

# Validasi file output yang dibutuhkan
echo "[+] Validating required output files..."
required_files=("windows_malfind_" "windows_pslist_" "windows_pstree_" "windows_cmdline_" "windows_netstat_" "windows_netscan_" "windows_svcscan_" "windows_pslist_" "windows_psscan_")
for prefix in "${required_files[@]}"; do
  file_path=$(ls "$OUTPUT_DIR"/${prefix}*.txt 2>/dev/null | head -n1)
  if [[ -z "$file_path" ]]; then
    echo "Error: Missing file with prefix '${prefix}' in '$OUTPUT_DIR'"
    exit 1
  fi
  echo "[OK] Found file: $file_path"
done

MALFIND_FILE=$(ls "$OUTPUT_DIR"/windows_malfind_*.txt | head -n1)
PSLIST_FILE=$(ls "$OUTPUT_DIR"/windows_pslist_*.txt | head -n1)
PSTREE_FILE=$(ls "$OUTPUT_DIR"/windows_pstree_*.txt | head -n1)
CMDLINE_FILE=$(ls "$OUTPUT_DIR"/windows_cmdline_*.txt | head -n1)
NETSTAT_FILE=$(ls "$OUTPUT_DIR"/windows_netstat_*.txt | head -n1)
NETSCAN_FILE=$(ls "$OUTPUT_DIR"/windows_netscan_*.txt | head -n1)
SERVICESCAN_FILE=$(ls "$OUTPUT_DIR"/windows_svcscan_*.txt | head -n1)
PSSCAN_FILE=$(ls "$OUTPUT_DIR"/windows_psscan_*.txt | head -n1)


# mengabaikan baris Volatility dan warning, ambil baris pertama dengan lebih dari satu kolom (anggap sebagai header).
get_header() {
  local file="$1"
  grep -vE '^(Volatility|WARNING)' "$file" | awk 'NF > 1 { print; exit }'
}


echo "[+] Extracting PIDs with PAGE_EXECUTE_READWRITE..."
PIDS=$(grep -E '^[1-9][0-9]*' "$MALFIND_FILE" | awk '$6 == "PAGE_EXECUTE_READWRITE" {print $1}' | sort -u)

# Step 1
echo "[1/11] Writing Identifying Injected Code section..."
{
  echo "Identifying Injected Code (Process with PAGE_EXECUTE_READWRITE permissions)"
  echo "$PIDS"
  echo
} > "$REPORT_FILE"

# Step 2 - pslist
echo "[2/11] Writing Identifying Running Processes section..."
{
  echo "Identifying Running Processes"
  get_header "$PSLIST_FILE"
  for pid in $PIDS; do
    grep -E "^$pid[[:space:]]" "$PSLIST_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 3 - pstree
echo "[3/11] Writing Identifying Running Processes (Check parent process ID) section..."
{
  echo "Identifying Running Processes (Check parent process ID)"
  get_header "$PSTREE_FILE"
  for pid in $PIDS; do
    grep -E "^$pid[[:space:]]" "$PSTREE_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 4 - cmdline
echo "[4/11] Writing Identifying Command Line Arguments section..."
{
  echo "Identifying Command Line Arguments"
  get_header "$CMDLINE_FILE"
  for pid in $PIDS; do
    grep -E "^$pid[[:space:]]" "$CMDLINE_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 5 - DLL list
echo "[5/11] Writing Identifying Loaded DLLs section..."
{
  echo "Identifying Loaded DLLs"
  for pid in $PIDS; do
    echo -e "\nDLLs for PID $pid"
    vol -q -f "$MEMORY_FILE" windows.dlllist --pid "$pid"
  done
  echo
} >> "$REPORT_FILE"

# Step 6 - Handles
echo "[6/11] Writing Identifying Handles section..."
{
  echo "Identifying Handles"
  for pid in $PIDS; do
    echo -e "\nHandles for PID $pid"
    vol -q -f "$MEMORY_FILE" windows.handles --pid "$pid"
  done
  echo
} >> "$REPORT_FILE"


# Step 7 - netstat
echo "[7/11] Writing Network Connections (Netstat) section..."
{
  echo "Network Connections (Netstat)"
  get_header "$NETSTAT_FILE"
  for pid in $PIDS; do
    grep -E "[[:space:]]$pid[[:space:]]" "$NETSTAT_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 8 - netscan
echo "[8/1]1 Writing Network Connections (Netscan) section..."
{
  echo "Network Connections (Netscan)"
  get_header "$NETSCAN_FILE"
  for pid in $PIDS; do
    grep -E "[[:space:]]$pid[[:space:]]" "$NETSCAN_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 9 - svcscan
echo "[9/11] Writing Service Scan (svcscan) section..."
{
  echo "Service Scan (svcscan)"
  get_header "$SERVICESCAN_FILE"
  for pid in $PIDS; do
    grep -E "[[:space:]]$pid[[:space:]]" "$SERVICESCAN_FILE"
  done
  echo
} >> "$REPORT_FILE"


# Step 10 - psscan & pslist
echo "[10/11] Writing rootkit detection section..."
{
  echo "Rootkit detection using psscan vs pslist"
  # Ekstrak PID, PPID, ImageFileName dari file
  TMP_PSLIST=$(mktemp)
  TMP_PSSCAN=$(mktemp)
  
  grep -E '^[0-9]+\s+[0-9]+\s+\S+' "$PSLIST_FILE" | awk '{print $1, $2, $3}' | sort > "$TMP_PSLIST"
  grep -E '^[0-9]+\s+[0-9]+\s+\S+' "$PSSCAN_FILE" | awk '{print $1, $2, $3}' | sort > "$TMP_PSSCAN"
  
  # Tampilkan proses yang hanya muncul di psscan
  echo "Proses mencurigakan (hanya di psscan, kemungkinan hidden):"
  comm -13 "$TMP_PSLIST" "$TMP_PSSCAN"
  
  echo ""
  echo "Proses hanya di pslist (tidak di psscan, anomali langka):"
  comm -23 "$TMP_PSLIST" "$TMP_PSSCAN"
  
  # Hapus file sementara
  rm -f "$TMP_PSLIST" "$TMP_PSSCAN"
} >> "$REPORT_FILE"

# Step 11 - memory dump (optional)
if [[ "$DUMP_MEMORY" == "yes" ]]; then
  echo "[+] Performing memory dump for all detected PIDs..."
  for pid in $PIDS; do
    vol -q -f "$MEMORY_FILE" windows.memmap --pid "$pid" --dump -o "$OUTPUT_DIR"
  done
  echo "[+] Memory dump completed."
else
  echo "[!] Skipping memory dump (not requested)."
fi

echo "[✓] Analysis complete. Report written to: $REPORT_FILE"
