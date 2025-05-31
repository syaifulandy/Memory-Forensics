#!/bin/bash

# Cek argumen
if [[ $# -lt 2 || $# -gt 4 ]]; then
  echo "Usage: $0 <path_to_memory_raw> <volatility_output_directory> [dump] [extra_pid]"
  echo "       'dump' (optional)     = yes untuk melakukan dump memory, default no"
  echo "       'extra_pid' (optional)= PID tambahan untuk dianalisis"
  exit 1
fi

MEMORY_FILE="$1"
OUTPUT_DIR="${2%/}"
DUMP_MEMORY="no"
EXTRA_PID=""

if [[ "$3" == "yes" ]]; then
  DUMP_MEMORY="yes"
elif [[ "$3" =~ ^[0-9]+$ ]]; then
  EXTRA_PID="$3"
elif [[ -n "$3" ]]; then
  echo "Argumen ketiga harus 'yes' untuk dump atau PID (angka)."
  exit 1
fi

if [[ "$4" =~ ^[0-9]+$ ]]; then
  EXTRA_PID="$4"
elif [[ -n "$4" ]]; then
  echo "Argumen keempat harus PID (angka)."d
  exit 1
fi

# Ambil nama file tanpa path dan tanpa ekstensi
BASENAME=$(basename "$MEMORY_FILE")          # misal: Win7.vmem
NAME="${BASENAME%.*}"                         # misal: Win7

# Buat nama report dinamis
REPORT_FILE="$OUTPUT_DIR/report_${NAME}_analisis_memory.txt"


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
HANDLES_FILE=$(ls "$OUTPUT_DIR"/windows_handles_*.txt | head -n1)
DLLLIST_FILE=$(ls "$OUTPUT_DIR"/windows_dlllist_*.txt | head -n1)

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


# Step 2 - psscan & pslist
echo "[2/11] Writing rootkit detection section..."
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

  # Simpan hasil pid dari hasil analisis rootkit
  HIDDEN_PIDS=$(comm -13 "$TMP_PSLIST" "$TMP_PSSCAN" | awk '{print $1}')
  ORPHAN_PIDS=$(comm -23 "$TMP_PSLIST" "$TMP_PSSCAN" | awk '{print $1}')
  
  # Gabungkan semua PID dan buat unik
  PIDS=$(echo -e "$PIDS\n$HIDDEN_PIDS\n$ORPHAN_PIDS" | sort -u)

  # Gabungkan Extra PID klo ada
  if [[ -n "$EXTRA_PID" ]]; then
    PIDS=$(echo -e "$PIDS\n$EXTRA_PID" | sort -u)
  fi

  # Hapus file sementara
  rm -f "$TMP_PSLIST" "$TMP_PSSCAN"
} >> "$REPORT_FILE"

# Step 3 - pslist
echo "[3/11] Writing Identifying Running Processes section..."
{
  echo
  echo
  echo "Identifying Running Processes"
  get_header "$PSLIST_FILE"
  for pid in $PIDS; do
    line=$(grep -E "^$pid[[:space:]]" "$PSLIST_FILE")
    if [ -n "$line" ]; then
      echo "$line"
      ppid=$(echo "$line" | awk '{print $2}')
      PIDS=$(echo -e "$PIDS\n$ppid" | sort -u)
    fi
  done
  echo
} >> "$REPORT_FILE"


# Step 4 - pstree
echo "[4/11] Writing Identifying Running Processes (Check parent process ID) section..."
{
  echo "Identifying Running Processes (Check parent process ID)"
  get_header "$PSTREE_FILE"

  PRINTED_PIDS=""

  for pid in $PIDS; do
    # Cari baris induk (tanpa *)
    base_line=$(grep -E "^$pid[[:space:]]" "$PSTREE_FILE")

    if [ -n "$base_line" ]; then
      this_pid=$(echo "$base_line" | awk '{print $1}')
      if ! grep -qw "$this_pid" <<< "$PRINTED_PIDS"; then
        echo "$base_line"
        PRINTED_PIDS="$PRINTED_PIDS $this_pid"
      fi

      # Ambil semua anak berdasarkan struktur pohon (*, **, dll)
      found=0
      while IFS= read -r line; do
        if [[ "$line" =~ ^$pid[[:space:]] ]]; then
          found=1
          continue
        fi

        if [[ $found -eq 1 ]]; then
          if [[ "$line" =~ ^\*+ ]]; then
            child_pid=$(echo "$line" | awk '{print $2}')
            if ! grep -qw "$child_pid" <<< "$PRINTED_PIDS"; then
              echo "$line"
              PRINTED_PIDS="$PRINTED_PIDS $child_pid"
            fi
          else
            break
          fi
        fi
      done < "$PSTREE_FILE"
    fi
  done
  echo

  # Update PIDS dengan semua PID unik yang sudah dicetak
  # Gunakan tr dan sort -u untuk unik dan rapikan
  PIDS=$(echo "$PIDS $PRINTED_PIDS" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u | tr '\n' ' ' | sed 's/ $//')
} >> "$REPORT_FILE"



# Step 5 - cmdline
echo "[5/11] Writing Identifying Command Line Arguments section..."
{
  echo "Identifying Command Line Arguments"
  get_header "$CMDLINE_FILE"
  for pid in $PIDS; do
    grep -E "^$pid[[:space:]]" "$CMDLINE_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 6 - DLL list
echo "[6/11] Writing Identifying Loaded DLLs section..."
{
  echo "Identifying Loaded DLLs"
  get_header "$DLLLIST_FILE"
  for pid in $PIDS; do
    grep -E "^$pid[[:space:]]" "$DLLLIST_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 7 - Handles
echo "[7/11] Writing Identifying Handles section..."
{
  echo "Identifying Handles"
  get_header "$HANDLES_FILE"
  for pid in $PIDS; do
    grep -E "^$pid[[:space:]]" "$HANDLES_FILE"
  done
  echo
} >> "$REPORT_FILE"


# Step 8 - netstat
echo "[8/11] Writing Network Connections (Netstat) section..."
{
  echo "Network Connections (Netstat)"
  get_header "$NETSTAT_FILE"
  for pid in $PIDS; do
    grep -E "[[:space:]]$pid[[:space:]]" "$NETSTAT_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 9 - netscan
echo "[9/1]1 Writing Network Connections (Netscan) section..."
{
  echo "Network Connections (Netscan)"
  get_header "$NETSCAN_FILE"
  for pid in $PIDS; do
    grep -E "[[:space:]]$pid[[:space:]]" "$NETSCAN_FILE"
  done
  echo
} >> "$REPORT_FILE"

# Step 10 - svcscan
echo "[10/11] Writing Service Scan (svcscan) section..."
{
  echo "Service Scan (svcscan)"
  get_header "$SERVICESCAN_FILE"
  for pid in $PIDS; do
    grep -E "[[:space:]]$pid[[:space:]]" "$SERVICESCAN_FILE"
  done
  echo
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
