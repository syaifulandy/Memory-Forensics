#!/bin/bash

# Mengecek parameter
if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/memory.raw"
    exit 1
fi

MEMFILE="$1"
MEMBASENAME=$(basename "$MEMFILE")
OUTDIR="output_$MEMBASENAME"

# Membuat folder output jika belum ada
mkdir -p "$OUTDIR"

# Daftar plugin yang ingin dijalankan
PLUGINS=(
  "windows.info"
  "windows.malfind"
  "windows.pslist"
  "windows.pstree"
  "windows.cmdline"
  "windows.netstat"
  "windows.netscan"
  "windows.psscan"
  "windows.svcscan"
  "windows.dlllist"
  "windows.handles"
  "windows.registry.hivelist" #tidak dianalisis otomatis
)

# Jalankan tiap plugin dan simpan output ke file
for plugin in "${PLUGINS[@]}"; do
  OUTFILE="${OUTDIR}/${plugin//./_}_${MEMBASENAME}.txt"
  echo "[*] Running $plugin..."
  vol -q -f "$MEMFILE" "$plugin" > "$OUTFILE" 2>&1
done

echo "[+] All plugins finished. Output saved to $OUTDIR"
