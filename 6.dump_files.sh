#!/bin/bash

# === Bagian 1: Validasi & Persiapan ===
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 /path/to/file.vmem [quick|normal]"
  exit 1
fi

VMEM_PATH="$1"
FILTER_MODE="${2:-quick}"  # default: quick

if [[ ! -f "$VMEM_PATH" ]]; then
  echo "File tidak ditemukan: $VMEM_PATH"
  exit 2
fi

VMEM_FILE=$(basename "$VMEM_PATH")             # e.g. ecorpwin7-e73257c4.vmem
VMEM_NAME="${VMEM_FILE}"                 # ecorpwin7-e73257c4

CSV_FILE=$(ls output_pstree_analysis_${VMEM_NAME}*.csv 2>/dev/null | head -n 1)
if [[ -z "$CSV_FILE" ]]; then
  echo "Tidak ditemukan file CSV: output_pstree_analysis_${VMEM_NAME}*.csv"
  exit 3
fi

OUTPUT_DIR="dump_memory_${VMEM_NAME}"
mkdir -p "$OUTPUT_DIR"

UNIQUE_PID_FILE="${OUTPUT_DIR}/unique_pid_${VMEM_NAME}"

echo "[*] Mode filter: $FILTER_MODE"

# === Bagian 1.5: Ambil PID dari hasil malfind ===
MALFIND_DIR="output_${VMEM_FILE}"
MALFIND_FILE="${MALFIND_DIR}/windows_malfind_${VMEM_FILE}.txt"

MALFIND_PID_FILE="${OUTPUT_DIR}/malfind_pids_${VMEM_NAME}.txt"

if [[ -f "$MALFIND_FILE" ]]; then
  echo "[*] Membaca PID dari file malfind: $MALFIND_FILE"

  # Ekstrak PID dari dua jenis pola:
  # 1. [proc_id NNNN]
  # 2. Baris tabel: diawali angka (PID), diikuti nama proses, dll
  grep -oP '\[proc_id \K[0-9]+' "$MALFIND_FILE" > "${MALFIND_PID_FILE}.tmp"
  grep -E '^[0-9]+\s' "$MALFIND_FILE" | cut -f1 | grep -E '^[0-9]+$' >> "${MALFIND_PID_FILE}.tmp"

  # Gabungkan dan deduplikasi
  sort -n "${MALFIND_PID_FILE}.tmp" | uniq > "$MALFIND_PID_FILE"
  rm -f "${MALFIND_PID_FILE}.tmp"

  PID_COUNT=$(wc -l < "$MALFIND_PID_FILE")
  echo "[+] PID dari malfind: $PID_COUNT ditemukan"
  cat "$MALFIND_PID_FILE" | sed 's/^/    - /'

else
  echo "[!] File malfind tidak ditemukan: $MALFIND_FILE"
  > "$MALFIND_PID_FILE"
fi


# === Bagian 2: Ekstraksi PID Unik Berdasarkan Mode ===
case "$FILTER_MODE" in
  quick)
    # Ambil PID dari CSV, exclude OK & system32
    grep -v '^pid' "$CSV_FILE" | grep -v ',OK$' | grep -iv "system32" | cut -d',' -f1 > "${UNIQUE_PID_FILE}.csv"

    # Tambahkan PID dari malfind (jika ada)
    if [[ -s "$MALFIND_PID_FILE" ]]; then
      cat "$MALFIND_PID_FILE" >> "${UNIQUE_PID_FILE}.csv"
    fi

    # Gabungkan, urutkan, dan ambil yang unik
    sort -n "${UNIQUE_PID_FILE}.csv" | uniq > "$UNIQUE_PID_FILE"
    rm -f "${UNIQUE_PID_FILE}.csv"
    ;;
    
  normal)
    # Ambil semua PID dari CSV tanpa filter system32 atau OK
    grep -v '^pid' "$CSV_FILE" | grep -v ',OK$' | cut -d',' -f1 | sort -n | uniq > "$UNIQUE_PID_FILE"
    ;;
    
  *)
    echo "Mode tidak dikenali: $FILTER_MODE"
    echo "Gunakan: quick (default) atau normal"
    exit 4
    ;;
esac
echo "[+] PID unik disimpan di: $UNIQUE_PID_FILE"

# === Bagian 3: Dump per PID (PARALEL) ===
echo "[+] Menjalankan dumpfiles per PID dari direktori: $OUTPUT_DIR"
pushd "$OUTPUT_DIR" > /dev/null

> dump_result.log
> dump_success.log
> dump_failed.log

export VMEM_PATH

dump_pid() {
  PID="$1"
  [[ -z "$PID" ]] && exit 0

  TIMESTAMP=$(date +%H:%M:%S)
  echo "[$TIMESTAMP] Dumping PID $PID ..."

  PID_DIR="pid_$PID"
  mkdir -p "$PID_DIR"
  pushd "$PID_DIR" > /dev/null

  echo "===== PID $PID - dumpfiles =====" >> ../dump_result.log
  vol -f "$VMEM_PATH" windows.dumpfiles --pid "$PID" >> ../dump_result.log 2>&1 > ../tmp_output_$PID.log

  if grep -qE '^\S+\s+\S+\s+\S+\s+file\.' ../tmp_output_$PID.log; then
    grep -i 'Result: OK' ../tmp_output_$PID.log >> ../dump_success.log
    echo "  [+] PID $PID dumpfiles: SUKSES"
  else
    grep -i 'Result:' ../tmp_output_$PID.log >> ../dump_failed.log
    echo "  [-] PID $PID dumpfiles: GAGAL"
  fi

  popd > /dev/null
}

export -f dump_pid

cat "../$UNIQUE_PID_FILE" | xargs -P4 -I{} bash -c 'dump_pid "$@"' _ {}

rm -f tmp_output_*.log
popd > /dev/null
