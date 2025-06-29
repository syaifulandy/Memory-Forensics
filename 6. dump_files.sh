#!/bin/bash

# Inputan: file memory dan hasil analisis proses di folder yang sama

# === Bagian 1: Validasi & Persiapan ===
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/file.vmem"
  exit 1
fi

VMEM_PATH="$1"
if [[ ! -f "$VMEM_PATH" ]]; then
  echo "File tidak ditemukan: $VMEM_PATH"
  exit 2
fi

VMEM_FILE=$(basename "$VMEM_PATH")             # e.g. ecorpwin7-e73257c4.vmem
VMEM_NAME="${VMEM_FILE%.vmem}"                 # ecorpwin7-e73257c4

CSV_FILE=$(ls output_pstree_analysis_${VMEM_NAME}*.csv 2>/dev/null | head -n 1)
if [[ -z "$CSV_FILE" ]]; then
  echo "Tidak ditemukan file CSV: output_pstree_analysis_${VMEM_NAME}*.csv"
  exit 3
fi

OUTPUT_DIR="dump_memory_${VMEM_NAME}"
mkdir -p "$OUTPUT_DIR"

UNIQUE_PID_FILE="${OUTPUT_DIR}/unique_pid_${VMEM_NAME}"
grep -v '^pid' "$CSV_FILE" | grep -v ',OK$' | cut -d',' -f1 | sort -n | uniq > "$UNIQUE_PID_FILE"
echo "[+] PID unik disimpan di: $UNIQUE_PID_FILE"

# === Bagian 2: Dump per PID ===
echo "[+] Menjalankan dumpfiles per PID dari direktori: $OUTPUT_DIR"
pushd "$OUTPUT_DIR" > /dev/null

> dump_result.log
> dump_success.log
> dump_failed.log

while read -r PID; do
  [[ -z "$PID" ]] && continue
  TIMESTAMP=$(date +%H:%M:%S)
  echo "[$TIMESTAMP] Dumping PID $PID ..."
  
  # Jalankan dan simpan output ke log

  echo "===== PID $PID =====" | tee -a dump_result.log
  vol -f "$VMEM_PATH" windows.dumpfiles --pid "$PID" 2>&1 | tee -a dump_result.log > tmp_output.log

  if grep -qE '^\S+\s+\S+\s+\S+\s+file\.' tmp_output.log; then
    grep -i 'Result: OK' tmp_output.log >> dump_success.log
    echo "  [+] PID $PID: SUKSES"
  else
    grep -i 'Result:' tmp_output.log >> dump_failed.log
    echo "  [-] PID $PID: GAGAL"
  fi
done < "../$UNIQUE_PID_FILE"

rm -f tmp_output.log
popd > /dev/null
