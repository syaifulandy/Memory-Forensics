#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/memory.raw"
    exit 1
fi

MEMFILE="$1"
MEMBASENAME=$(basename "$MEMFILE")
OUTDIR="output_$MEMBASENAME"
mkdir -p "$OUTDIR"

# Plugin yang cenderung lebih lambat (>2 detik)
HEAVY_PLUGINS=(
  "windows.malfind"
  "windows.netscan"
  "windows.handles"
  "windows.svcscan"
  "windows.psscan"
  "windows.dlllist"
)

# Plugin yang cenderung cepat (≤2 detik)
LIGHT_PLUGINS=(
  "windows.info"
  "windows.pslist"
  "windows.pstree"
  "windows.cmdline"
  "windows.netstat"
  "windows.registry.hivelist"
)

START_TIME=$(date +%s)

run_plugin() {
  plugin="$1"
  group="$2"
  OUTFILE="${OUTDIR}/${plugin//./_}_${MEMBASENAME}.txt"

  if [ -f "$OUTFILE" ]; then
    echo "[*] Skipping $plugin ($group), output exists."
    exit 0
  fi

  echo "[*] Running $plugin ($group)..."
  PLUGIN_START=$(date +%s)
  vol -q -f "$MEMFILE" "$plugin" > "$OUTFILE" 2>&1
  PLUGIN_END=$(date +%s)
  echo "[*] Finished $plugin in $((PLUGIN_END - PLUGIN_START)) seconds."
}

export -f run_plugin
export MEMFILE MEMBASENAME OUTDIR

# Jalankan plugin berat paralel (maks 3 proses)
printf "%s\n" "${HEAVY_PLUGINS[@]}" | xargs -P 3 -I{} bash -c 'run_plugin "$@"' _ {} heavy &

# Jalankan plugin ringan paralel (maks 6 proses)
printf "%s\n" "${LIGHT_PLUGINS[@]}" | xargs -P 6 -I{} bash -c 'run_plugin "$@"' _ {} light

# Tunggu proses latar belakang
wait

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "[+] All plugins finished. Output saved to $OUTDIR"
echo "[*] Total time: $DURATION seconds"
