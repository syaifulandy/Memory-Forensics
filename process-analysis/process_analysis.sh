#!/bin/bash

# Fungsi: normalisasi path
normalize_path() {
    echo "$1" | tr '[:upper:]' '[:lower:]' \
        | sed -E 's|.*\\(windows\\.*)|windows\\\1|' \
        | sed -E 's|.*\\(programdata\\.*)|programdata\\\1|' \
        | sed -E 's|.*\\(program files \(x86\)\\.*)|program files (x86)\\\1|' \
        | sed -E 's|.*\\(program files\\.*)|program files\\\1|' \
        | sed -E 's|.*\\(users\\[^\\]*\\desktop\\.*)|users\\\1|' \
        | sed -E 's|.*\\(appdata\\.*)|appdata\\\1|' \
        | sed -E 's|.*\\(temp\\.*)|temp\\\1|' \
        | sed -E 's|.*\\(system32\\.*)|windows\\\1|' \
        | sed -E 's|^(programdata)\\+\1|programdata|' \
        | sed -E 's|^(program files \(x86\))\\+\1|program files (x86)|' \
        | sed -E 's|^(program files)\\+\1|program files|' \
        | sed -E 's|^(windows)\\+\1|windows|' \
        | sed -E 's|\\\\|\\|g'
}

# Fungsi: ambil path gabungan audit dan path jika memungkinkan
combine_paths() {
    audit_lc=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    path_lc=$(echo "$2" | tr '[:upper:]' '[:lower:]')

    if [[ -n "$audit_lc" && -n "$path_lc" ]]; then
        audit_sub=$(normalize_path "$audit_lc")
        path_sub=$(normalize_path "$path_lc")
        if [[ "$audit_sub" == "$path_sub" ]]; then
            echo "$audit_sub"
            return
        fi
    fi

    if [[ -n "$audit_lc" ]]; then
        echo $(normalize_path "$audit_lc")
    elif [[ -n "$path_lc" ]]; then
        echo $(normalize_path "$path_lc")
    else
        echo ""
    fi
}

# Parsing argumen
while getopts "p:t:" opt; do
  case $opt in
    p) psscan_file="$OPTARG" ;;
    t) pstree_file="$OPTARG" ;;
    *) echo "Usage: $0 -p <windows_psscan_*> -t <windows_pstree_*>"; exit 1 ;;
  esac
done


if [[ -z "$psscan_file" || -z "$pstree_file" ]]; then
  echo "Usage: $0 -p <windows_psscan_*> -t <windows_pstree_*>"
  exit 1
fi

kamus_file="kamus.txt"

basename_psscan=$(basename "$psscan_file")
basename_pstree=$(basename "$pstree_file" | sed 's/^windows_pstree_//')
temp_pstree="temp_${basename_pstree}.txt"


# Step 1: Hapus * di awal baris diikuti spasi
sed -E 's/^\*+ +//; s/\*//g' "$pstree_file" > "$temp_pstree"

# Step 2: Hapus semua sisa * di mana pun
pstree_file="$temp_pstree"

psscan_output="output_${basename_psscan}"
pstree_output="output_pstree_analysis_${basename_pstree%.txt}.csv"

# 1. Baca kamus jadi associative array
declare -A path_kamus parent_kamus

while IFS=";" read -r proc path parents; do
  proc=$(echo "$proc" | tr '[:upper:]' '[:lower:]')
  path_kamus["$proc"]=$(normalize_path "$path")
  parent_kamus["$proc"]=$(echo "$parents" | tr '[:upper:]' '[:lower:]')
done < "$kamus_file"

# 2. Ekstrak PID dan ImageFileName dari psscan
declare -A pid_to_proc
awk -F'\t' 'BEGIN{IGNORECASE=1} /^[0-9]+/ { print tolower($1), tolower($3) }' "$psscan_file" > "$psscan_output"
while read -r pid proc; do
  pid_to_proc["$pid"]="$proc"
done < "$psscan_output"

# Tambahan: ambil juga mapping dari pstree
awk -F'\t' 'BEGIN{IGNORECASE=1} /^[0-9]+/ { print tolower($1), tolower($3) }' "$pstree_file" >> "$psscan_output"
while read -r pid proc; do
  pid_to_proc["$pid"]="$proc"
done < "$psscan_output"

# 3. Ekstrak dari pstree + konversi PPID ke process name
echo "pid,ppid,image,path,parent_proc,status" > "$pstree_output"
awk -F'\t' 'BEGIN{OFS=","} /^[0-9]+/ { print $1, $2, tolower($3), $11, $13 }' "$pstree_file" | while IFS=',' read -r pid ppid image audit path; do
  # Skip SYSTEM dengan PPID 0
  if [[ "$image" == "system" && "$ppid" == "0" ]]; then
    continue
  fi

  parent_proc=${pid_to_proc["$ppid"]}
  [[ -z "$parent_proc" ]] && parent_proc="UNKNOWN"

  norm_path=$(combine_paths "$audit" "$path")

  # 4. Validasi dengan kamus
  allowed_path="${path_kamus[$image]}"
  allowed_parents="${parent_kamus[$image]}"
  status=""

  [[ "$norm_path" != "$allowed_path" ]] && status="MALICIOUS_PATH"
  ! echo "$allowed_parents" | grep -qw "$parent_proc" && status="${status:+${status}_}MALICIOUS_PARENT"
  [[ "$status" == "MALICIOUS_PATH_MALICIOUS_PARENT" ]] && status="UNKNOWN_PROCESS"
  [[ -z "$status" ]] && status="OK"

  echo "$pid,$ppid,$image,$norm_path,$parent_proc,$status"
done >> "$pstree_output"
rm $psscan_output
rm $temp_pstree
echo "Process analysis completed"
