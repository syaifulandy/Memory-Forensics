#!/bin/bash

# Cek jumlah argumen
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <folder_output> <keyword>"
    exit 1
fi

FOLDER="$1"
KEYWORD="$2"

# Cek apakah folder ada
if [ ! -d "$FOLDER" ]; then
    echo "Error: Folder '$FOLDER' tidak ditemukan."
    exit 1
fi

# Jalankan grep
echo "Mencari keyword '$KEYWORD' di folder '$FOLDER' (file *.txt)..."
grep -rnw "$FOLDER" -e "$KEYWORD" --include="*.txt"
