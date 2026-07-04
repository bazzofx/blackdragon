#!/bin/bash
output_dir="/home/kali/Documents/pbtools/blackdragon_dev/test"
domain="cybersamurai.co.uk"

ffuf -u "https://$domain/FUZZ" \
    -w /home/kali/wordlist/pblist/fuzzing/common.txt \
    -fc 403,404,429,500,503 \
    -t 30 \
    -o "${output_dir}/ffuf_report.json" \
    -of json \
    -c \
    -v \
    -r