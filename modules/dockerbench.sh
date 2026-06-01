#!/bin/bash

TARGET=$1
REPORT=$2
LOG=$3

echo "" >> $REPORT
echo "=========================" >> $REPORT
echo "DOCKER BENCH ASSESSMENT" >> $REPORT
echo "=========================" >> $REPORT

# Jalankan Docker Bench
ssh deb@$TARGET "cd docker-bench-security && sudo sh docker-bench-security.sh" \
> $LOG 2>&1

WARNINGS=$(grep "\[WARN\]" $LOG | wc -l)

echo "[INFO] Docker Bench Warnings: $WARNINGS" \
| tee -a $REPORT

# Tambahkan medium jika warning banyak
if [ "$WARNINGS" -ge 50 ]; then

    echo "[MEDIUM] Multiple Docker security misconfigurations detected." \
    | tee -a $REPORT

fi
