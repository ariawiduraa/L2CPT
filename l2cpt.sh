#!/bin/bash

# Resolve BASE_DIR to the actual project directory
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET=$1
DATE=$(date +"%Y-%m-%d_%H-%M-%S")

REPORT="$BASE_DIR/reports/report_$DATE.txt"
LOG="$BASE_DIR/logs/log_$DATE.txt"

echo "====================================="
echo "L2CPT Automated Assessment Framework"
echo "====================================="

echo "[+] Target: $TARGET"
echo "[+] Report: $REPORT"

# Create files
mkdir -p "$BASE_DIR/reports" "$BASE_DIR/logs"
touch $REPORT
touch $LOG

# Write target info to report
echo "[+] Target: $TARGET" >> $REPORT
echo "[+] Date: $(date)" >> $REPORT

# Run modules

$BASE_DIR/modules/recon.sh $TARGET $REPORT $LOG

$BASE_DIR/modules/dockercheck.sh $TARGET $REPORT $LOG

$BASE_DIR/modules/webcheck.sh $TARGET $REPORT $LOG

$BASE_DIR/modules/trivy.sh $TARGET $REPORT $LOG

$BASE_DIR/modules/dockerbench.sh $TARGET $REPORT $LOG

$BASE_DIR/modules/dockerenum.sh $TARGET $REPORT $LOG

$BASE_DIR/modules/risk.sh $REPORT

$BASE_DIR/modules/remediation.sh $REPORT



echo ""

echo ""
echo "========================="
echo "FINAL SECURITY SUMMARY"
echo "========================="

tail -35 $REPORT

echo ""
echo "[+] Assessment Complete."
echo "[+] Report saved to: $REPORT"
echo "[+] Log saved to: $LOG"
