#!/bin/bash

TARGET=$1
REPORT=$2
LOG=$3

echo "" | tee -a $REPORT
echo "=========================" | tee -a $REPORT
echo "RECONNAISSANCE PHASE" | tee -a $REPORT
echo "=========================" | tee -a $REPORT

NMAP_OUTPUT=$(nmap -sV $TARGET)

# Full raw output -> LOG
echo "$NMAP_OUTPUT" >> "$LOG"

# Summary -> REPORT
echo "[INFO] Open Ports Detected:" | tee -a $REPORT

echo "$NMAP_OUTPUT" | grep "/tcp" | tee -a $REPORT
