#!/bin/bash

TARGET=$1
REPORT=$2

echo ""
echo "=========================" | tee -a $REPORT
echo "WEB ANALYSIS" | tee -a $REPORT
echo "=========================" | tee -a $REPORT

if grep -q "^80/tcp" $REPORT; then
    echo "[INFO] Web Service Detected (80)" | tee -a $REPORT
fi

if grep -q "^3306/tcp" $REPORT; then
    echo "[HIGH] Database Port Exposed (3306)" | tee -a $REPORT
fi
