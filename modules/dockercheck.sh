#!/bin/bash

TARGET=$1
REPORT=$2

echo ""
echo "=========================" | tee -a $REPORT
echo "DOCKER EXPOSURE CHECK" | tee -a $REPORT
echo "=========================" | tee -a $REPORT

curl -s http://$TARGET:2375/version > /tmp/dockercheck.txt

if grep -q "Version" /tmp/dockercheck.txt; then
    echo "[CRITICAL] Docker Remote API Exposed!" | tee -a $REPORT
else
    echo "[OK] Docker API not exposed." | tee -a $REPORT
fi
