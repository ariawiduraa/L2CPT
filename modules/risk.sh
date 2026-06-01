#!/bin/bash

REPORT=$1

echo "" >> $REPORT
echo "=========================" >> $REPORT
echo "RISK SCORING" >> $REPORT
echo "=========================" >> $REPORT
echo "" >> $REPORT

RISK=0

grep -q "Privileged container detected" $REPORT && ((RISK+=4))
grep -q "docker.sock mounted" $REPORT && ((RISK+=4))
grep -q "Docker API exposed" $REPORT && ((RISK+=4))

grep -q "Database Port Exposed" $REPORT && ((RISK+=2))
grep -q "Critical CVEs detected" $REPORT && ((RISK+=2))

grep -q "High severity vulnerabilities detected" $REPORT && ((RISK+=1))

if [ $RISK -gt 10 ]; then
    RISK=10
fi

echo "[+] Final Risk Score : $RISK/10" >> $REPORT
echo "" >> $REPORT

if [ $RISK -ge 9 ]; then
    echo "[+] Security Level   : CRITICAL" >> $REPORT

elif [ $RISK -ge 6 ]; then
    echo "[+] Security Level   : HIGH RISK" >> $REPORT

elif [ $RISK -ge 3 ]; then
    echo "[+] Security Level   : MODERATE" >> $REPORT

else
    echo "[+] Security Level   : LOW RISK" >> $REPORT
fi

echo "" >> $REPORT
