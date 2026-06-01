#!/bin/bash

REPORT=$1

echo "" >> $REPORT
echo "=========================" >> $REPORT
echo "SEVERITY SUMMARY" >> $REPORT
echo "=========================" >> $REPORT
echo "" >> $REPORT

CRITICAL=$(grep -c "\[CRITICAL\]" $REPORT)
HIGH=$(grep -c "\[HIGH\]" $REPORT)
MEDIUM=$(grep -c "\[MEDIUM\]" $REPORT)
LOW=$(grep -c "\[LOW\]" $REPORT)

echo "Critical Findings : $CRITICAL" >> $REPORT
echo "High Findings     : $HIGH" >> $REPORT
echo "Medium Findings   : $MEDIUM" >> $REPORT
echo "Low Findings      : $LOW" >> $REPORT

echo "" >> $REPORT
echo "=========================" >> $REPORT
echo "REMEDIATION RECOMMENDATIONS" >> $REPORT
echo "=========================" >> $REPORT

if grep -q "Privileged container detected" $REPORT; then
    echo "" >> $REPORT
    echo "[CRITICAL] Privileged Container" >> $REPORT
    echo "  - Avoid using privileged containers unless absolutely necessary." >> $REPORT
    echo "  - Use Linux capabilities instead of full privileged mode." >> $REPORT
fi

if grep -q "docker.sock mounted" $REPORT || grep -q "Docker socket exposure detected" $REPORT; then
    echo "" >> $REPORT
    echo "[CRITICAL] Docker Socket Exposure" >> $REPORT
    echo "  - Avoid mounting /var/run/docker.sock inside containers." >> $REPORT
    echo "  - Docker socket exposure may lead to full host compromise." >> $REPORT
fi

if grep -q "Database Port Exposed" $REPORT; then
    echo "" >> $REPORT
    echo "[HIGH] Database Exposure" >> $REPORT
    echo "  - Restrict database services using internal Docker networks." >> $REPORT
    echo "  - Avoid exposing database ports directly to external networks." >> $REPORT
fi

if grep -q "Critical CVEs detected" $REPORT; then
    echo "" >> $REPORT
    echo "[HIGH] Vulnerable Docker Images" >> $REPORT
    echo "  - Update Docker images regularly to patch vulnerabilities." >> $REPORT
    echo "  - Use minimal and maintained base images." >> $REPORT
fi

if grep -q "High severity vulnerabilities detected" $REPORT; then
    echo "" >> $REPORT
    echo "[MEDIUM] Patch Management" >> $REPORT
    echo "  - Perform periodic vulnerability scanning." >> $REPORT
    echo "  - Apply regular security patch management." >> $REPORT
fi

echo "" >> $REPORT
echo "[INFO] Remediation analysis completed." >> $REPORT
echo "" >> $REPORT
