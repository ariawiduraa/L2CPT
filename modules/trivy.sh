#!/bin/bash

TARGET=$1
REPORT=$2
LOG=$3

echo "" >> $REPORT
echo "=========================" >> $REPORT
echo "TRIVY VULNERABILITY SCAN" >> $REPORT
echo "=========================" >> $REPORT

# Ambil image dari container aktif saja
RUNNING_IMAGES=$(ssh deb@$TARGET "docker ps --format '{{.Image}}'")

# Jika tidak ada container aktif
if [ -z "$RUNNING_IMAGES" ]; then

    echo "[INFO] No running containers detected." | tee -a $REPORT
    echo "[INFO] Trivy scan skipped." >> $LOG

    exit 0
fi

# Scan tiap image aktif
for image in $RUNNING_IMAGES
do

    echo "[INFO] Scanning image: $image" >> $LOG

    ssh deb@$TARGET "trivy image --severity CRITICAL,HIGH $image" \
    >> $LOG 2>&1

    # CRITICAL
    if ssh deb@$TARGET "trivy image --severity CRITICAL $image | grep CRITICAL" > /dev/null
    then
        echo "[CRITICAL] Critical CVEs detected in $image!" \
        | tee -a $REPORT
    fi

    # HIGH
    if ssh deb@$TARGET "trivy image --severity HIGH $image | grep HIGH" > /dev/null
    then
        echo "[HIGH] High severity vulnerabilities detected in $image!" \
        | tee -a $REPORT
    fi

done
