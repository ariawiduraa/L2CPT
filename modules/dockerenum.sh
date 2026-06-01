#!/bin/bash

TARGET=$1
REPORT=$2

echo ""
echo "=========================" | tee -a $REPORT
echo "DOCKER ENUMERATION" | tee -a $REPORT
echo "=========================" | tee -a $REPORT

# List containers

ssh deb@$TARGET "sudo docker ps --format '{{.Names}}'" > /tmp/containers.txt

echo "[INFO] Running Containers:" | tee -a $REPORT

cat /tmp/containers.txt | tee -a $REPORT

# Check privileged containers

for container in $(cat /tmp/containers.txt); do

    PRIV=$(ssh deb@$TARGET "sudo docker inspect -f '{{.HostConfig.Privileged}}' $container")

    if [ "$PRIV" = "true" ]; then
        echo "[CRITICAL] $container running as privileged!" | tee -a $REPORT
    fi

done

# Check docker.sock mount

for container in $(cat /tmp/containers.txt); do

    SOCK=$(ssh deb@$TARGET "sudo docker inspect $container | grep docker.sock")

    if [ ! -z "$SOCK" ]; then
        echo "[CRITICAL] docker.sock mounted in $container" | tee -a $REPORT
    fi

done

# Docker Network Enumeration

echo ""
echo "[INFO] Docker Networks:" | tee -a $REPORT

ssh deb@$TARGET "sudo docker network ls" | tee -a $REPORT
