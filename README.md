# L2CPT — Layered Lifecycle Container Penetration Testing Framework

L2CPT (Layered Lifecycle Container Penetration Testing) is an automated Docker security assessment framework designed to perform reconnaissance, vulnerability scanning, Docker auditing, runtime enumeration, risk scoring, and remediation recommendation against Docker-based environments.

This framework was developed as an academic cybersecurity research project focusing on automated penetration testing and Docker security assessment.

---

# Features

* Automated Docker Security Assessment
* Runtime-aware Vulnerability Scanning
* Docker Misconfiguration Detection
* Docker Exposure Analysis
* Runtime Container Enumeration
* Risk Scoring Engine
* Remediation Recommendation Engine
* Interactive Web Dashboard
* Dynamic Reporting System
* Modular Architecture

---

# Framework Workflow

```text
Target Identification
        ↓
Reconnaissance
        ↓
Service Enumeration
        ↓
Docker Exposure Analysis
        ↓
Vulnerability Scanning
        ↓
Docker Bench Security Audit
        ↓
Runtime Container Enumeration
        ↓
Risk Scoring
        ↓
Remediation Recommendation
        ↓
Report Generation
```

---

# Modules

| Module         | Function                          |
| -------------- | --------------------------------- |
| recon.sh       | Reconnaissance & port scanning    |
| dockercheck.sh | Docker API exposure detection     |
| webcheck.sh    | Web & database exposure analysis  |
| trivy.sh       | Runtime vulnerability scanning    |
| dockerbench.sh | Docker security auditing          |
| dockerenum.sh  | Runtime container enumeration     |
| risk.sh        | Risk scoring engine               |
| remediation.sh | Remediation recommendation engine |

---

# Technologies Used

* Bash Script
* Flask
* Docker
* Nmap
* Trivy
* Docker Bench Security

---

# Testing Environment

## Host Machine

* Linux Mint

## Attacker Machine

* Kali Linux

## Target Machine

* Debian Linux

## Tested Applications

* DVWA
* MariaDB
* Nextcloud

---

# Installation

## Clone Repository

```bash
git clone https://github.com/ariawiduraa/L2CPT.git
cd L2CPT
```

---

# Install Dependencies

## Kali Linux

```bash
sudo apt update
sudo apt install nmap docker.io python3-flask git -y
```

## Install Trivy

```bash
sudo apt install wget apt-transport-https gnupg lsb-release -y

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | \
sudo tee /etc/apt/sources.list.d/trivy.list

sudo apt update
sudo apt install trivy -y
```

---

# Install Docker Bench Security

```bash
git clone https://github.com/docker/docker-bench-security.git
```

---

# Usage

## CLI Mode

```bash
chmod +x l2cpt.sh
./l2cpt.sh <TARGET-IP>
```

Example:

```bash
./l2cpt.sh 192.168.56.7
```

---

# Web Dashboard

## Run Flask Dashboard

```bash
cd web
python3 app.py
```

Open browser:

```text
http://localhost:5000
```

---

# Example Findings

L2CPT can detect:

* Privileged Containers
* Docker Socket Exposure
* Exposed Database Services
* Vulnerable Docker Images
* Docker Misconfigurations
* Runtime Container Risks
* Critical CVEs

---

# Sample Assessment Result

```text
Final Risk Score : 9/10
Security Level   : CRITICAL
```

---

# Severity Classification

| Severity | Description               |
| -------- | ------------------------- |
| Critical | Immediate security risk   |
| High     | High impact vulnerability |
| Medium   | Moderate security issue   |
| Low      | Minor security issue      |

---

# Dashboard Features

* Dynamic Scan Result Viewer
* Generated Reports
* Severity Summary
* Risk Score Visualization
* Interactive Assessment Output

---

# Research Scope

This framework focuses on:

* Docker Security Assessment
* Container Penetration Testing
* Runtime Container Security
* Vulnerability Assessment
* Docker Misconfiguration Detection

---

# Limitations

* No exploitation automation
* Requires SSH access
* No Kubernetes support
* No real-time monitoring
* No distributed scanning support

---

# Future Development

* Kubernetes Integration
* Real-time Monitoring
* Exploitation Framework Integration
* PDF Report Export
* Distributed Assessment Support

---

# Academic Context

This project was developed as part of a cybersecurity research and penetration testing study focusing on Docker-based server architecture security.

---

# Disclaimer

This framework is intended for:

* Educational purposes
* Security research
* Authorized penetration testing
* Docker security auditing

Unauthorized usage against systems without permission is strictly prohibited.

---

# Author

Made Aria Widura
Information Systems Study Program
Universitas Pendidikan Ganesha
2026
