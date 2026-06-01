from flask import Flask, render_template, request, redirect, url_for, jsonify
import subprocess
import threading
import time
import re
import json
import os
from pathlib import Path
from datetime import datetime

app = Flask(__name__)

# =========================================
# PATH CONFIGURATION
# =========================================

# Resolve BASE_DIR relative to the project, not ~/L2CPT
BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"
SCRIPT_PATH = BASE_DIR / "l2cpt.sh"

REPORT_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Track active scans
active_scans = {}

# =========================================
# ENHANCED REPORT PARSER
# =========================================

def parse_report(content, log_content=None):
    """Parse report content and extract all structured data."""

    score = "N/A"
    score_num = 0
    level = "UNKNOWN"

    # Match: [+] Final Risk Score : 10/10
    score_match = re.search(
        r'Final Risk Score\s*:\s*(\d+)/(\d+)',
        content
    )

    # Match: [+] Security Level   : CRITICAL
    level_match = re.search(
        r'Security Level\s*:\s*(.+)',
        content
    )

    if score_match:
        score_num = int(score_match.group(1))
        score = f"{score_match.group(1)}/{score_match.group(2)}"

    if level_match:
        level = level_match.group(1).strip()

    # Count findings ONLY in the assessment sections, NOT in remediation
    # Split content at REMEDIATION RECOMMENDATIONS to avoid double-counting
    assessment_content = content.split("REMEDIATION RECOMMENDATIONS")[0] if "REMEDIATION RECOMMENDATIONS" in content else content

    critical = len(re.findall(r'\[CRITICAL\]', assessment_content))
    high = len(re.findall(r'\[HIGH\]', assessment_content))
    medium = len(re.findall(r'\[MEDIUM\]', assessment_content))
    low = len(re.findall(r'\[LOW\]', assessment_content))

    # Extract target from report content
    target = "Unknown"
    # Try [+] Target: line first
    target_match = re.search(r'Target:\s*(.+)', content)
    if target_match:
        target = target_match.group(1).strip()
    else:
        # Try to extract IP from nmap scan report line in report
        nmap_target = re.search(r'Nmap scan report for\s+(\S+)', content)
        if nmap_target:
            target = nmap_target.group(1).strip()
        elif log_content:
            # Check in log file for nmap output
            nmap_log_target = re.search(r'Nmap scan report for\s+(\S+)', log_content)
            if nmap_log_target:
                target = nmap_log_target.group(1).strip()
        if target == "Unknown":
            # Final fallback: extract any IP address
            search_content = (log_content or "") + content
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', search_content)
            if ip_match:
                target = ip_match.group(1)

    # Extract open ports
    ports = []
    port_matches = re.findall(r'(\d+/tcp)\s+(\w+)\s+(\w+)\s*(.*)', content)
    for port_match in port_matches:
        ports.append({
            "port": port_match[0],
            "state": port_match[1],
            "service": port_match[2],
            "version": port_match[3].strip()
        })

    # Extract containers
    containers = []
    container_section = re.search(r'Running Containers:\n(.*?)(?:\n\[|$)', content, re.DOTALL)
    if container_section:
        for line in container_section.group(1).strip().split('\n'):
            name = line.strip()
            if name and not name.startswith('[') and not name.startswith('='):
                containers.append(name)

    # Extract individual findings with context
    findings = []
    finding_patterns = [
        (r'\[CRITICAL\]\s*(.+)', 'CRITICAL'),
        (r'\[HIGH\]\s*(.+)', 'HIGH'),
        (r'\[MEDIUM\]\s*(.+)', 'MEDIUM'),
        (r'\[LOW\]\s*(.+)', 'LOW'),
    ]

    for pattern, severity in finding_patterns:
        for match in re.finditer(pattern, assessment_content):
            finding_text = match.group(1).strip()
            if finding_text not in [f['text'] for f in findings]:
                findings.append({
                    "severity": severity,
                    "text": finding_text
                })

    # Extract remediation recommendations
    remediations = []
    remediation_section = content.split("REMEDIATION RECOMMENDATIONS")
    if len(remediation_section) > 1:
        rem_content = remediation_section[1]
        # Parse each recommendation block
        rem_blocks = re.findall(
            r'\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)(?=\n\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]|\n\n\[INFO\] Remediation|\Z)',
            rem_content,
            re.DOTALL
        )
        for severity, block in rem_blocks:
            title_line = block.strip().split('\n')[0]
            steps = re.findall(r'  - (.+)', block)
            if title_line and severity != 'INFO':
                remediations.append({
                    "severity": severity,
                    "title": title_line.strip(),
                    "steps": steps
                })

    # Extract scan phases/sections
    sections = []
    section_matches = re.findall(r'=+\n(.+?)\n=+\n(.*?)(?==+|$)', content, re.DOTALL)
    for section_name, section_content in section_matches:
        if section_name.strip() not in ['RISK SCORING', 'SEVERITY SUMMARY', 'REMEDIATION RECOMMENDATIONS']:
            sections.append({
                "name": section_name.strip(),
                "content": section_content.strip()
            })

    return {
        "score": score,
        "score_num": score_num,
        "level": level,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "target": target,
        "ports": ports,
        "containers": containers,
        "findings": findings,
        "remediations": remediations,
        "sections": sections,
        "total_findings": critical + high + medium + low
    }


def extract_target_from_filename(filename):
    """Try to extract target IP/domain from report filename or content."""
    # report_2026-05-14_10-55-39.txt -> extract date
    date_match = re.search(r'report_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})', filename)
    if date_match:
        raw = date_match.group(1)
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d_%H-%M-%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return filename


# =========================================
# DASHBOARD
# =========================================

@app.route("/")
def index():

    reports = sorted(
        REPORT_DIR.glob("*.txt"),
        key=lambda f: f.stat().st_mtime,
        reverse=True
    )

    parsed_reports = []

    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_findings = 0

    for report in reports:

        try:
            content = report.read_text()

            # Try to read corresponding log file for additional data
            log_name = report.name.replace("report_", "log_")
            log_path = LOG_DIR / log_name
            log_content = None
            if log_path.exists():
                try:
                    log_content = log_path.read_text(errors='ignore')[:5000]  # Read first 5KB only
                except:
                    pass

            parsed = parse_report(content, log_content)

            total_critical += parsed["critical"]
            total_high += parsed["high"]
            total_medium += parsed["medium"]
            total_low += parsed["low"]
            total_findings += parsed["total_findings"]

            # Extract date from filename
            scan_date = extract_target_from_filename(report.name)

            parsed_reports.append({
                "name": report.name,
                "score": parsed["score"],
                "score_num": parsed["score_num"],
                "level": parsed["level"],
                "critical": parsed["critical"],
                "high": parsed["high"],
                "medium": parsed["medium"],
                "low": parsed["low"],
                "target": parsed["target"],
                "date": scan_date,
                "total_findings": parsed["total_findings"]
            })

        except Exception as e:
            print(f"Error parsing report {report.name}: {e}")

    # Calculate average risk score
    avg_score = 0
    if parsed_reports:
        avg_score = round(
            sum(r["score_num"] for r in parsed_reports) / len(parsed_reports),
            1
        )

    stats = {
        "total": len(parsed_reports),
        "critical": total_critical,
        "high": total_high,
        "medium": total_medium,
        "low": total_low,
        "total_findings": total_findings,
        "avg_score": avg_score
    }

    return render_template(
        "index.html",
        reports=parsed_reports,
        stats=stats,
        active_scans=active_scans
    )


# =========================================
# ASYNC SCAN
# =========================================

def run_scan_async(target, scan_id):
    """Run the scan in a background thread."""
    active_scans[scan_id] = {
        "target": target,
        "status": "running",
        "start_time": datetime.now().strftime("%H:%M:%S"),
        "output": "",
        "progress": 0
    }

    try:
        cmd = [
            "bash",
            str(SCRIPT_PATH),
            target
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(BASE_DIR)
        )

        output_lines = []
        for line in iter(process.stdout.readline, ''):
            output_lines.append(line)
            active_scans[scan_id]["output"] = "".join(output_lines)

            # Estimate progress based on phases
            full_output = active_scans[scan_id]["output"]
            progress = 5
            if "RECONNAISSANCE" in full_output:
                progress = 15
            if "DOCKER EXPOSURE" in full_output:
                progress = 30
            if "WEB ANALYSIS" in full_output:
                progress = 45
            if "TRIVY" in full_output:
                progress = 55
            if "DOCKER BENCH" in full_output:
                progress = 70
            if "DOCKER ENUMERATION" in full_output:
                progress = 80
            if "RISK SCORING" in full_output:
                progress = 90
            if "Assessment Complete" in full_output:
                progress = 100
            active_scans[scan_id]["progress"] = progress

        process.wait()
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100

    except Exception as e:
        active_scans[scan_id]["status"] = "error"
        active_scans[scan_id]["output"] = str(e)


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")

    if not target:
        return redirect(url_for("index"))

    scan_id = f"scan_{int(time.time())}"

    # Start async scan
    thread = threading.Thread(
        target=run_scan_async,
        args=(target, scan_id)
    )
    thread.daemon = True
    thread.start()

    return render_template(
        "scanning.html",
        target=target,
        scan_id=scan_id
    )


@app.route("/scan/sync", methods=["POST"])
def scan_sync():
    """Synchronous scan fallback."""
    target = request.form.get("target")

    if not target:
        return redirect(url_for("index"))

    cmd = [
        "bash",
        str(SCRIPT_PATH),
        target
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(BASE_DIR)
    )

    output = result.stdout + "\n" + result.stderr

    # Find the latest report for this scan
    latest_report = None
    reports = sorted(REPORT_DIR.glob("*.txt"), key=lambda f: f.stat().st_mtime, reverse=True)
    if reports:
        latest_report = reports[0].name

    return render_template(
        "result.html",
        output=output,
        target=target,
        report_name=latest_report
    )


# =========================================
# SCAN STATUS API
# =========================================

@app.route("/api/scan/<scan_id>")
def scan_status(scan_id):
    """API endpoint for checking scan progress."""
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        data = {
            "status": scan["status"],
            "progress": scan["progress"],
            "output": scan["output"],
            "target": scan["target"]
        }
        # If completed, find the latest report
        if scan["status"] == "completed":
            reports = sorted(
                REPORT_DIR.glob("*.txt"),
                key=lambda f: f.stat().st_mtime,
                reverse=True
            )
            if reports:
                data["report_name"] = reports[0].name
        return jsonify(data)
    return jsonify({"status": "not_found"}), 404


# =========================================
# DASHBOARD API (for live updates)
# =========================================

@app.route("/api/stats")
def api_stats():
    """Return dashboard statistics as JSON for live updates."""
    reports = sorted(
        REPORT_DIR.glob("*.txt"),
        key=lambda f: f.stat().st_mtime,
        reverse=True
    )

    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0

    for report in reports:
        try:
            content = report.read_text()
            parsed = parse_report(content)
            total_critical += parsed["critical"]
            total_high += parsed["high"]
            total_medium += parsed["medium"]
            total_low += parsed["low"]
        except:
            pass

    return jsonify({
        "total": len(reports),
        "critical": total_critical,
        "high": total_high,
        "medium": total_medium,
        "low": total_low,
        "active_scans": len([s for s in active_scans.values() if s["status"] == "running"])
    })


# =========================================
# REPORT VIEWER
# =========================================

@app.route("/report/<name>")
def report(name):

    report_path = REPORT_DIR / name

    if report_path.exists():

        content = report_path.read_text()

        # Read log file for additional context
        log_name = name.replace("report_", "log_")
        log_path = LOG_DIR / log_name
        log_content = None
        if log_path.exists():
            try:
                log_content = log_path.read_text(errors='ignore')[:5000]
            except:
                pass

        parsed = parse_report(content, log_content)

    else:

        content = "Report not found."
        parsed = {
            "score": "N/A",
            "score_num": 0,
            "level": "UNKNOWN",
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "target": "Unknown",
            "ports": [],
            "containers": [],
            "findings": [],
            "remediations": [],
            "sections": [],
            "total_findings": 0
        }

    return render_template(
        "report.html",
        content=content,
        name=name,
        parsed=parsed
    )


# =========================================
# REPORT DELETE API
# =========================================

@app.route("/api/report/<name>/delete", methods=["POST"])
def delete_report(name):
    """Delete a report file."""
    report_path = REPORT_DIR / name
    log_name = name.replace("report_", "log_")
    log_path = LOG_DIR / log_name

    if report_path.exists():
        report_path.unlink()
    if log_path.exists():
        log_path.unlink()

    return jsonify({"status": "deleted"})


# =========================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
