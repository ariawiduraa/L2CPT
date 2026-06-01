L2CPT Web Dashboard

How to run:

1. Install Flask:
   pip install flask

2. Go to project directory:
   cd L2CPT-WebUI

3. Run dashboard:
   python3 app.py

4. Open browser:
   http://127.0.0.1:5000

Features:
- Input target IP
- Run l2cpt.sh automatically
- View scan output
- Browse generated reports

Folder Explanation:
- reports/ = generated assessment reports
- logs/ = raw scan outputs, debug logs, and module execution logs

Suggested logs usage:
- nmap raw output
- trivy raw output
- docker bench raw output
- SSH execution logs
