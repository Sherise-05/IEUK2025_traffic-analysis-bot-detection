# IEUK2025_traffic-analysis-bot-detection

## Project Overview
This project investigates abnormal traffic patterns in a sample server log file for a small media startup. The goal is to identify signs of bot or abusive behavior and recommend a cost-effective strategy to mitigate server overload caused by non-human traffic.

---

## 📂 File Structure
```
.
├── log_analyzer.py # Main Python script for log parsing and analysis
├── sample-log.log # Provided log file 
├── requirements.txt # Python dependencies
├── report.md # 300-word written summary of findings
├── README.md # This documentation file
```

---

## 🚀 How to Run the Script

### 1. Set up a virtual environment (optional but recommended)
```
python -m venv venv
source venv/bin/activate
```
### 2. Install dependencies
```
pip install -r requirements.txt
```
### 3. Run the log analysis
```
python log_analyzer.py
```

### The script will print:
- Top 5 most active IPs
- Top 5 requested endpoints
- Suspicious IPs (e.g. frequent 404s or POSTs)
- IPs exceeding rate limits (e.g. >5 requests/second)

## Features
- Log parsing using regular expressions
- IP and endpoint frequency tracking
- Basic bot detection (404s, high-frequency POSTs)
- Rate-limiting detection logic
- Cost-effective mitigation recommendations

## Assumptions
The company uses a basic web server stack (e.g. NGINX or Apache)
No advanced firewall, CDN, or bot management system is currently in place

## License
This project was created for learning purposes during the Bright Network IEUK 2025 internship and is not licensed for commercial use.
