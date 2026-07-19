# ⚔️ Cyber Samurai OSINT Correlation & Verification Toolkit

This directory houses the core engines for profile verification and multi-target fingerprint correlation.

---

## 📂 Components Included
* **sheylong.js**: Standalone Puppeteer engine that scans targets, handles anti-detection, checks false-positive patterns, and writes output reports.
* **report.py**: Aggregates and correlates verified CSV records to compile the final interactive dashboard.
* **verify.py**: Offline concurrent checker (alternative validation utility).
* **generate-report-main.py**: Master pipeline coordinator.

---

## 🚀 Execution Instructions

### 1. Perform Footprint Scan
Scans targets for a given username and exports results to the `rawReports` folder:
```bash
node sheylong.js -u bazzofx -csv -v
```

### 2. Generate Correlation Report
Correlate target CSV reports from the `rawReports` folder to compile the final visualizer:
```bash
python report.py rawReports/bazzofx.csv rawReports/another_target.csv osint_correlation_report.html
```
