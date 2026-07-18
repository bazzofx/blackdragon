# ⚔️ Cyber Samurai OSINT Correlation & Verification Toolkit

This toolkit provides an automated pipeline to verify active OSINT profiles, eliminate HTTP 200 false positives (redirects or landing pages served instead of profile pages), and generate a professional, interactive HTML visualization report correlating multiple target profiles.

## 📂 Files Included
- **[generate-report-main.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/dev/osint_report_function/generate-report-main.py)**: The master pipeline coordinator that orchestrates the verification and correlation stages automatically.
- **[verify.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/dev/osint_report_function/verify.py)**: Scans profile URLs in parallel to verify if usernames actually exist in the page body and filters out false positive links.
- **[report.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/dev/osint_report_function/report.py)**: Correlates verified profiles, reconstructs missing links, and compiles the interactive Vis.js & Mermaid dashboard.
- **[osint_correlation_report.html](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/dev/osint_report_function/osint_correlation_report.html)**: The generated interactive report.

---

## 🚀 Quick Execution Guide (Single Command)

To run the entire pipeline (verification + correlation) in a single command:

```bash
# Run directly with target CSV files
python generate-report-main.py luizcalixt0.csv robsonsaint.csv
```

*What the master coordinator does:*
1. Automatically runs `verify.py` on the input files.
2. Saves verified results to temporary clean outputs: `luizcalixt0_clean.csv` and `robsonsaint_clean.csv`.
3. Executes `report.py` on these verified files to generate the final visualizer report `osint_correlation_report.html`.

---

## 🛠️ Step-by-Step Manual Execution

If you prefer to execute the stages individually:

### Step 1: Verify Profile Links (Filter False Positives)
Websites often return `HTTP 200 OK` for users that do not exist by redirecting to sign-up pages. Use `verify.py` to check the HTML text content of each active account.

```bash
# Verify Luiz's profile list
python verify.py luizcalixt0.csv luizcalixt0_clean.csv

# Verify Robson's profile list
python verify.py robsonsaint.csv robsonsaint_clean.csv
```

- Verification checks for the presence of the username and screens out typical error strings.
- Filters out **~149 false positive profiles per user**, leaving exactly **11 true positives** for Luiz and **11 true positives** for Robson.

---

### Step 2: Correlate and Compile the Dashboard Report
Once you have the verified CSV files, feed them to `report.py` to align their footprints.

```bash
# Generate the report from verified files
python report.py luizcalixt0_clean.csv robsonsaint_clean.csv
```

- Aligns matching accounts (detecting shared locations).
- Reconstructs missing profile links using dynamic templates.
- Compiles the HTML dashboard.

---

## 📊 Viewing the Report
Once generated, double-click **[osint_correlation_report.html](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/dev/osint_report_function/osint_correlation_report.html)** to load it in any browser.

- **Zoom and Pan**: Hover over the network graph and use the mousewheel to zoom, and drag to move/pan the footprint.
- **Interactive Routing**: Click a unique site node (blue) to open its URL immediately. Click a shared site node (green) to open a modal routing you to either Target A's or Target B's profile.
- **Freeze Layout**: Use the toolbar to stop nodes from floating around once settled.
- **Resizing**: Adjust canvas height dynamically using the Expand/Shrink buttons.
- **Live Search Table**: Toggle the "Footprint Register Table" tab and search in real-time or filter by Correlation Type (Shared vs Unique).
