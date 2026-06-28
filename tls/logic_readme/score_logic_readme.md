# 📋 TLS Security Health Score Logic & Code Walkthrough

This document provides a detailed walkthrough of the security health score calculation rules implemented in the TLS assessment report generator.

---

## 🔍 1. Brief Description

The health scoring logic is located in the [generate_html_report](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/tls/generateTLSEnhanceReport.py#L323) function of the [generateTLSEnhanceReport.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/tls/generateTLSEnhanceReport.py) script.

This function evaluates parsed TLS scan findings (including vulnerabilities, supported/vulnerable protocols, and cipher suites), computes an overall percentage score (the **Health Score**), maps it to a qualitative rating, assigns styling/theme configurations, and constructs a responsive, premium HTML report containing interactive elements and dynamic SVG progress rings.

---

## 💻 2. Code Implementation

Below is the code section from [generateTLSEnhanceReport.py:L323-373](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/tls/generateTLSEnhanceReport.py#L323-L373) that handles the categorization of vulnerabilities, calculation of the score, and mapping of the rating metadata:

```python
def generate_html_report(findings: Dict, input_file: str) -> str:
    """Generate a premium, branded HTML report from findings."""

    # Count issues by severity
    critical_vulns = {k: v for k, v in findings['vulnerabilities'].items() if v['severity'] == 'CRITICAL'}
    warning_vulns = {k: v for k, v in findings['vulnerabilities'].items() if v['severity'] == 'WARNING'}
    pass_vulns = {k: v for k, v in findings['vulnerabilities'].items() if v['severity'] == 'PASS'}

    critical_count = len(critical_vulns)
    warning_count = len(warning_vulns)
    pass_count = len(pass_vulns)
    total_protocols = len(findings['protocols']['supported'])

    # Deprecated protocols
    deprecated_protos = [p for p in findings['protocols']['vulnerable'] if p in ['TLSv1', 'TLSv1.1']]

    # New health score logic:
    # - If >= 2 criticals -> 10% health score
    # - If exactly 1 critical -> 25% health score
    # - If 0 criticals but warnings exist -> 50% base, and for more than 1 warning: -5% per warning (floor of 10%)
    # - If 0 criticals and 0 warnings -> 100% health score
    if critical_count >= 2:
        score = 10
    elif critical_count == 1:
        score = 25
    elif warning_count > 0:
        if warning_count == 1:
            score = 50
        else:
            score = 50 - (warning_count * 5)
            score = max(10, score)
    else:
        score = 100

    if score >= 90:
        score_rating = "SECURE"
        score_color = "#10b981"  # Cyber Green
        score_class = "secure"
    elif score >= 75:
        score_rating = "STRONG"
        score_color = "#3b82f6"  # Cyber Blue
        score_class = "strong"
    elif score >= 50:
        score_rating = "WARNING"
        score_color = "#f59e0b"  # Cyber Yellow/Orange
        score_class = "warning"
    else:
        score_rating = "CRITICAL"
        score_color = "#ff2e3b"  # Cyber Red
        score_class = "critical"
```

---

## 🧮 3. Logical Breakdown

The scoring metric prioritizes severity issues in a hierarchical structure:

### ⚠️ Severity Assessment Rules
1. **Multiple Critical Vulnerabilities**
   - **Condition**: $\text{critical\_count} \ge 2$
   - **Outcome**: Health score drops immediately to **10%**.
2. **Single Critical Vulnerability**
   - **Condition**: $\text{critical\_count} = 1$
   - **Outcome**: Health score is set to **25%** (ignoring the number of warnings present).
3. **Single Warning (No Criticals)**
   - **Condition**: $\text{critical\_count} = 0 \text{ and } \text{warning\_count} = 1$
   - **Outcome**: Health score is set to **50%**.
4. **Multiple Warnings (No Criticals)**
   - **Condition**: $\text{critical\_count} = 0 \text{ and } \text{warning\_count} > 1$
   - **Outcome**: Calculated by subtracting $5\%$ for each warning starting from a $50\%$ base, bounded by a lower limit of $10\%$:
     $$\text{score} = \max(10, 50 - (\text{warning\_count} \times 5))$$
5. **No Issues Found**
   - **Condition**: $\text{critical\_count} = 0 \text{ and } \text{warning\_count} = 0$
   - **Outcome**: Health score is set to **100%**.

### 📊 Calculation & Rating Flowchart

```mermaid
graph TD
    Start([Start Calculation]) --> CheckCriticals{critical_count?}
    CheckCriticals -- ">= 2" --> Score10[score = 10]
    CheckCriticals -- "== 1" --> Score25[score = 25]
    CheckCriticals -- "== 0" --> CheckWarnings{warning_count?}
    CheckWarnings -- "> 0" --> CheckOneWarning{warning_count == 1?}
    CheckOneWarning -- "Yes" --> Score50[score = 50]
    CheckOneWarning -- "No (Multiple)" --> ScoreDeduct[score = 50 - warning_count * 5]
    ScoreDeduct --> FloorCheck{score < 10?}
    FloorCheck -- "Yes" --> ScoreFloor[score = 10]
    FloorCheck -- "No" --> MapRating
    CheckWarnings -- "== 0" --> Score100[score = 100]
    
    Score10 --> MapRating
    Score25 --> MapRating
    Score50 --> MapRating
    ScoreFloor --> MapRating
    Score100 --> MapRating
    
    MapRating{score?}
    MapRating -- ">= 90" --> Secure[SECURE / #10b981 / secure]
    MapRating -- ">= 75 and < 90" --> Strong[STRONG / #3b82f6 / strong]
    MapRating -- ">= 50 and < 75" --> Warning[WARNING / #f59e0b / warning]
    MapRating -- "< 50" --> Critical[CRITICAL / #ff2e3b / critical]
```

---

## 📋 4. Variable Matrix

The following table details the primary variables used during score assessment and formatting:

| Variable Name | Type | Description / Role |
| :--- | :--- | :--- |
| `findings` | `Dict` | Input dictionary parsed from raw scan data, containing vulnerabilities, protocols, and cipher suites. |
| `critical_vulns` | `Dict` | A subset of `findings` mapping only vulnerability entries whose severity level is `'CRITICAL'`. |
| `warning_vulns` | `Dict` | A subset of `findings` mapping only vulnerability entries whose severity level is `'WARNING'`. |
| `pass_vulns` | `Dict` | A subset of `findings` mapping only vulnerability entries whose severity level is `'PASS'`. |
| `critical_count` | `int` | The calculated count of critical vulnerabilities. |
| `warning_count` | `int` | The calculated count of warning vulnerabilities. |
| `pass_count` | `int` | The calculated count of passed checks. |
| `total_protocols` | `int` | Total number of protocols detected in the assessment. |
| `deprecated_protos`| `List[str]` | List of deprecated protocols (`TLSv1` or `TLSv1.1`) present in the vulnerable list. |
| `score` | `int` | Calculated security health rating (percentage, $10\% \text{ to } 100\%$). |
| `score_rating` | `str` | Qualitative status descriptor (`SECURE`, `STRONG`, `WARNING`, `CRITICAL`). |
| `score_color` | `str` | Hex color code applied to UI elements based on severity. |
| `score_class` | `str` | CSS class name injected into the HTML template to apply custom visual properties. |
| `score_offset` | `int` | Stroke dashoffset used to dynamically update the circular SVG progress meter ($427$ circumference). |

---

## 🔄 5. System Integration

### Data Input & Flow
1. The raw input file path is supplied to the assessment tool, which parses configuration details into the standard Python dictionary format (`findings`).
2. `generate_html_report()` parses the dictionary structure to extract severity metrics.

### HTML Template Placeholders
Once the scoring is resolved, the variables are formatted and injected into the target report templates. Specifically:
- **`<!--SCORE-->`**: Replaced with the calculated `score` value (e.g., `"25"`).
- **`<!--SCORE_RATING-->`**: Replaced with the textual descriptor (`score_rating`).
- **`<!--SCORE_COLOR-->`**: Replaced with the branding HEX code (`score_color`).
- **`<!--SCORE_CLASS-->`**: Replaced with the HTML styling class identifier (`score_class`).
- **`<!--SCORE_OFFSET-->`**: Replaced with `score_offset` to scale the circumference dash length of the animated progress circular gauge:
  ```python
  score_offset = 427 - (427 * score // 100)
  ```
- **Vulnerability/Status Counts**: `<!--CRITICAL_COUNT-->`, `<!--WARNING_COUNT-->`, `<!--PASS_COUNT-->`, and `<!--TOTAL_PROTOCOLS-->` are dynamically populated to display summary statistics at the top of the report.
