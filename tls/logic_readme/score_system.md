# 📋 TLS Security Health Score Logic Documentation

This document explains the security health score calculation rules implemented in the TLS assessment report generator.

---

## 🔍 1. Brief Description of the Function

The logic is part of the `generate_html_report` function located in [report.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/tls/report.py). 

This function accepts a dictionary containing parsed scan data (vulnerabilities, protocols, and ciphers), determines the overall security posture rating (the **Health Score**), maps the rating to corresponding styles/colors, and compiles the standalone HTML report.

---

## 💻 2. The Code Implementation

Here is the exact code block from `generate_html_report` in [report.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/tls/report.py) that calculates the score:

```python
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
```

---

## 🧮 3. Detailed Logic Breakdown

The scoring metric evaluates vulnerabilities in a hierarchical manner:

1.  **Multiple Critical Vulnerabilities**
    *   **Condition**: The system finds two or more vulnerabilities flagged as `CRITICAL`.
    *   **Result**: The score is set to **10%**.
2.  **Single Critical Vulnerability**
    *   **Condition**: The system finds exactly one vulnerability flagged as `CRITICAL`.
    *   **Result**: The score is set to **25%** (regardless of the number of warnings present).
3.  **Single Warning (No Criticals)**
    *   **Condition**: The system finds zero `CRITICAL` issues and exactly one issue flagged as `WARNING`.
    *   **Result**: The score is set to **50%**.
4.  **Multiple Warnings (No Criticals)**
    *   **Condition**: The system finds zero `CRITICAL` issues and more than one issue flagged as `WARNING`.
    *   **Result**: The score starts at a base of `50%` and deducts **5% for each warning** found in the scan:
        $$\text{Score} = 50\% - (\text{warning\_count} \times 5\%)$$
    *   A minimum floor constraint of **10%** is enforced so the score never drops below this value.
5.  **No Issues Found**
    *   **Condition**: The system finds zero `CRITICAL` and zero `WARNING` issues.
    *   **Result**: The score is set to **100%**.

---

## 📋 4. Variables Utilized

*   `critical_count` (*int*): The total count of unique vulnerabilities categorized with a severity of `'CRITICAL'` (e.g. LUCKY13 timing vulnerability).
*   `warning_count` (*int*): The total count of unique vulnerabilities categorized with a severity of `'WARNING'` (e.g. BREACH gzip compression detection).
*   `score` (*int*): The computed final percentage value representing the security status.
*   `score_rating` (*str*): The qualitative assessment text. Maps to:
    *   `SECURE` (for scores $\ge 90\%$)
    *   `STRONG` (for scores $\ge 75\%$)
    *   `WARNING` (for scores $\ge 50\%$)
    *   `CRITICAL` (for scores $< 50\%$)
*   `score_color` (*str*): The hex color representation of the rating (glowing green, blue, orange, or red).
*   `score_class` (*str*): The CSS class name used to apply color-themed status effects.

---

## 🔄 5. Integration in the Code Flow

Once computed, the `score` and associated variables are used to build the HTML elements:

*   **SVG Dashoffset Calculation**:
    The progress ring is an SVG circle with a circumference of $427$ pixels. The script calculates the stroke-dashoffset to draw the correct arc length:
    ```python
    score_offset = 427 - (427 * score // 100)
    ```
    This is injected into the HTML replacement block `<!--SCORE_OFFSET-->`.
*   **Placeholder Replacement**:
    The HTML generation template contains placeholders that are swapped dynamically:
    *   `<!--SCORE-->` is replaced with `str(score)` to print the big number.
    *   `<!--SCORE_COLOR-->` styles the SVG stroke and gauge text label.
    *   `<!--SCORE_RATING-->` updates the text inside the gauge and the Executive Summary description.
