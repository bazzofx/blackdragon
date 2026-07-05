# Feature: Locked Report Flag (`-locked`) for SSL/TLS Reports

**Script:** `prod/ssl_report_function/report.py`  
**Updated:** 2026-07-05 (Updated free preview count to 2, added Action Roadmap and Vulnerabilities gating)

---

## 🔍 Summary

The `-locked` feature enables generating password-protected, premium-gated security reports for clients. When the report is generated in **Locked** mode:
1. **Limited Preview**: Only the first **2** items/findings in both the **Vulnerabilities** and **Action Roadmap** tabs are visible.
2. **Password Gate Overlay**: Content beyond the first 2 items is blurred (`filter: blur(6px)`) and covered by an overlay prompting the client for a password.
3. **Interactive Unlock**: Entering the correct password (`cybersamurai2024`) dynamically reveals all findings.
4. **Tab Lock Indicators**: Padlock icons (`🔒`) and visual cues are appended to the tab headers.

If the `-locked` flag is omitted, the report is generated in **Full Display** mode with zero gating or password requirements.

---

## 🛠️ How to Use

To generate a locked report, run [report.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/prod/ssl_report_function/report.py) with the `-locked` flag.

### Command Examples

```bash
# Standard Full Report (unlocked)
python prod/ssl_report_function/report.py rawTLSReport.html -o enhancedTLSReport.html

# Password-Protected Locked Report
python prod/ssl_report_function/report.py rawTLSReport.html -o enhancedTLSReport.html -locked
```

### Script Orchestration via Bash Wrapper

The [fetch.sh](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/prod/ssl_report_function/fetch.sh) script orchestrates the Docker-based scan and calls `report.py`. To run a locked scan automatically, you can edit [fetch.sh](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/prod/ssl_report_function/fetch.sh) to append the `-locked` flag to the Python execution command on line 73:

```bash
python3 "$SCRIPT_DIR/report.py" -o "$folder/enhancedTLSReport.html" "$folder/rawTLSReport.html" -locked
```

---

## ⚙️ Configuration

The paywall parameters are configured at the module level in [report.py](file:///C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/prod/ssl_report_function/report.py#L621-L623):

| Variable | Default Value | Purpose |
| --- | --- | --- |
| `PAYWALL_PASSWORD` | `"cybersamurai2024"` | Password required to unlock the gated sections. |
| `FREE_PREVIEW_COUNT` | `2` | Number of items visible in each section before the content is gated. |

---

## 💻 Code Blocks Used

Below are the primary Python and Javascript code blocks that implement this feature:

### 1. Module Configuration & Helpers
The helper functions return styling classes, icon emojis, banner advertisements, styling blocks, and JavaScript logic dynamically depending on the `locked` status:

```python
# Configuration
PAYWALL_PASSWORD = "cybersamurai2024"
FREE_PREVIEW_COUNT = 2

def _lock_class(locked):
    """Return ' locked-tab' class if locked, empty string otherwise."""
    return " locked-tab" if locked else ""

def _lock_icon(locked):
    """Return lock icon HTML entity if locked, empty string otherwise."""
    return " &#x1F512;" if locked else ""

def _paywall_banner(locked):
    """Return paywall banner HTML if locked, empty string otherwise."""
    if not locked:
        return ""
    return f"""\
        <!-- Paywall promotion banner -->
        <div class="highlight-box paywall-banner" style="background:rgba(255,46,59,0.08);border:1px solid rgba(255,46,59,0.2);margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
            <span style="font-size:13px">&#x1F512; <strong style="color:var(--color-critical)">Premium Content Locked</strong> — The first {FREE_PREVIEW_COUNT} findings in each section are free. Enter the password to reveal all results.</span>
            <span style="font-size:11px;color:var(--text-muted)">Contact Cyber Samurai to obtain your unlock code.</span>
        </div>"""
```

### 2. Gated Section Generator (`_gated_section`)
This function splits the items list into free and gated blocks, wraps the gated portion in a container, and embeds the interactive unlock gate overlay:

```python
def _gated_section(container_id, items, label, free_count=2, locked=True):
    """Wrap items in a paywall gate: show first `free_count` free, blur the rest behind a password.
    When locked=False, all items are shown without gating."""
    if not locked or len(items) <= free_count:
        return "".join(items)

    free_html = "".join(items[:free_count])
    gated_html = "".join(items[free_count:])

    return free_html + f"""
    <div class="paywall-gated" id="{container_id}">
        <div class="gated-content">
            {gated_html}
        </div>
        <div class="gated-overlay">
            <span class="lock-text">&#x1F512; {len(items) - free_count} More {label} Locked</span>
            <span class="lock-sub">Enter password to reveal all {len(items)} {label.lower()}</span>
            <input type="password" class="pw-input" placeholder="Password" onkeydown="if(event.key==='Enter')unlockGate('{container_id}')">
            <span class="pw-error">Incorrect password</span>
            <button class="btn-unlock" onclick="unlockGate('{container_id}')">Unlock</button>
        </div>
    </div>"""
```

### 3. Action Roadmap Gating Logic
Splits the prioritized roadmap entries across Critical, High, and Medium priority categories, displaying only up to `FREE_PREVIEW_COUNT` total items:

```python
    total_roadmap_count = len(all_roadmap_items)
    
    if not locked or total_roadmap_count <= FREE_PREVIEW_COUNT:
        # Full render flow ...
    else:
        # Gated mode: show first FREE_PREVIEW_COUNT free, gate the rest
        free_items = all_roadmap_items[:FREE_PREVIEW_COUNT]
        gated_items = all_roadmap_items[FREE_PREVIEW_COUNT:]
        
        # Build free_html & gated_html loops ...
```

### 4. Interactive JavaScript Unlock Mechanism
Validates input dynamically in the browser against the configuration value:

```javascript
function unlockGate(containerId) {
    var container = document.getElementById(containerId);
    if (!container) return;
    var overlay = container.querySelector('.gated-overlay');
    var input = overlay.querySelector('.pw-input');
    var error = overlay.querySelector('.pw-error');
    var pw = input.value.trim();
    if (pw === 'cybersamurai2024') {
        container.classList.add('unlocked');
    } else {
        error.style.display = 'block';
        input.value = '';
        input.focus();
    }
}
```

---

## 🛡️ Verification & Diagnostics

To verify the generated report correctness, grep the produced HTML file for double-braces `{{` or `}}` which would indicate broken Javascript/CSS formatting:

```bash
# Verify double-braces (must return 0)
grep -c '{{' enhancedTLSReport.html

# Verify container definitions are present
grep -i 'gate-roadmap' enhancedTLSReport.html
grep -i 'gate-vulns' enhancedTLSReport.html
```
