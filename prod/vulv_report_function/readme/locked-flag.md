# Feature: Locked Report Flag (`-locked`)

**Script:** `vulv2/report.py`
**Date:** 2026-07-04
**Updated:** 2026-07-04 (brace escaping fix)

## Data Flow

```
CLI: python report.py domain -locked
  ↓
sys.argv parsed → LOCKED = "-locked" in sys.argv   (line 36)
  ↓
main() calls build_html_report(..., locked=LOCKED)  (line 3304)
  ↓
build_html_report() threads `locked` to:
  ├── UI helpers (inline in f-string template)
  │     _paywall_css(locked)      → CSS or ""
  │     _lock_class(locked)       → " locked-tab" or ""
  │     _lock_icon(locked)        → " &#x1F512;" or ""
  │     _paywall_banner(locked)   → banner HTML or ""
  │     _unlock_js(locked)        → unlockGate JS or ""
  │
  └── Section builders
        _build_ffuf_section(ffuf_data, locked=locked)
        _build_vulners_section(nmap_data, locked=locked)
        _build_vulnerabilities_section(nmap_data, locked=locked)
              └── _gated_section(..., locked=locked)
```

**Key rule:** locked=False is the DEFAULT. All five UI helpers return `""` when not locked. All three section builders show full content without gating. The user must explicitly pass `-locked` to activate the paywall.

## Functions

### `_lock_class(locked)`

- **Purpose:** Return `" locked-tab"` CSS class when locked, empty string otherwise
- **Signature:** `_lock_class(locked)`
- **Called by:** `build_html_report()` inline in the tab button HTML template
- **Behavior:** `" locked-tab" if locked else ""`

### `_lock_icon(locked)`

- **Purpose:** Return lock emoji HTML entity when locked, empty string otherwise
- **Signature:** `_lock_icon(locked)`
- **Called by:** `build_html_report()` inline in the tab button HTML template
- **Behavior:** `" &#x1F512;" if locked else ""`

### `_paywall_banner(locked)`

- **Purpose:** Return the "Premium Content Locked" banner HTML when locked
- **Signature:** `_paywall_banner(locked)`
- **Called by:** `build_html_report()` inline between tab nav and content
- **Behavior:** Uses its own f-string to embed `{FREE_PREVIEW_COUNT}`. Returns full banner div when locked, `""` when not.

### `_unlock_js(locked)`

- **Purpose:** Return the `unlockGate()` JavaScript function when locked
- **Signature:** `_unlock_js(locked)`
- **Called by:** `build_html_report()` inline in the `<script>` block
- **Behavior:** Returns JS function with embedded password from `{PAYWALL_PASSWORD}` when locked, `""` when not.
- **Brace handling:** This is its own f-string. JS function braces use `{{` (f-string escape → single `{` in output). The `{PAYWALL_PASSWORD}` expression resolves to the password string. The returned string is inserted as-is into the outer f-string — braces are NOT re-escaped.

### `_paywall_css(locked)`

- **Purpose:** Return the full paywall CSS block when locked
- **Signature:** `_paywall_css(locked)`
- **Called by:** `build_html_report()` inline in the `<style>` block
- **Behavior:** Returns 70+ lines of paywall CSS rules when locked, `""` when not.
- **Brace handling:** This is a PLAIN triple-quoted string (NOT an f-string). Uses single `{` and `}` for CSS selectors. The returned string is inserted as-is into the outer f-string — no further processing occurs. If `{{` were used here, the output HTML would have invalid double-brace CSS and browsers would silently ignore all the rules.
- **CSS rules returned:** `.paywall-gated`, `.gated-content` (blur + opacity), `.gated-content.unlocked`, `.gated-overlay` (absolute positioning + dark background), `.gated-overlay.unlocked`, `.lock-text`, `.lock-sub`, `.btn-unlock`, `.btn-unlock:hover`, `.pw-input`, `.pw-error`

### `_gated_section(container_id, items, label, free_count=2, locked=True)`

- **Purpose:** Wrap items in a paywall gate when locked, show all items when not
- **Signature:** `_gated_section(container_id, items, label, free_count=2, locked=True)`
- **Called by:** `_build_vulnerabilities_section()`
- **Behavior:** When `locked=False` OR `len(items) <= free_count`: returns all items joined, no gating. When locked with more items than free_count: returns first N items free + gated div wrapping the rest with password overlay.

### `_build_ffuf_section(ffuf_data, locked=True)`

- **Purpose:** Build the Asset Discovery tab content
- **Signature:** `_build_ffuf_section(ffuf_data, locked=True)`
- **Called by:** `build_html_report()` inline f-string
- **Behavior:** When not locked: returns all endpoint rows in a single table, no gating. When locked: gates rows beyond `FREE_PREVIEW_COUNT` behind a separate paywall-gated div with its own table (never inside `<tbody>`).

### `_build_vulners_section(nmap_data, locked=True)`

- **Purpose:** Build the CVE Database tab content
- **Signature:** `_build_vulners_section(nmap_data, locked=True)`
- **Called by:** `build_html_report()` inline f-string
- **Behavior:** When not locked: returns all CVE rows in a single table, no gating. When locked: gates rows beyond `FREE_PREVIEW_COUNT` behind a separate paywall-gated div.

### `_build_vulnerabilities_section(nmap_data, locked=True)`

- **Purpose:** Build the Vulnerabilities tab content with business impact cards
- **Signature:** `_build_vulnerabilities_section(nmap_data, locked=True)`
- **Called by:** `build_html_report()` inline f-string
- **Behavior:** Builds `card_items` list, passes to `_gated_section("gate-vulns", card_items, "Vulnerabilities", FREE_PREVIEW_COUNT, locked=locked)`.

### `build_html_report(nmap_data, dirsearch_data, whatweb_data, ffuf_data, output_path, locked=False)`

- **Purpose:** Orchestrate the full HTML report generation
- **Signature:** `build_html_report(nmap_data, dirsearch_data, whatweb_data, ffuf_data, output_path, locked=False)`
- **Called by:** `main()`
- **Behavior:** Builds a single giant f-string HTML template. Calls all five UI helpers and three section builders with the `locked` parameter. Default is `locked=False` (full display).

## Flags & Commands

| Flag/Command | Effect |
|---|---|
| `-locked` | Generates password-protected report with paywall CSS, locked tabs, banner, gated content, unlockGate JS. Content beyond `FREE_PREVIEW_COUNT` items per section is blurred behind a password overlay. |
| (no flag) | Generates full display report — ALL findings visible, zero paywall elements in the HTML. |

## Usage Examples

```bash
# Full display — all findings visible without password
python vulv2/report.py cybersamurai.co.uk

# Locked report — password-protected gated content
python vulv2/report.py cybersamurai.co.uk -locked

# Flag works in any position
python vulv2/report.py -locked cybersamurai.co.uk
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LOCKED` | `"-locked" in sys.argv` | Module-level boolean set at import (line 36) |
| `PAYWALL_PASSWORD` | `"cybersamurai2024"` | Password to unlock gated content (only relevant in locked mode) |
| `FREE_PREVIEW_COUNT` | `2` | Items shown free per section before gating (only relevant in locked mode) |

## Critical Pitfall: f-string Brace Escaping

The HTML template in `build_html_report()` is a single f-string. When helper functions return strings injected via `{helper(locked)}`, the outer f-string does NOT re-process braces in those strings — they are already resolved values.

**The bug that broke the paywall:** `_paywall_css` and `_unlock_js` originally used `{{` `}}` (the f-string escape for literal braces) because they were copied from inline code. But as standalone functions, their return values are plain strings — `{{` passes through as `{{` into the HTML, producing invalid CSS and broken JS.

**Correct brace usage per function:**

| Function | String type | Braces for selectors/blocks | Why |
|---|---|---|---|
| `_paywall_css` | Plain `"""..."""` | Single `{` and `}` | No f-string processing — braces go straight to HTML |
| `_unlock_js` | f-string `f"""..."""` | `{{` → output `{` | f-string escape → single brace. `{PAYWALL_PASSWORD}` is an f-string expression |
| `_paywall_banner` | f-string `f"""..."""` | N/A (no brace literals) | `{FREE_PREVIEW_COUNT}` is an f-string expression |
| `_lock_class` / `_lock_icon` | Plain Python return | N/A (strings only) | Simple ternaries, no braces involved |

**How to verify the fix:**
```bash
python vulv2/report.py domain -locked
grep -c '{{{{' domain/vulnReport.html    # MUST be 0
grep '\.paywall-gated {' domain/vulnReport.html     # MUST have single brace
grep 'function unlockGate(containerId) {' domain/vulnReport.html  # MUST have single brace
```

## Notes

- The `LOCKED` boolean is set at module level (line 36) before any HTML generation
- The `-locked` flag is filtered from `sys.argv` so it doesn't interfere with domain argument parsing
- When `locked=False`, ALL paywall infrastructure is stripped: no CSS, no JS, no lock icons, no banner, no gated divs
- All five UI helpers return `""` when not locked — no wrapping or conditional HTML needed
- The default is **full display** (locked=False); the user must opt-in to locking with `-locked`
- `PAYWALL_PASSWORD` is a Python variable — it never appears in rendered HTML. Grep for the actual password value (`cybersamurai2024`) to verify it's embedded in the JS.