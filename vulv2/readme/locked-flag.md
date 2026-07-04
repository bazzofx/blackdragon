# Feature: Locked Report Flag (`-locked`)

**Script:** `vulv2/report.py`
**Date:** 2026-07-04

## Functions

### `_lock_class(locked)`

- **Purpose:** Return `" locked-tab"` CSS class when locked, empty string otherwise
- **Signature:** `_lock_class(locked)`
- **Called by:** `build_html_report()` inline in the tab button HTML template
- **Behavior:** Simple ternary — `" locked-tab" if locked else ""`

### `_lock_icon(locked)`

- **Purpose:** Return lock emoji HTML entity when locked, empty string otherwise
- **Signature:** `_lock_icon(locked)`
- **Called by:** `build_html_report()` inline in the tab button HTML template
- **Behavior:** Simple ternary — `" &#x1F512;" if locked else ""`

### `_paywall_banner(locked)`

- **Purpose:** Return the "Premium Content Locked" banner HTML when locked
- **Signature:** `_paywall_banner(locked)`
- **Called by:** `build_html_report()` inline between tab nav and content
- **Behavior:** Returns full banner HTML div when locked, empty string `""` when not locked

### `_unlock_js(locked)`

- **Purpose:** Return the `unlockGate()` JavaScript function when locked
- **Signature:** `_unlock_js(locked)`
- **Called by:** `build_html_report()` inline in the `<script>` block
- **Behavior:** Returns JS function with embedded `PAYWALL_PASSWORD` when locked, empty string `""` when not

### `_paywall_css(locked)`

- **Purpose:** Return the full paywall CSS block when locked
- **Signature:** `_paywall_css(locked)`
- **Called by:** `build_html_report()` inline in the `<style>` block
- **Behavior:** Returns 70+ lines of paywall CSS (`.paywall-gated`, `.gated-content`, `.gated-overlay`, `.btn-unlock`, `.pw-input`, `.pw-error`) when locked, empty string `""` when not

### `_gated_section(container_id, items, label, free_count=2, locked=True)`

- **Modified:** Added `locked` parameter (default `True` for backward compatibility)
- **Behavior:** When `locked=False`, returns ALL items joined without any gating. When `locked=True`, gates items beyond `free_count` behind a paywall div.

### `_build_ffuf_section(ffuf_data, locked=True)`

- **Modified:** Added `locked` parameter
- **Behavior:** When not locked, returns all endpoint rows in a single table without gating. When locked, gates rows beyond `FREE_PREVIEW_COUNT`.

### `_build_vulners_section(nmap_data, locked=True)`

- **Modified:** Added `locked` parameter
- **Behavior:** When not locked, returns all CVE rows in a single table without gating. When locked, gates rows beyond `FREE_PREVIEW_COUNT`.

### `_build_vulnerabilities_section(nmap_data, locked=True)`

- **Modified:** Added `locked` parameter, passed through to `_gated_section()`

### `build_html_report(nmap_data, dirsearch_data, whatweb_data, ffuf_data, output_path, locked=False)`

- **Modified:** Added `locked` parameter (default `False` = full display)
- **Threads** `locked` to all section builders and UI helper functions

## Flags & Commands

| Flag/Command | Effect |
|---|---|
| `-locked` | Generates password-protected report with paywall CSS, locked tabs, banner, gated content, unlockGate JS |
| (no flag) | Generates full display report — all findings visible, no password, no paywall elements |

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
| `LOCKED` | `"-locked" in sys.argv` | Module-level boolean set at import |
| `PAYWALL_PASSWORD` | `"cybersamurai2024"` | Password to unlock gated content (only relevant in locked mode) |
| `FREE_PREVIEW_COUNT` | `2` | Items shown free per section before gating (only relevant in locked mode) |

## Notes

- The `LOCKED` boolean is set at module level (line 35) before any HTML generation
- The `-locked` flag is filtered from `sys.argv` so it doesn't interfere with domain argument parsing
- When `locked=False`, ALL paywall infrastructure is stripped from the HTML: no CSS, no JS, no lock icons, no banner, no gated divs
- All five UI helper functions return empty strings when not locked — no wrapping or conditional HTML
- The default is **full display** (locked=False); the user must opt-in to locking with `-locked`
