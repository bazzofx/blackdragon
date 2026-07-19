#!/usr/bin/env python3
import os
import re
import csv
import json
import glob
import sys

def parse_standard_csv(filepath):
    """
    Parses standard CSV containing columns like base_username, site, http_code, url.
    Filters by status/http_code in (200, 201) and, if present, verified == 'true'.
    """
    accounts = {}
    username = None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Determine username
                if not username:
                    username = row.get('base_username') or row.get('username')
                
                # Check status code
                http_code = row.get('http_code')
                if not http_code:
                    status_val = row.get('status')
                    if status_val and status_val.isdigit():
                        http_code = status_val
                
                # Check if verified column exists and enforce it
                has_verified_field = reader.fieldnames and 'verified' in reader.fieldnames
                if has_verified_field:
                    verified_str = str(row.get('verified') or '').lower()
                    is_verified = (verified_str == 'true') and (http_code in ('200', '201'))
                else:
                    is_verified = (http_code in ('200', '201'))
                
                if is_verified:
                    site = row.get('site')
                    url = row.get('final_url') or row.get('url')
                    if not url:
                        continue
                    
                    if not site:
                        # Extract domain name as site
                        try:
                            from urllib.parse import urlparse
                            domain = urlparse(url).netloc
                            parts = domain.split('.')
                            if len(parts) > 2 and parts[0] == 'www':
                                site = parts[1]
                            elif len(parts) >= 2:
                                site = parts[0]
                            else:
                                site = domain
                        except:
                            site = 'unknown'
                    
                    if site:
                        accounts[site.lower()] = {
                            'site': site.capitalize(),
                            'url': url,
                            'code': int(http_code) if (http_code and http_code.isdigit()) else 200,
                            'status': 'Found'
                        }
    except Exception as e:
        print(f"Error parsing standard CSV {filepath}: {e}")
    
    # Fallback to file prefix for username if not found inside CSV
    if not username:
        base = os.path.basename(filepath)
        username = base.split('_')[0].split('.')[0]
        
    return username, accounts

def parse_maltego_csv(filepath):
    """
    Parses Maltego CSV where columns are SourceEntity, SourceType, TargetEntity, TargetType, Relationship.
    Relationship is 'has-account'.
    """
    accounts = {}
    username = None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                source = row.get('SourceEntity')
                relationship = row.get('Relationship')
                target = row.get('TargetEntity')
                
                if relationship == 'has-account' and source and target:
                    if not username:
                        username = source
                    
                    # TargetEntity is typically username:sitename
                    site_name = target
                    if ':' in target:
                        site_name = target.split(':', 1)[1]
                    
                    accounts[site_name.lower()] = {
                        'site': site_name,
                        'url': None, # Maltego CSV doesn't have URLs
                        'code': 200, # Assume 200 since it is in the Maltego list of connections
                        'status': 'Found'
                    }
    except Exception as e:
        print(f"Error parsing Maltego CSV {filepath}: {e}")
        
    if not username:
        base = os.path.basename(filepath)
        username = base.split('_')[0].split('.')[0]
        
    return username, accounts

def parse_mmd_file(filepath):
    """
    Parses MMD file to extract node relationships if CSV files are not available.
    """
    accounts = {}
    username = None
    node_labels = {}
    edges = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Parse node definitions: n0["fandom"] or n281(["luizcalixt0"])
        # Matches: n[0-9]+...["name"] or ([ "name" ])
        node_def_re = re.compile(r'^\s*(n\d+)(?:\["([^"]+)"\]|\(\["([^"]+)"\]\))', re.MULTILINE)
        for match in node_def_re.finditer(content):
            node_id, label1, label2 = match.groups()
            label = label1 or label2
            node_labels[node_id] = label
            
        # Parse edges: n281 -- has-account --- n0
        edge_re = re.compile(r'^\s*(n\d+)\s+--\s+(\S+)\s+---\s+(n\d+)', re.MULTILINE)
        for match in edge_re.finditer(content):
            source_id, rel, target_id = match.groups()
            edges.append((source_id, rel, target_id))
            
        # The username is usually the source node that connects to many targets
        # Let's find which node has the most outgoing edges
        outgoing_counts = {}
        for src, rel, tgt in edges:
            outgoing_counts[src] = outgoing_counts.get(src, 0) + 1
            
        if outgoing_counts:
            user_node_id = max(outgoing_counts, key=outgoing_counts.get)
            username = node_labels.get(user_node_id)
            
            # Map all targets
            for src, rel, tgt in edges:
                if src == user_node_id and rel == 'has-account':
                    site_name = node_labels.get(tgt)
                    if site_name:
                        accounts[site_name.lower()] = {
                            'site': site_name,
                            'url': None,
                            'code': 200,
                            'status': 'Found'
                        }
    except Exception as e:
        print(f"Error parsing MMD file {filepath}: {e}")
        
    if not username:
        base = os.path.basename(filepath)
        username = base.split('_')[0].split('.')[0]
        
    return username, accounts

def get_url_templates(file_paths):
    """
    Extracts URL templates from standard CSV files.
    e.g. site 'telegram' -> 'https://t.me/{username}'
    """
    templates = {}
    for filepath in file_paths:
        if '_maltego.csv' not in filepath and filepath.endswith('.csv'):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        url = row.get('url') or row.get('final_url')
                        username = row.get('username') or row.get('base_username')
                        if url and username:
                            # Replace username in URL with {username} placeholder (case-insensitive)
                            pattern = re.compile(re.escape(username), re.IGNORECASE)
                            template = pattern.sub('{username}', url)
                            
                            site = row.get('site')
                            if not site:
                                try:
                                    from urllib.parse import urlparse
                                    domain = urlparse(url).netloc
                                    parts = domain.split('.')
                                    if len(parts) > 2 and parts[0] == 'www':
                                        site = parts[1]
                                    elif len(parts) >= 2:
                                        site = parts[0]
                                    else:
                                        site = domain
                                except:
                                    site = 'unknown'
                            
                            if site:
                                templates[site.lower()] = template
            except Exception as e:
                print(f"Error reading templates from {filepath}: {e}")
    return templates

def build_report_data_from_files(file_paths):
    """
    Processes specific list of file paths. Combines accounts, filters HTTP 200 where possible,
    and formats URLs.
    """
    # 1. Gather templates from standard files
    templates = get_url_templates(file_paths)
    
    # 2. Parse each file
    users_data = {}
    for filepath in file_paths:
        if not os.path.exists(filepath):
            print(f"Warning: File {filepath} does not exist!")
            continue
            
        base = os.path.basename(filepath)
        username = base.split('_')[0].split('.')[0]
        
        user_accounts = {}
        if filepath.endswith('_maltego.csv'):
            parsed_username, user_accounts = parse_maltego_csv(filepath)
        elif filepath.endswith('.csv'):
            parsed_username, user_accounts = parse_standard_csv(filepath)
        elif filepath.endswith('.mmd'):
            parsed_username, user_accounts = parse_mmd_file(filepath)
        else:
            print(f"Warning: Unsupported file format {filepath}")
            continue
            
        actual_username = parsed_username or username
        if actual_username not in users_data:
            users_data[actual_username] = {}
        users_data[actual_username].update(user_accounts)
        
    # Reconstruct URLs using templates
    for username, accounts in users_data.items():
        for site_key, acc_info in accounts.items():
            if not acc_info['url']:
                if site_key in templates:
                    acc_info['url'] = templates[site_key].format(username=username)
                else:
                    acc_info['url'] = f"https://www.google.com/search?q={username}+{acc_info['site']}"
                    
    return users_data

def generate_mermaid_code(users_data, shared_sites, user_unique_sites, max_display_shared=15, max_display_unique=5):
    """
    Generates Mermaid graph code. Summarizes overflow nodes to keep it beautiful and uncluttered.
    """
    usernames = sorted(list(users_data.keys()))
    if len(usernames) < 1:
        return ""
        
    lines = [
        "graph TD",
        "    %% Node styling classes",
        "    classDef user fill:#ff2e3b,stroke:#ff2e3b,stroke-width:2px,color:#fff;",
        "    classDef shared fill:#0f0f13,stroke:#10b981,stroke-width:2px,color:#fff;",
        "    classDef unique fill:#0f0f13,stroke:#3b82f6,stroke-width:1.5px,color:#fff;",
        ""
    ]
    
    # Render user nodes
    for idx, u in enumerate(usernames):
        lines.append(f'    u{idx}(["{u}"]):::user')
    lines.append("")
    
    # Sort shared sites for consistency
    shared_list = sorted(list(shared_sites))
    displayed_shared = shared_list[:max_display_shared]
    overflow_shared = shared_list[max_display_shared:]
    
    # 1. Add shared sites
    for i, site in enumerate(displayed_shared):
        node_id = f"s_shared_{i}"
        lines.append(f'    {node_id}["{site}"]:::shared')
        # Link to each user that has this site
        for idx, u in enumerate(usernames):
            if site in users_data[u]:
                lines.append(f"    u{idx} --- {node_id}")
                
    # Summarized shared node if overflow
    if overflow_shared:
        node_id = "s_shared_more"
        lines.append(f'    {node_id}["+ {len(overflow_shared)} More Shared Sites"]:::shared')
        for idx, u in enumerate(usernames):
            has_overflow_site = any(s in users_data[u] for s in overflow_shared)
            if has_overflow_site:
                lines.append(f"    u{idx} --- {node_id}")
                
    # 2. Add unique sites for each user
    for idx, u in enumerate(usernames):
        u_unique = sorted(list(user_unique_sites.get(u, set())))
        displayed_unique = u_unique[:max_display_unique]
        overflow_unique = u_unique[max_display_unique:]
        
        for i, site in enumerate(displayed_unique):
            node_id = f"s_u{idx}_{i}"
            lines.append(f'    {node_id}["{site}"]:::unique')
            lines.append(f"    u{idx} --- {node_id}")
            
        if overflow_unique:
            node_id = f"s_u{idx}_more"
            lines.append(f'    {node_id}["+ {len(overflow_unique)} More Sites"]:::unique')
            lines.append(f"    u{idx} --- {node_id}")
            
    return "\n".join(lines)

def generate_html_report_from_files(file_paths, output_filepath, css_base_dir="."):
    """
    Main aggregator function that parses explicit report files and generates a Vis-Network based interactive dashboard.
    """
    users_data = build_report_data_from_files(file_paths)
    
    usernames = sorted(list(users_data.keys()))
    if len(usernames) < 1:
        print(f"Error: Need at least 1 user to correlate, found: {usernames}")
        return False
        
    # Calculate overlap
    site_users = {}
    all_sites = set()
    for u in usernames:
        for site_key in users_data[u].keys():
            site_users.setdefault(site_key, []).append(u)
            all_sites.add(site_key)
            
    shared_sites = {site for site, u_list in site_users.items() if len(u_list) >= 2}
    unique_sites = {site for site, u_list in site_users.items() if len(u_list) == 1}
    
    user_unique_sites = {u: set() for u in usernames}
    for site_key in unique_sites:
        owner = site_users[site_key][0]
        user_unique_sites[owner].add(site_key)
        
    # Build list of connection entities for JavaScript insertion
    embedded_sites = []
    for site_key in sorted(list(all_sites)):
        first_owner = site_users[site_key][0]
        pretty_name = users_data[first_owner][site_key]['site']
        
        status = 'shared' if site_key in shared_sites else 'unique'
        unique_owner = site_users[site_key][0] if status == 'unique' else None
        
        users_mapping = {}
        for u in usernames:
            if site_key in users_data[u]:
                users_mapping[u] = {
                    'present': True,
                    'url': users_data[u][site_key]['url'],
                    'code': users_data[u][site_key]['code'],
                    'status': users_data[u][site_key]['status']
                }
            else:
                users_mapping[u] = {
                    'present': False,
                    'url': None,
                    'code': None,
                    'status': 'Not Found'
                }
                
        embedded_sites.append({
            'site': pretty_name,
            'status': status,
            'unique_owner': unique_owner,
            'users': users_mapping
        })
        
    # Read global_report.css styling
    css_content = ""
    css_locations = [
        os.path.join(css_base_dir, '..', 'reference', 'global_report.css'),
        os.path.join(css_base_dir, 'reference', 'global_report.css'),
        'C:/Users/joker/OneDrive/Documents/Github/cybersamurai_business/blackdragon/reference/global_report.css'
    ]
    for loc in css_locations:
        if os.path.exists(loc):
            try:
                with open(loc, 'r', encoding='utf-8') as css_f:
                    css_content = css_f.read()
                print(f"Loaded brand stylesheet from: {loc}")
                break
            except Exception as e:
                pass
                
    if not css_content:
        # Fallback styles
        css_content = """
        :root {
            --bg-primary: #070709;
            --bg-secondary: #0f0f13;
            --bg-tertiary: #16161e;
            --accent-red: #ff2e3b;
            --accent-red-glow: rgba(255, 46, 59, 0.45);
            --accent-red-dim: rgba(255, 46, 59, 0.1);
            --text-primary: #ffffff;
            --text-secondary: #9ea2b0;
            --border-color: rgba(255, 255, 255, 0.06);
            --card-bg: rgba(15, 15, 19, 0.75);
            --glass-blur: blur(12px);
            --color-critical: #ff2e3b;
            --color-warning: #f59e0b;
            --color-pass: #10b981;
            --color-info: #3b82f6;
        }
        body { font-family: 'Inter', sans-serif; background: var(--bg-primary); color: var(--text-primary); padding: 40px 24px; }
        """
        
    mermaid_code = generate_mermaid_code(users_data, shared_sites, user_unique_sites)
    
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Samurai - OSINT Connection Report</title>
    
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Outfit:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    
    <!-- Vis Network JavaScript & CSS for interactive graphs -->
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    
    <!-- Mermaid Diagram Library (v9 UMD bundle for global compatibility) -->
    <script src="https://cdn.jsdelivr.net/npm/mermaid@9/dist/mermaid.min.js"></script>
    
    <style>
        /* Inlined global_report.css */
        {{STYLE_SHEET}}
        
        /* Custom styles for the interactive diagram container */
        .tab-btn i {
            margin-right: 6px;
        }
        .connection-table th {
            text-align: left;
            padding: 12px 16px;
            background: rgba(255, 255, 255, 0.02);
            color: var(--text-secondary);
            font-family: 'Outfit', sans-serif;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border-color);
        }
        .connection-table td {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
            vertical-align: middle;
        }
        .connection-table tr:hover {
            background: rgba(255, 255, 255, 0.01);
        }
        .profile-link {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--color-info);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.2s ease;
        }
        .profile-link:hover {
            color: #fff;
            text-decoration: underline;
        }
        .search-container {
            display: flex;
            gap: 12px;
            margin-bottom: 24px;
        }
        .search-box {
            flex: 1;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            padding: 12px 18px;
            border-radius: 8px;
            color: #fff;
            font-size: 14px;
            font-family: 'Inter', sans-serif;
            outline: none;
            transition: all 0.3s ease;
        }
        .search-box:focus {
            border-color: var(--accent-red);
            box-shadow: 0 0 10px rgba(255, 46, 59, 0.25);
        }
        
        /* Interactive Network Layout classes */
        .network-viewport-container {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-bottom: 24px;
        }
        .network-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(15, 15, 19, 0.4);
            border: 1px solid var(--border-color);
            padding: 10px 18px;
            border-radius: 8px;
            flex-wrap: wrap;
            gap: 10px;
        }
        .toolbar-group {
            display: flex;
            gap: 8px;
        }
        .network-div {
            width: 100%;
            height: 600px;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            background: rgba(15, 15, 19, 0.6);
            backdrop-filter: var(--glass-blur);
            position: relative;
            box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.6);
            transition: height 0.3s ease;
        }
        .network-legend {
            display: flex;
            gap: 18px;
            padding: 12px 18px;
            background: rgba(255,255,255,0.01);
            border-radius: 6px;
            border: 1px solid var(--border-color);
            font-size: 12px;
            color: var(--text-secondary);
            align-items: center;
        }
        .legend-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 6px;
            vertical-align: middle;
        }
        
        /* Overlay Modal Styles */
        .modal-overlay {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(7, 7, 9, 0.85);
            backdrop-filter: blur(10px);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.25s ease forwards;
        }
        .modal-content {
            max-width: 440px;
            width: 90%;
            padding: 30px;
            border-radius: 16px;
            background: rgba(15, 15, 19, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 20px 60px rgba(0,0,0,0.8);
            text-align: center;
        }
        .modal-buttons {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 24px;
        }
        .modal-link-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            text-decoration: none;
            padding: 14px;
            font-weight: 600;
            border-radius: 8px;
            font-family: 'Outfit', sans-serif;
            font-size: 14px;
            transition: all 0.2s ease;
        }
        .modal-link-btn-red {
            background: var(--accent-red-dim);
            border: 1px solid var(--accent-red);
            color: #fff;
        }
        .modal-link-btn-red:hover {
            background: var(--accent-red);
            box-shadow: 0 0 15px var(--accent-red-glow);
        }
        .modal-link-btn-blue {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid var(--color-info);
            color: #fff;
        }
        .modal-link-btn-blue:hover {
            background: var(--color-info);
            box-shadow: 0 0 15px rgba(59, 130, 246, 0.4);
        }
        .modal-close-btn {
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-secondary);
            padding: 10px;
            width: 100%;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 14px;
            font-weight: 500;
            transition: all 0.2s ease;
        }
        .modal-close-btn:hover {
            color: #fff;
            background: rgba(255,255,255,0.05);
        }
        
        .mermaid {
            background: rgba(15, 15, 19, 0.5);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            padding: 20px;
            display: flex;
            justify-content: center;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        
        <!-- Floating Header Bar -->
        <header class="header-bar">
            <div class="brand">
                <div class="brand-logo">Cyber<span>Samurai</span></div>
                <div class="brand-japanese">OSINT DIVISION</div>
            </div>
            <div>
                <button onclick="window.print()" class="btn-print">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                    Print Report
                </button>
            </div>
        </header>
        
        <!-- Hero Section -->
        <section class="hero-section">
            <div class="hero-overlay"></div>
            <div class="hero-content">
                <div class="hero-tagline">Correlation Matrix</div>
                <h1 class="hero-title">Interactive Footprint Correlation</h1>
                <p class="summary-text" style="margin-bottom: 20px;">
                    Cross-referencing profile registers to find overlapping locations. This visualizer matches shared handles, accounts, and unique endpoints.
                </p>
                <div class="hero-meta">
{{METADATA_ITEMS}}
                    <div class="meta-item">
                        <span class="meta-label">Scan Constraints</span>
                        <span class="meta-val">Verified HTTP 200 Matches Only</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Date Generated</span>
                        <span class="meta-val" id="generation-time">July 18, 2026</span>
                    </div>
                </div>
            </div>
        </section>
        
        <!-- Quick Stats Grid -->
        <div class="stat-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 24px;">
            <div class="stat-card">
                <span class="stat-val stat-pass">{{STATS_SHARED_SITES}}</span>
                <span class="stat-lbl">Shared Locations</span>
            </div>
            <div class="stat-card">
                <span class="stat-val stat-critical">{{STATS_TARGET_COUNT}}</span>
                <span class="stat-lbl">Correlated Targets</span>
            </div>
            <div class="stat-card">
                <span class="stat-val stat-info">{{STATS_UNIQUE_SITES}}</span>
                <span class="stat-lbl">Unique Platforms</span>
            </div>
            <div class="stat-card">
                <span class="stat-val" style="color: #a78bfa;">{{STATS_TOTAL_SITES}}</span>
                <span class="stat-lbl">Unique Aggregate Footprint</span>
            </div>
        </div>
        
        <!-- Navigation Tabs -->
        <div class="tabs-nav">
            <button class="tab-btn active" onclick="switchTab(event, 'interactive-tab')">
                Interactive Graph (Drag/Zoom)
            </button>
            <button class="tab-btn" onclick="switchTab(event, 'mermaid-tab')">
                Static Diagram
            </button>
            <button class="tab-btn" onclick="switchTab(event, 'data-tab')">
                Footprint Register Table
            </button>
        </div>
        
        <!-- Tab 1: Vis.js Interactive Graph -->
        <div id="interactive-tab" class="tab-content active">
            <div class="glass-card">
                <h3 class="card-title">Dynamic Footprint Topology</h3>
                <p class="summary-text" style="margin-bottom: 16px;">
                    Use mousewheel/trackpad to <strong>zoom</strong> and drag mouse to <strong>move/pan</strong>. Click on any site node to directly navigate to the target profile URLs. Drag nodes to reposition them.
                </p>
                
                <div class="network-viewport-container">
                    <!-- Graph Toolbar -->
                    <div class="network-toolbar">
                        <div class="toolbar-group">
                            <button onclick="zoomNetwork(1.2)" class="btn-print" style="margin: 0;">➕ Zoom In</button>
                            <button onclick="zoomNetwork(0.8)" class="btn-print" style="margin: 0;">➖ Zoom Out</button>
                            <button onclick="fitNetwork()" class="btn-print" style="margin: 0;">🔍 Fit Screen</button>
                            <button onclick="togglePhysics()" id="physics-btn" class="btn-print" style="margin: 0;">⏸️ Freeze Layout</button>
                        </div>
                        <div class="toolbar-group">
                            <button onclick="resizeContainer(150)" class="btn-print" style="margin: 0;">↕️ Expand Graph</button>
                            <button onclick="resizeContainer(-150)" class="btn-print" style="margin: 0;">↕️ Shrink Graph</button>
                        </div>
                    </div>
                    
                    <!-- Graph Viewport -->
                    <div id="mynetwork" class="network-div"></div>
                    
                    <!-- Graph Legend -->
                    <div class="network-legend">
                        <span><strong>Legend:</strong></span>
                        <span><span class="legend-dot" style="background: #ff2e3b; box-shadow: 0 0 10px #ff2e3b;"></span> Target Identity</span>
                        <span><span class="legend-dot" style="background: #16161e; border: 2px solid #10b981; box-shadow: 0 0 8px #10b981;"></span> Shared Connection (HTTP 200 both)</span>
                        <span><span class="legend-dot" style="background: #16161e; border: 2px solid #3b82f6; box-shadow: 0 0 8px #3b82f6;"></span> Unique Endpoint (HTTP 200 one)</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Tab 2: Static Graph (Mermaid) -->
        <div id="mermaid-tab" class="tab-content">
            <div class="glass-card">
                <h3 class="card-title">Footprint Link Analysis</h3>
                <p class="summary-text" style="margin-bottom: 20px;">
                    Below is a classic static mapping of node overlaps for print output and reference.
                </p>
                <div class="mermaid">
{{MERMAID_GRAPH}}
                </div>
            </div>
        </div>
        
        <!-- Tab 3: Detailed Connections Table -->
        <div id="data-tab" class="tab-content">
            <div class="glass-card">
                <h3 class="card-title">Affiliation Register</h3>
                
                <!-- Search & Filters -->
                <div class="search-container">
                    <input type="text" id="site-search" class="search-box" placeholder="Filter sites by name (e.g. telegram, github)..." onkeyup="filterData()">
                    <select id="filter-type" class="search-box" style="max-width: 200px;" onchange="filterData()">
                        {{FILTER_OPTIONS}}
                    </select>
                </div>
                
                <!-- Table -->
                <div style="overflow-x: auto; width: 100%;">
                    <table class="cert-table connection-table">
                        <thead>
                            {{THEAD_CONTENT}}
                        </thead>
                        <tbody id="connections-tbody">
                            <!-- Dynamic Content Rendered by JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <footer class="footer">
            <p>&copy; 2026 Cyber Samurai Business - Black Dragon OSINT Report Tool</p>
            <p style="font-size: 11px; margin-top: 5px; color: var(--text-muted);">Confidential - For Cyber Samurai Authorized Personnel Only</p>
        </footer>
        
    </div>
    
    <!-- Profile Click Selection Modal -->
    <div id="profile-modal" class="modal-overlay" style="display:none;">
        <div class="modal-content glass-card">
            <h4 class="card-title" id="modal-site-title" style="justify-content: center; font-size: 20px;">Correlation Link</h4>
            <p class="summary-text" style="margin-bottom: 20px; font-size: 14px;">Select which target profile you would like to open:</p>
            <div class="modal-buttons" id="modal-buttons-container">
                <!-- Dynamic buttons rendered by JS -->
            </div>
            <button onclick="closeModal()" class="modal-close-btn">Cancel</button>
        </div>
    </div>
    
    <!-- Script holding raw data and logic -->
    <script>
        // Set date
        document.getElementById('generation-time').innerText = new Date().toLocaleString();
        
        // Embedded OSINT data
        const osintData = {{JSON_DATA}};
        
        // Modal helpers
        function closeModal() {
            document.getElementById('profile-modal').style.display = 'none';
        }
        
        // Initialize Mermaid
        mermaid.initialize({
            startOnLoad: false,
            theme: 'dark',
            themeVariables: {
                background: '#0f0f13',
                primaryColor: '#0f0f13',
                primaryTextColor: '#fff',
                lineColor: '#5f6377'
            }
        });
        
        // Tab switching
        function switchTab(evt, tabId) {
            const tabContents = document.getElementsByClassName("tab-content");
            for (let i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove("active");
            }
            
            const tabBtns = document.getElementsByClassName("tab-btn");
            for (let i = 0; i < tabBtns.length; i++) {
                tabBtns[i].classList.remove("active");
            }
            
            document.getElementById(tabId).classList.add("active");
            evt.currentTarget.classList.add("active");
            
            // Re-init graphics rendering if tabs are visible
            if (tabId === 'mermaid-tab') {
                mermaid.init(undefined, document.getElementsByClassName('mermaid'));
            } else if (tabId === 'interactive-tab') {
                network.fit();
            }
        }
        
        // Render table rows
        function renderTable(sites) {
            const tbody = document.getElementById('connections-tbody');
            tbody.innerHTML = '';
            
            if (sites.length === 0) {
                tbody.innerHTML = `<tr><td colspan="${2 + osintData.users.length}" style="text-align: center; color: var(--text-muted); padding: 30px;">No matching connection records found.</td></tr>`;
                return;
            }
            
            sites.forEach(item => {
                const tr = document.createElement('tr');
                
                // Site cell
                const siteTd = document.createElement('td');
                siteTd.style.fontWeight = '600';
                siteTd.innerText = item.site;
                tr.appendChild(siteTd);
                
                // Correlation Badge cell
                const corrTd = document.createElement('td');
                if (item.status === 'shared') {
                    const count = Object.values(item.users).filter(u => u.present).length;
                    corrTd.innerHTML = `<span class="badge badge-green">Shared (${count}/${osintData.users.length})</span>`;
                } else {
                    corrTd.innerHTML = `<span class="badge badge-blue">Unique (${item.unique_owner})</span>`;
                }
                tr.appendChild(corrTd);
                
                // Add a cell for each user profile link
                osintData.users.forEach(username => {
                    const uTd = document.createElement('td');
                    const uData = item.users[username];
                    if (uData.present) {
                        uTd.innerHTML = `<a href="${uData.url}" target="_blank" class="profile-link">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                            ${uData.status} (HTTP ${uData.code})
                        </a>`;
                    } else {
                        uTd.innerHTML = '<span style="color: var(--text-muted);">-</span>';
                    }
                    tr.appendChild(uTd);
                });
                
                tbody.appendChild(tr);
            });
        }
        
        // Filter table data based on input search & filter dropdown
        function filterData() {
            const query = document.getElementById('site-search').value.toLowerCase().trim();
            const filterVal = document.getElementById('filter-type').value;
            
            let filtered = osintData.sites;
            
            if (filterVal === 'shared') {
                filtered = filtered.filter(item => item.status === 'shared');
            } else if (filterVal.startsWith('unique-')) {
                const targetUser = filterVal.substring(7);
                filtered = filtered.filter(item => item.status === 'unique' && item.unique_owner === targetUser);
            }
            
            if (query) {
                filtered = filtered.filter(item => item.site.toLowerCase().includes(query));
            }
            
            renderTable(filtered);
        }
        
        // Build Vis Network interactive nodes and edges
        var nodesArray = [];
        var edgesArray = [];
        
        // 1. Add User Identity Nodes
        osintData.users.forEach((username, idx) => {
            nodesArray.push({
                id: username,
                label: username,
                shape: 'dot',
                size: 38,
                color: {
                    background: '#ff2e3b',
                    border: '#ff2e3b',
                    highlight: {
                        background: '#ff5c67',
                        border: '#ff5c67'
                    }
                },
                font: {
                    color: '#ffffff',
                    size: 16,
                    face: 'Outfit',
                    bold: 'bold'
                },
                shadow: {
                    enabled: true,
                    color: 'rgba(255, 46, 59, 0.45)',
                    size: 15
                }
            });
        });
        
        // 2. Add Site Platform Nodes & Connections
        osintData.sites.forEach((item, idx) => {
            var siteId = 'site_' + idx;
            var isShared = item.status === 'shared';
            var bgColor = '#0f0f13';
            var borderColor = isShared ? '#10b981' : '#3b82f6';
            var highlightColor = isShared ? '#10b981' : '#3b82f6';
            var shadowColor = isShared ? 'rgba(16, 185, 129, 0.35)' : 'rgba(59, 130, 246, 0.35)';
            
            nodesArray.push({
                id: siteId,
                label: item.site,
                shape: 'dot',
                size: isShared ? 20 : 13,
                color: {
                    background: bgColor,
                    border: borderColor,
                    highlight: {
                        background: '#16161e',
                        border: highlightColor
                    }
                },
                font: {
                    color: '#9ea2b0',
                    size: 12,
                    face: 'Inter'
                },
                shadow: {
                    enabled: true,
                    color: shadowColor,
                    size: 10
                },
                customData: item
            });
            
            // Add linking lines (edges) to active users
            osintData.users.forEach(username => {
                if (item.users[username].present) {
                    edgesArray.push({
                        from: username,
                        to: siteId,
                        color: {
                            color: isShared ? 'rgba(16, 185, 129, 0.45)' : 'rgba(95, 99, 119, 0.35)',
                            highlight: isShared ? '#10b981' : '#3b82f6'
                        },
                        width: isShared ? 2 : 1.2
                    });
                }
            });
        });
        
        var container = document.getElementById('mynetwork');
        var data = {
            nodes: new vis.DataSet(nodesArray),
            edges: new vis.DataSet(edgesArray)
        };
        var options = {
            nodes: {
                borderWidth: 2,
                shadow: true
            },
            edges: {
                width: 1.5,
                selectionWidth: 2,
                smooth: {
                    type: 'continuous',
                    forceDirection: 'none'
                }
            },
            interaction: {
                hover: true,
                zoomView: true,
                dragView: true
            },
            physics: {
                stabilization: {
                    iterations: 150,
                    updateInterval: 25
                },
                barnesHut: {
                    gravitationalConstant: -4000,
                    centralGravity: 0.35,
                    springLength: 100,
                    springConstant: 0.04,
                    damping: 0.09,
                    avoidOverlap: 1
                }
            }
        };
        
        var network = new vis.Network(container, data, options);
        
        // Click handler to open external links
        network.on("click", function (params) {
            if (params.nodes.length > 0) {
                var nodeId = params.nodes[0];
                if (osintData.users.includes(nodeId)) {
                    return; // Ignore user nodes
                }
                
                var nodeObj = data.nodes.get(nodeId);
                if (nodeObj && nodeObj.customData) {
                    var item = nodeObj.customData;
                    
                    if (item.status === 'shared') {
                        document.getElementById('modal-site-title').innerText = item.site + " Links";
                        
                        const btnContainer = document.getElementById('modal-buttons-container');
                        btnContainer.innerHTML = '';
                        
                        osintData.users.forEach((username, uIdx) => {
                            const uData = item.users[username];
                            if (uData.present) {
                                const link = document.createElement('a');
                                link.href = uData.url;
                                link.target = '_blank';
                                link.className = `modal-link-btn ${uIdx % 2 === 0 ? 'modal-link-btn-red' : 'modal-link-btn-blue'}`;
                                link.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg> Open ${username} Profile`;
                                btnContainer.appendChild(link);
                            }
                        });
                        
                        document.getElementById('profile-modal').style.display = 'flex';
                    } else {
                        // Direct navigation for unique links
                        var url = item.users[item.unique_owner].url;
                        if (url) {
                            window.open(url, '_blank');
                        }
                    }
                }
            }
        });
        
        // Toolbar actions
        var isPhysicsActive = true;
        function togglePhysics() {
            isPhysicsActive = !isPhysicsActive;
            network.setOptions({ physics: { enabled: isPhysicsActive } });
            document.getElementById('physics-btn').innerText = isPhysicsActive ? "⏸️ Freeze Layout" : "▶️ Settle Layout";
        }
        function zoomNetwork(factor) {
            network.moveTo({ scale: network.getScale() * factor });
        }
        function fitNetwork() {
            network.fit();
        }
        var currentHeight = 600;
        function resizeContainer(amount) {
            currentHeight = Math.max(300, Math.min(1200, currentHeight + amount));
            document.getElementById('mynetwork').style.height = currentHeight + 'px';
            network.setSize('100%', currentHeight + 'px');
        }
        
        // Initial table rendering
        renderTable(osintData.sites);
    </script>
</body>
</html>"""
    
    # Build metadata block HTML
    meta_items = []
    for idx, u in enumerate(usernames):
        label = f"Target {chr(65+idx)}" if idx < 26 else f"Target {idx+1}"
        meta_items.append(f"""                    <div class="meta-item">
                        <span class="meta-label">{label}</span>
                        <span class="meta-val">{u}</span>
                    </div>""")
    meta_items_html = '\n'.join(meta_items)
    
    # Build filter dropdown options HTML
    filter_options = [
        '<option value="all">All Platforms</option>',
        '<option value="shared">Shared Platforms Only</option>'
    ]
    for u in usernames:
        filter_options.append(f'<option value="unique-{u}">{u} Unique</option>')
    filter_options_html = '\n'.join(filter_options)
    
    # Build table head HTML
    thead_cols = ["<th>Site Platform</th>", "<th>Correlation Type</th>"]
    for u in usernames:
        thead_cols.append(f"<th>{u} URL</th>")
    thead_html = f"<tr>{' '.join(thead_cols)}</tr>"
    
    # Fill HTML template
    html_output = html_template
    html_output = html_output.replace('{{STYLE_SHEET}}', css_content)
    html_output = html_output.replace('{{METADATA_ITEMS}}', meta_items_html)
    html_output = html_output.replace('{{STATS_SHARED_SITES}}', str(len(shared_sites)))
    html_output = html_output.replace('{{STATS_TARGET_COUNT}}', str(len(usernames)))
    html_output = html_output.replace('{{STATS_UNIQUE_SITES}}', str(len(unique_sites)))
    html_output = html_output.replace('{{STATS_TOTAL_SITES}}', str(len(all_sites)))
    html_output = html_output.replace('{{FILTER_OPTIONS}}', filter_options_html)
    html_output = html_output.replace('{{THEAD_CONTENT}}', thead_html)
    html_output = html_output.replace('{{MERMAID_GRAPH}}', mermaid_code)
    html_output = html_output.replace('{{JSON_DATA}}', json.dumps({
        'users': usernames,
        'sites': embedded_sites
    }, indent=4))
    
    # Save the output file
    try:
        with open(output_filepath, 'w', encoding='utf-8') as out_f:
            out_f.write(html_output)
        print(f"Interactive OSINT correlation HTML report generated at {output_filepath}")
        return True
    except Exception as e:
        print(f"Error saving HTML report to {output_filepath}: {e}")
        return False

if __name__ == '__main__':
    args = sys.argv[1:]
    
    # Defaults
    target_dir = os.path.dirname(os.path.abspath(__file__))
    output_html = None
    csv_inputs = []
    
    for arg in args:
        if arg.endswith('.html'):
            output_html = arg
        elif arg.endswith('.csv') or arg.endswith('.mmd'):
            csv_inputs.append(arg)
        elif os.path.isdir(arg):
            target_dir = arg
            
    if not output_html:
        output_html = os.path.join(target_dir, 'osint_correlation_report.html')
        
    if csv_inputs:
        print(f"Correlating specific files: {csv_inputs}")
        generate_html_report_from_files(csv_inputs, output_html, css_base_dir=target_dir)
    else:
        print(f"Scanning directory for report files in: {target_dir}")
        # Automatically gather all csv/mmd files in target directory
        all_files = glob.glob(os.path.join(target_dir, '*.csv')) + glob.glob(os.path.join(target_dir, '*.mmd'))
        # Exclude already processed HTML and _maltego files unless there's no standard csv
        std_csvs = [f for f in all_files if not f.endswith('_maltego.csv') and f.endswith('.csv')]
        maltego_csvs = [f for f in all_files if f.endswith('_maltego.csv')]
        mmds = [f for f in all_files if f.endswith('.mmd')]
        
        # Select one per user
        selected_files = []
        users_added = set()
        
        # Prioritize Standard CSV
        for f in std_csvs:
            user = os.path.basename(f).split('_')[0]
            if user not in users_added:
                selected_files.append(f)
                users_added.add(user)
                
        # Fallback to Maltego CSV
        for f in maltego_csvs:
            user = os.path.basename(f).split('_')[0]
            if user not in users_added:
                selected_files.append(f)
                users_added.add(user)
                
        # Fallback to MMD
        for f in mmds:
            user = os.path.basename(f).split('_')[0]
            if user not in users_added:
                selected_files.append(f)
                users_added.add(user)
                
        print(f"Discovered report files: {selected_files}")
        generate_html_report_from_files(selected_files, output_html, css_base_dir=target_dir)
