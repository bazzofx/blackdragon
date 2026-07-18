#!/usr/bin/env python3
import os
import csv
import sys
import urllib.request
import urllib.error
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common browser user-agent to bypass basic bot blocks
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'

# Typical markers indicating a page is an error or false profile page
ERROR_PATTERNS = [
    r'user not found',
    r'profile not found',
    r'member not found',
    r'no such user',
    r'does not exist',
    r'invalid user',
    r'cannot find the user',
    r'page not found',
    r'error 404',
    r'404 not found',
    r'profile does not exist',
    r'sign up to view',
    r'create an account to',
    r'register to see',
    r'join to see'
]

def check_url_for_profile(url, username):
    """
    Checks a URL's HTML response to verify if the profile actually exists.
    Returns (is_verified, reason)
    """
    req = urllib.request.Request(
        url, 
        headers={'User-Agent': USER_AGENT}
    )
    
    try:
        # Fetch content with a timeout
        with urllib.request.urlopen(req, timeout=8) as response:
            html = response.read().decode('utf-8', errors='ignore')
            
            # 1. Clean HTML to avoid picking up script tags / styles
            text_content = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
            text_content = re.sub(r'<style.*?>.*?</style>', '', text_content, flags=re.DOTALL | re.IGNORECASE)
            text_content = re.sub(r'<.*?>', ' ', text_content)  # strip tags
            
            # 2. Check if username is present in the text (case-insensitive)
            username_present = username.lower() in text_content.lower()
            if not username_present:
                return False, f"Username '{username}' not found in page body."
                
            # 3. Check for typical error signatures (case-insensitive)
            for pattern in ERROR_PATTERNS:
                if re.search(pattern, text_content, re.IGNORECASE):
                    return False, f"Error keyword matched: '{pattern}'"
                    
            return True, "Profile verified (Username present & no error patterns matched)."
            
    except urllib.error.HTTPError as e:
        return False, f"HTTP Error {e.code}"
    except urllib.error.URLError as e:
        return False, f"URL Error: {e.reason}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def verify_csv_reports(input_csv, output_csv):
    """
    Loads a CSV, finds http_code 200 links, verifies them in parallel,
    and updates the http_code/status if they are false positives.
    """
    rows = []
    headers = []
    
    with open(input_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        for row in reader:
            rows.append(row)
            
    # Filter links that returned 200 to verify them
    verification_targets = []
    for idx, row in enumerate(rows):
        if row.get('http_code') == '200':
            verification_targets.append((idx, row.get('url'), row.get('base_username') or row.get('username')))
            
    print(f"Loaded {len(rows)} total rows from {input_csv}.")
    print(f"Found {len(verification_targets)} active (HTTP 200) accounts to verify. Verifying in parallel...")
    
    verified_count = 0
    false_positive_count = 0
    
    # Run requests concurrently using threads
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {
            executor.submit(check_url_for_profile, url, username): (idx, url) 
            for idx, url, username in verification_targets
        }
        
        for future in as_completed(futures):
            idx, url = futures[future]
            try:
                is_verified, reason = future.result()
                if is_verified:
                    verified_count += 1
                else:
                    false_positive_count += 1
                    # Use safe CP1252 prefix [FALSE] instead of emoji flags
                    print(f"[FALSE POSITIVE] {url} | Reason: {reason}")
                    
                    # Update row to reflect false positive status
                    rows[idx]['http_code'] = '404'
                    rows[idx]['status'] = 'Not Found'
                    rows[idx]['confidence'] = '0'
            except Exception as e:
                # Catch encoding/output errors locally
                try:
                    print(f"Error checking {url}: {e}")
                except:
                    print(f"Error checking a URL: {type(e).__name__}")
                
    print("\nVerification Completed:")
    print(f"True Positives: {verified_count}")
    print(f"False Positives Filtered: {false_positive_count}")
    
    # Save the updated file
    with open(output_csv, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"Updated CSV saved to {output_csv}.")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python verify.py <input_csv> <output_csv>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    verify_csv_reports(input_file, output_file)
