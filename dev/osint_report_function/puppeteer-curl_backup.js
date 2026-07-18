#!/usr/bin/env node
/**
 * puppeteer-curl.js
 * A standalone Puppeteer CLI tool mimicking 'curl' that evades detection,
 * fetches fully-rendered page content, and computes profile verification
 * confidence scores by looking for a target username and checking against 
 * typical error signatures.
 */

const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// Safely require puppeteer
let puppeteer;
try {
    puppeteer = require('puppeteer');
} catch (err) {
    console.error('❌ Error: Puppeteer is not installed in this environment.');
    console.error('Please run: npm install puppeteer');
    process.exit(1);
}

// Typical markers indicating a page is an error or false profile page
const ERROR_PATTERNS = [
    /user not found/i,
    /profile not found/i,
    /member not found/i,
    /no such user/i,
    /does not exist/i,
    /invalid user/i,
    /cannot find the user/i,
    /page not found/i,
    /error 404/i,
    /404 not found/i,
    /profile does not exist/i,
    /sign up to view/i,
    /create an account to/i,
    /register to see/i,
    /join to see/i,
    /access denied/i
];

function printHelp() {
    console.log(`
puppeteer-curl.js - Browser-mimicking curl with OSINT Username Verification

USAGE:
  node puppeteer-curl.js <URL> [OPTIONS]

OPTIONS:
  -u, --username <name>     Username to search for in page body.
                            Enables confidence score estimation:
                            - Base 75% if page loads successfully.
                            - Adds +25% (total 100%) if username is found.
                            - Drops to 0% if error patterns match or status >= 400.
  -H, --header "Name: Val"  Add custom HTTP header (can be used multiple times).
  -o, --output <file>       Save response HTML to file instead of printing to stdout.
  -t, --timeout <ms>        Navigation timeout in milliseconds (default: 30000).
  -p, --proxy <url>         Use proxy server (e.g., http://127.0.0.1:8080).
  --json                    Output metadata & verification results as JSON to stdout
                            instead of raw HTML.
  --summary                 Output a human-readable verification summary instead of raw HTML.
  --no-headless             Run browser in visible (headful) mode.
  -d, --debug               Enable debug logs (printed to stderr).
  -h, --help                Show this help message.

EXAMPLES:
  # Standard fetch (prints HTML body to stdout, logs/stats to stderr)
  node puppeteer-curl.js https://github.com/luizcalixt0

  # Fetch and verify username
  node puppeteer-curl.js https://github.com/luizcalixt0 -u luizcalixt0

  # Fetch, verify username, and get output in JSON format
  node puppeteer-curl.js https://github.com/luizcalixt0 -u luizcalixt0 --json

  # Fetch with custom headers and save to a file
  node puppeteer-curl.js https://github.com/luizcalixt0 -H "Cookie: session=xyz" -o out.html
    `);
}

async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
        printHelp();
        process.exit(0);
    }

    // Parse options
    let url = null;
    let username = null;
    const headers = {};
    let outputFile = null;
    let timeout = 30000;
    let proxy = null;
    let jsonMode = false;
    let summaryMode = false;
    let headless = 'new';
    let debug = false;

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        const nextArg = args[i + 1];

        if ((arg === '-u' || arg === '--username') && nextArg) {
            username = nextArg;
            i++;
        } else if ((arg === '-H' || arg === '--header') && nextArg) {
            const separatorIdx = nextArg.indexOf(':');
            if (separatorIdx > -1) {
                const name = nextArg.substring(0, separatorIdx).trim();
                const value = nextArg.substring(separatorIdx + 1).trim();
                headers[name] = value;
            } else {
                console.warn(`[WARNING] Invalid header format: "${nextArg}". Expected "Name: Value".`);
            }
            i++;
        } else if ((arg === '-o' || arg === '--output') && nextArg) {
            outputFile = nextArg;
            i++;
        } else if ((arg === '-t' || arg === '--timeout') && nextArg) {
            timeout = parseInt(nextArg, 10);
            i++;
        } else if ((arg === '-p' || arg === '--proxy') && nextArg) {
            proxy = nextArg;
            i++;
        } else if (arg === '--json') {
            jsonMode = true;
        } else if (arg === '--summary') {
            summaryMode = true;
        } else if (arg === '--no-headless') {
            headless = false;
        } else if (arg === '-d' || arg === '--debug') {
            debug = true;
        } else if (arg.startsWith('http://') || arg.startsWith('https://')) {
            url = arg;
        }
    }

    if (!url) {
        console.error('❌ Error: No URL provided. First argument or option must be a valid HTTP/HTTPS URL.');
        process.exit(1);
    }

    const logDebug = (msg) => {
        if (debug) {
            console.error(`[DEBUG] ${msg}`);
        }
    };

    logDebug(`Target URL: ${url}`);
    if (username) logDebug(`Target Username: ${username}`);
    logDebug(`Timeout: ${timeout}ms`);
    if (proxy) logDebug(`Proxy: ${proxy}`);

    // Build puppeteer launch arguments
    const launchArgs = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-features=IsolateOrigins,site-per-process',
        '--window-size=1920,1080'
    ];

    if (proxy) {
        launchArgs.push(`--proxy-server=${proxy}`);
    }

    let browser;
    try {
        logDebug('Launching headless browser...');
        browser = await puppeteer.launch({
            headless: headless,
            args: launchArgs,
            timeout: 30000
        });
    } catch (launchError) {
        console.error(`❌ Error: Failed to launch Puppeteer browser: ${launchError.message}`);
        process.exit(1);
    }

    try {
        const page = await browser.newPage();

        // 1. Evade standard detection flags
        logDebug('Injecting anti-detection scripts...');
        
        // Hide webdriver flag
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
        });

        // Set realistic viewport
        await page.setViewport({ width: 1920, height: 1080 });

        // Set realistic browser headers to mimic Chrome
        const userAgent = headers['User-Agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        await page.setUserAgent(userAgent);

        const defaultHeaders = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            ...headers
        };

        logDebug(`Setting headers: ${JSON.stringify(defaultHeaders)}`);
        await page.setExtraHTTPHeaders(defaultHeaders);

        // 2. Perform Navigation
        logDebug(`Navigating to ${url}...`);
        const response = await page.goto(url, {
            waitUntil: 'networkidle2',
            timeout: timeout
        });

        if (!response) {
            throw new Error('No HTTP response received from page navigation.');
        }

        const statusCode = response.status();
        const finalUrl = response.url();
        logDebug(`Navigation completed. Status: ${statusCode}, Final URL: ${finalUrl}`);

        // Wait a bit for async JS execution just to make sure content loads fully
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Get fully rendered page body and inner text
        const renderedHtml = await page.content();
        const textContent = await page.evaluate(() => document.body ? document.body.innerText : '');
        const pageTitle = await page.title();

        await browser.close();
        browser = null;

        // 3. Process Verification & Confidence Scoring
        let verified = false;
        let baseConfidence = 0;
        let bonusConfidence = 0;
        let confidenceScore = 0;
        let usernameFound = false;
        let matchedErrorPattern = null;

        if (statusCode >= 400) {
            matchedErrorPattern = `HTTP Error Status Code: ${statusCode}`;
        } else {
            // Check for profile error keywords in the visible text content
            for (const pattern of ERROR_PATTERNS) {
                if (pattern.test(textContent)) {
                    matchedErrorPattern = String(pattern);
                    break;
                }
            }

            if (!matchedErrorPattern) {
                // If the page loaded successfully (HTTP 200) and no error patterns matched
                verified = true;
                baseConfidence = 75;

                if (username) {
                    // Check if the username is found within the body or the title of the page (case-insensitive)
                    usernameFound = textContent.toLowerCase().includes(username.toLowerCase()) || 
                                    pageTitle.toLowerCase().includes(username.toLowerCase());
                    if (usernameFound) {
                        bonusConfidence = 25; // Increase confidence score by +25%
                    }
                }
                confidenceScore = baseConfidence + bonusConfidence;
            }
        }

        // 4. Output Results
        const resultObject = {
            url: url,
            final_url: finalUrl,
            status: statusCode,
            title: pageTitle,
            username: username || null,
            username_found: usernameFound,
            matched_error_pattern: matchedErrorPattern,
            base_confidence: baseConfidence,
            bonus_confidence: bonusConfidence,
            confidence_score: confidenceScore,
            verified: verified,
            body_length: renderedHtml.length
        };

        if (jsonMode) {
            // JSON Output to stdout
            console.log(JSON.stringify(resultObject, null, 2));
        } else if (summaryMode) {
            // Human-readable summary to stdout
            console.log(`=== Verification Summary for ${url} ===`);
            console.log(`Final URL:             ${finalUrl}`);
            console.log(`HTTP Status Code:      ${statusCode}`);
            console.log(`Page Title:            ${pageTitle}`);
            console.log(`Verified Status:       ${verified ? 'YES' : 'NO'}`);
            if (matchedErrorPattern) {
                console.log(`Error Pattern Match:   ${matchedErrorPattern}`);
            }
            if (username) {
                console.log(`Target Username:       ${username}`);
                console.log(`Username Found in Page: ${usernameFound ? 'YES (+25% confidence)' : 'NO'}`);
            }
            console.log(`Confidence Score:      ${confidenceScore}%`);
            console.log(`HTML Length:           ${renderedHtml.length} bytes`);
        } else {
            // Default: Mimic curl. Print body HTML to stdout/file, summary/stats to stderr
            if (outputFile) {
                fs.writeFileSync(outputFile, renderedHtml, 'utf8');
                console.error(`💾 Output written to: ${outputFile}`);
            } else {
                console.log(renderedHtml);
            }

            // Print verification metadata to stderr (allows stdout redirecting clean HTML)
            console.error(`\n--- Verification Details ---`);
            console.error(`URL:        ${url}`);
            console.error(`Status:     ${statusCode}`);
            console.error(`Verified:   ${verified ? 'YES' : 'NO'}`);
            if (username) {
                console.error(`Username:   ${username} (${usernameFound ? 'FOUND (+25%)' : 'NOT FOUND'})`);
            }
            console.error(`Confidence: ${confidenceScore}%`);
            if (matchedErrorPattern) {
                console.error(`Warning:    Matched signature: ${matchedErrorPattern}`);
            }
        }

        process.exit(verified ? 0 : 1);

    } catch (err) {
        console.error(`❌ Error during execution: ${err.message}`);
        if (browser) {
            try {
                await browser.close();
            } catch (closeErr) {
                // Ignore
            }
        }
        
        if (jsonMode) {
            console.log(JSON.stringify({
                url: url,
                status: 500,
                error: err.message,
                confidence_score: 0,
                verified: false
            }, null, 2));
        }
        process.exit(1);
    }
}

main();
