#!/usr/bin/env node
/**
 * puppeteer-curl.js
 * A standalone Puppeteer CLI tool mimicking 'curl' that evades detection,
 * fetches fully-rendered page content, and computes profile verification
 * confidence scores by looking for a target username and checking against 
 * typical error signatures.
 * 
 * Supports both Single URL Fetch mode and List Scan mode using templates
 * from target-list/targets.txt and rules from target-list/false-positive-list.txt.
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

// Function to load false positive error patterns from file (supporting dynamic $user replacement)
function loadErrorPatterns(username) {
    let listPath = path.resolve(__dirname, 'target-list', 'false-positive-list.txt');
    if (!fs.existsSync(listPath)) {
        listPath = path.resolve(process.cwd(), 'target-list', 'false-positive-list.txt');
    }
    if (!fs.existsSync(listPath)) {
        listPath = path.resolve(process.cwd(), 'false-positive-list.txt');
    }

    if (fs.existsSync(listPath)) {
        try {
            const content = fs.readFileSync(listPath, 'utf8');
            const lines = content.split(/\r?\n/)
                .map(line => line.trim())
                .filter(line => line && !line.startsWith('#'));
            
            // Build the list by substituting $user / $username
            return lines.map(line => {
                return line.replace(/\$user/gi, username).replace(/\$username/gi, username);
            });
        } catch (err) {
            console.error(`[WARNING] Failed to load false-positive-list.txt: ${err.message}`);
        }
    }

    // Fallback static error patterns if file is not found
    const defaults = [
        'user not found',
        'profile not found',
        'member not found',
        'no such user',
        'does not exist',
        'invalid user',
        'cannot find the user',
        'page not found',
        'error 404',
        '404 not found',
        'profile does not exist',
        'sign up to view',
        'create an account to',
        'register to see',
        'join to see',
        'access denied'
    ];
    
    return defaults.map(line => line.replace(/\$user/gi, username).replace(/\$username/gi, username));
}

function printHelp() {
    console.log(`
puppeteer-curl.js - Browser-mimicking curl with OSINT Username Verification

USAGE:
  # Single URL Mode:
  node puppeteer-curl.js <URL> [OPTIONS]

  # List Scan Mode (reads target-list/targets.txt):
  node puppeteer-curl.js -u <username> [-csv] [-json] [OPTIONS]

OPTIONS:
  -u, --username <name>     Username to search for in page body.
                            Enables confidence score estimation:
                            - Base 75% if page loads successfully and username is found.
                            - Adds +25% (total 100%) if username is found in body text.
                            - Drops to 0% if error patterns match or status >= 400.
  -H, --header "Name: Val"  Add custom HTTP header (can be used multiple times).
  -o, --output <file>       Save response HTML to file instead of printing to stdout.
  -t, --timeout <ms>        Navigation timeout in milliseconds (default: 30000 for single, 15000 for list).
  -p, --proxy <url>         Use proxy server (e.g., http://127.0.0.1:8080).
  --concurrency <num>       Number of concurrent pages in List Scan mode (default: 15).
  -csv, --csv               Generate $username.csv containing the verification summary fields.
  -json, --json             Generate $username.json containing the verification summary fields.
  -v, -verbose, --verbose   Show live url fetch details and Found/Not Found status.
  --summary                 Output a human-readable verification summary instead of raw HTML.
  --no-headless             Run browser in visible (headful) mode.
  -d, --debug               Enable debug logs (printed to stderr).
  -h, --help                Show this help message.

EXAMPLES:
  # Standard fetch
  node puppeteer-curl.js https://github.com/luizcalixt0

  # Fetch and verify username
  node puppeteer-curl.js https://github.com/luizcalixt0 -u luizcalixt0

  # Run batch scan for a username against targets.txt list, outputting CSV & JSON with verbose progress
  node puppeteer-curl.js -u bazzofx -csv -json -v
    `);
}

function exportToCSV(results, filename) {
    const headers = [
        'url',
        'final_url',
        'status',
        'title',
        'verified',
        'username',
        'username_found',
        'confidence_score',
        'matched_error_pattern',
        'body_length'
    ];
    
    const rows = results.map(r => {
        return headers.map(header => {
            let val = r[header];
            if (val === null || val === undefined) {
                val = '';
            }
            val = String(val);
            // Escape double quotes and wrap in quotes if contains comma, quote, or newline
            if (val.includes(',') || val.includes('"') || val.includes('\n') || val.includes('\r')) {
                val = '"' + val.replace(/"/g, '""') + '"';
            }
            return val;
        }).join(',');
    });
    
    const csvContent = [headers.join(','), ...rows].join('\n');
    try {
        fs.writeFileSync(filename, csvContent, 'utf8');
        console.log(`💾 Exported verified CSV to: ${filename}`);
    } catch (err) {
        console.error(`⚠️ Warning: Failed to write CSV to ${filename} (file might be locked/busy): ${err.message}`);
        const fallbackFilename = filename.replace(/\.csv$/, `_${Date.now()}.csv`);
        try {
            fs.writeFileSync(fallbackFilename, csvContent, 'utf8');
            console.log(`💾 Fallback: Exported verified CSV to: ${fallbackFilename}`);
        } catch (fallbackErr) {
            console.error(`❌ Error: Failed to write fallback CSV: ${fallbackErr.message}`);
        }
    }
}

function exportToJSON(results, filename) {
    try {
        fs.writeFileSync(filename, JSON.stringify(results, null, 2), 'utf8');
        console.log(`💾 Exported verified JSON to: ${filename}`);
    } catch (err) {
        console.error(`⚠️ Warning: Failed to write JSON to ${filename} (file might be locked/busy): ${err.message}`);
        const fallbackFilename = filename.replace(/\.json$/, `_${Date.now()}.json`);
        try {
            fs.writeFileSync(fallbackFilename, JSON.stringify(results, null, 2), 'utf8');
            console.log(`💾 Fallback: Exported verified JSON to: ${fallbackFilename}`);
        } catch (fallbackErr) {
            console.error(`❌ Error: Failed to write fallback JSON: ${fallbackErr.message}`);
        }
    }
}

async function main() {
    const args = process.argv.slice(2);

    if (args.includes('-h') || args.includes('--help')) {
        printHelp();
        process.exit(0);
    }

    // Parse options
    let url = null;
    let username = null;
    const headers = {};
    let outputFile = null;
    let timeout = null; 
    let proxy = null;
    let jsonMode = false; 
    let summaryMode = false; 
    let headless = 'new';
    let debug = false;
    let verbose = false;
    let csvExport = false;
    let jsonExport = false;
    let concurrency = 15;

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
        } else if (arg === '--concurrency' && nextArg) {
            concurrency = parseInt(nextArg, 10);
            i++;
        } else if (arg === '-csv' || arg === '--csv') {
            csvExport = true;
        } else if (arg === '-json' || arg === '--json') {
            jsonExport = true;
            jsonMode = true;
        } else if (arg === '-verbose' || arg === '-v' || arg === '--verbose') {
            verbose = true;
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

    const logDebug = (msg) => {
        if (debug) {
            console.error(`[DEBUG] ${msg}`);
        }
    };

    // Determine Mode
    const listMode = !url;

    if (listMode) {
        if (!username) {
            console.error('❌ Error: No URL or Username provided.');
            printHelp();
            process.exit(1);
        }
        logDebug(`Running in LIST SCAN mode for username: ${username}`);
    } else {
        logDebug(`Running in SINGLE URL mode for URL: ${url}`);
    }

    // Set default timeouts
    if (timeout === null) {
        timeout = listMode ? 15000 : 30000;
    }

    // Resolve target templates list
    let targetList = [];
    if (listMode) {
        let targetsPath = path.resolve(__dirname, 'target-list', 'targets.txt');
        if (!fs.existsSync(targetsPath)) {
            targetsPath = path.resolve(process.cwd(), 'target-list', 'targets.txt');
        }
        if (!fs.existsSync(targetsPath)) {
            console.error(`❌ Error: Targets template file not found at ${targetsPath}`);
            process.exit(1);
        }
        
        logDebug(`Loading targets templates from: ${targetsPath}`);
        const fileContent = fs.readFileSync(targetsPath, 'utf8');
        targetList = fileContent.split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line && line !== 'url' && !line.startsWith('#'))
            .map(template => template.replace(/\$username/g, username));
        
        logDebug(`Loaded ${targetList.length} candidate URLs for verification.`);
    }

    // Build browser launch args
    const launchArgs = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-features=IsolateOrigins,site-per-process',
        '--window-size=1280,800'
    ];

    if (proxy) {
        launchArgs.push(`--proxy-server=${proxy}`);
    }

    const userAgent = headers['User-Agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

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

    // ==================== LIST SCAN MODE ====================
    if (listMode) {
        const results = [];
        let processedCount = 0;
        const totalTargets = targetList.length;

        console.error(`🚀 Processing ${totalTargets} URLs with concurrency = ${concurrency}...`);
        const startTime = Date.now();
        let activeIndex = 0;

        // Worker function pulling from shared queue
        const runWorker = async () => {
            while (activeIndex < totalTargets) {
                const targetUrl = targetList[activeIndex++];
                if (!targetUrl) break;

                let page;
                try {
                    page = await browser.newPage();

                    // Block resource loading (images, CSS, fonts, media)
                    await page.setRequestInterception(true);
                    page.on('request', (req) => {
                        const resourceType = req.resourceType();
                        if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) {
                            req.abort();
                        } else {
                            req.continue();
                        }
                    });

                    // Set anti-detection flags
                    await page.evaluateOnNewDocument(() => {
                        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                    });

                    await page.setViewport({ width: 1280, height: 800 });
                    await page.setUserAgent(userAgent);
                    await page.setExtraHTTPHeaders(defaultHeaders);

                    // Navigate
                    const response = await page.goto(targetUrl, {
                        waitUntil: 'domcontentloaded',
                        timeout: timeout
                    });

                    if (!response) {
                        throw new Error('No response');
                    }

                    const statusCode = response.status();
                    const finalUrl = response.url();
                    const renderedHtml = await page.content();
                    const textContent = await page.evaluate(() => document.body ? document.body.innerText : '');
                    const pageTitle = await page.title();

                    // Process verification and scoring
                    let verified = false;
                    let baseConfidence = 0;
                    let bonusConfidence = 0;
                    let confidenceScore = 0;
                    let usernameFound = false;
                    let matchedErrorPattern = null;

                    if (statusCode >= 400) {
                        matchedErrorPattern = `HTTP ${statusCode}`;
                    } else {
                        // Check if final URL does not contain username on HTTP 200/201 redirects
                        if ((statusCode === 200 || statusCode === 201) && username) {
                            if (!finalUrl.toLowerCase().includes(username.toLowerCase())) {
                                matchedErrorPattern = `URL Redirect Miss (${finalUrl})`;
                            }
                        }

                        if (!matchedErrorPattern) {
                            // Check profile error signatures from false-positive-list.txt (scans body text & page title)
                            const errorPatterns = loadErrorPatterns(username);
                            for (const pattern of errorPatterns) {
                                if (textContent.toLowerCase().includes(pattern.toLowerCase()) ||
                                    pageTitle.toLowerCase().includes(pattern.toLowerCase())) {
                                    matchedErrorPattern = pattern;
                                    break;
                                }
                            }
                        }

                        if (!matchedErrorPattern) {
                            if (username) {
                                const inBody = textContent.toLowerCase().includes(username.toLowerCase());
                                const inTitle = pageTitle.toLowerCase().includes(username.toLowerCase());
                                
                                if (inBody || inTitle) {
                                    verified = true;
                                    baseConfidence = 75;
                                    usernameFound = true;
                                    if (inBody) {
                                        bonusConfidence = 25; // +25% confidence if found in body text
                                    }
                                    confidenceScore = baseConfidence + bonusConfidence;
                                } else {
                                    matchedErrorPattern = 'Username not found in page body or title';
                                }
                            } else {
                                // If no username specified, consider verified
                                verified = true;
                                confidenceScore = 100;
                            }
                        }
                    }

                    results.push({
                        url: targetUrl,
                        final_url: finalUrl,
                        status: statusCode,
                        title: pageTitle,
                        verified: verified,
                        username: username,
                        username_found: usernameFound,
                        confidence_score: confidenceScore,
                        matched_error_pattern: matchedErrorPattern,
                        body_length: renderedHtml.length
                    });

                    if (verbose) {
                        const isFound = verified && usernameFound;
                        if (isFound) {
                            console.log(`- [+] - Found     - ${targetUrl}`);
                        } else {
                            console.log(`- [-] - Not Found - ${targetUrl}`);
                        }
                    }

                } catch (err) {
                    logDebug(`Failed URL: ${targetUrl} | Reason: ${err.message}`);
                    results.push({
                        url: targetUrl,
                        final_url: targetUrl,
                        status: 500,
                        title: '',
                        verified: false,
                        username: username,
                        username_found: false,
                        confidence_score: 0,
                        matched_error_pattern: err.message,
                        body_length: 0
                    });

                    if (verbose) {
                        console.log(`- [-] - Not Found - ${targetUrl}`);
                    }
                } finally {
                    if (page) {
                        try {
                            await page.close();
                        } catch (e) {}
                    }
                    processedCount++;
                    const progressPct = Math.round((processedCount / totalTargets) * 100);
                    if (processedCount % 15 === 0 || processedCount === totalTargets) {
                        console.error(`   Progress: ${processedCount}/${totalTargets} (${progressPct}%) processed...`);
                    }
                }
            }
        };

        // Launch concurrent sliding workers
        const workers = [];
        const activeConcurrency = Math.min(concurrency, totalTargets);
        for (let w = 0; w < activeConcurrency; w++) {
            workers.push(runWorker());
        }
        await Promise.all(workers);

        await browser.close();

        const durationSec = ((Date.now() - startTime) / 1000).toFixed(1);
        const verifiedCount = results.filter(r => r.verified).length;
        console.error(`\n✅ Scan completed in ${durationSec}s. Verified profiles found: ${verifiedCount}/${totalTargets}`);

        // Write outputs
        if (csvExport) {
            const csvFilename = path.resolve(process.cwd(), `${username}.csv`);
            exportToCSV(results, csvFilename);
        }
        if (jsonExport) {
            const jsonFilename = path.resolve(process.cwd(), `${username}.json`);
            exportToJSON(results, jsonFilename);
        }

        // Print results to stdout if no exports
        if (!csvExport && !jsonExport) {
            console.log(JSON.stringify(results, null, 2));
        }

        process.exit(0);
    }

    // ==================== SINGLE URL MODE ====================
    else {
        try {
            const page = await browser.newPage();

            // Hide webdriver flag
            await page.evaluateOnNewDocument(() => {
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            });

            await page.setViewport({ width: 1920, height: 1080 });
            await page.setUserAgent(userAgent);
            await page.setExtraHTTPHeaders(defaultHeaders);

            // Perform Navigation
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

            // Wait a bit for async JS rendering
            await new Promise(resolve => setTimeout(resolve, 1000));

            const renderedHtml = await page.content();
            const textContent = await page.evaluate(() => document.body ? document.body.innerText : '');
            const pageTitle = await page.title();

            await browser.close();
            browser = null;

            // Process Verification & Confidence Scoring
            let verified = false;
            let baseConfidence = 0;
            let bonusConfidence = 0;
            let confidenceScore = 0;
            let usernameFound = false;
            let matchedErrorPattern = null;

            if (statusCode >= 400) {
                matchedErrorPattern = `HTTP Error Status Code: ${statusCode}`;
            } else {
                // Check if final URL does not contain username on HTTP 200/201 redirects
                if ((statusCode === 200 || statusCode === 201) && username) {
                    if (!finalUrl.toLowerCase().includes(username.toLowerCase())) {
                        matchedErrorPattern = `URL Redirect Miss (${finalUrl})`;
                    }
                }

                if (!matchedErrorPattern) {
                    // Check for profile error keywords from false-positive-list.txt (scans body text & page title)
                    const errorPatterns = loadErrorPatterns(username || '');
                    for (const pattern of errorPatterns) {
                        if (textContent.toLowerCase().includes(pattern.toLowerCase()) ||
                            pageTitle.toLowerCase().includes(pattern.toLowerCase())) {
                            matchedErrorPattern = pattern;
                            break;
                        }
                    }
                }

                if (!matchedErrorPattern) {
                    if (username) {
                        const inBody = textContent.toLowerCase().includes(username.toLowerCase());
                        const inTitle = pageTitle.toLowerCase().includes(username.toLowerCase());
                        
                        if (inBody || inTitle) {
                            verified = true;
                            baseConfidence = 75;
                            usernameFound = true;
                            if (inBody) {
                                bonusConfidence = 25; // +25% confidence if found in body text
                            }
                            confidenceScore = baseConfidence + bonusConfidence;
                        } else {
                            matchedErrorPattern = 'Username not found in page body or title';
                        }
                    } else {
                        verified = true;
                        confidenceScore = 100;
                    }
                }
            }

            const resultObject = {
                url: url,
                final_url: finalUrl,
                status: statusCode,
                title: pageTitle,
                verified: verified,
                username: username || null,
                username_found: usernameFound,
                confidence_score: confidenceScore,
                matched_error_pattern: matchedErrorPattern,
                body_length: renderedHtml.length
            };

            const results = [resultObject];

            // Handle exports in single mode
            if (csvExport) {
                const csvFilename = path.resolve(process.cwd(), `${username || 'output'}.csv`);
                exportToCSV(results, csvFilename);
            }
            if (jsonExport && (args.includes('-json') || args.includes('--json'))) {
                const jsonFilename = path.resolve(process.cwd(), `${username || 'output'}.json`);
                exportToJSON(results, jsonFilename);
            }

            // Console output styling
            if (jsonMode && !outputFile && !csvExport) {
                console.log(JSON.stringify(resultObject, null, 2));
            } else if (summaryMode) {
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
                    console.log(`Username Found in Page: ${usernameFound ? 'YES' : 'NO'}`);
                }
                console.log(`Confidence Score:      ${confidenceScore}%`);
                console.log(`HTML Length:           ${renderedHtml.length} bytes`);
            } else {
                if (outputFile) {
                    fs.writeFileSync(outputFile, renderedHtml, 'utf8');
                    console.error(`💾 Output written to: ${outputFile}`);
                } else {
                    console.log(renderedHtml);
                }

                console.error(`\n--- Verification Details ---`);
                console.error(`URL:        ${url}`);
                console.error(`Status:     ${statusCode}`);
                console.error(`Verified:   ${verified ? 'YES' : 'NO'}`);
                if (username) {
                    console.error(`Username:   ${username} (${usernameFound ? 'FOUND' : 'NOT FOUND'})`);
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
                } catch (closeErr) {}
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
}

main();
