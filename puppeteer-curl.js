#!/usr/bin/env node
/**
 * Root wrapper for puppeteer-curl.js
 * Delegates execution to dev/osint_report_function/puppeteer-curl.js
 * ensuring correct local module resolution.
 */
require('./dev/osint_report_function/puppeteer-curl.js');
