'use strict';

const EPSS_URL = 'https://api.first.org/data/v1/epss';
const OSV_URL  = 'https://api.osv.dev/v1';
const CISA_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const POC_BASE = 'https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master';

const MAX_PKG_NAME  = 214;
const MAX_CVE_BATCH = 100;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

const IMAGE_RE = /^[a-z0-9\-_./:@]+$/i;


// Severity ordering used across all scan routes
const SEV_ORD = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE'];

module.exports = {
  EPSS_URL, OSV_URL, CISA_URL, POC_BASE,
  MAX_PKG_NAME, MAX_CVE_BATCH, CVE_RE,
  IMAGE_RE,
  SEV_ORD,
};
