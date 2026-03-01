'use strict';

const { MAX_PKG_NAME, MAX_CVE_BATCH, CVE_RE, IMAGE_RE } = require('./constants');

function validatePkgName(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= MAX_PKG_NAME;
}

function validateCveBatch(cves) {
  if (!Array.isArray(cves) || !cves.length) return null;
  const clean = cves
    .filter(c => typeof c === 'string' && CVE_RE.test(c))
    .slice(0, MAX_CVE_BATCH);
  return clean.length ? clean : null;
}

function validateImage(image) {
  return typeof image === 'string' && image.length > 0 && image.length < 512 && IMAGE_RE.test(image);
}

module.exports = { validatePkgName, validateCveBatch, validateImage };
