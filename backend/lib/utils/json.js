'use strict';

function safeJson(str, fallback = null) {
  try {
    return JSON.parse(str || '{}');
  } catch (e) {
    console.warn('[safeJson] parse failed:', e.message, '| input:', String(str).slice(0, 300));
    return fallback;
  }
}

module.exports = { safeJson };
