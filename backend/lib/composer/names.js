'use strict';

function normalizeVersion(v) {
  if (!v) return v;
  return String(v).trim().replace(/^v/i, '');
}

function isComposerPackageName(name) {
  return /^[a-z0-9]([_.-]?[a-z0-9]+)*\/[a-z0-9](([_.]?|-{0,2})[a-z0-9]+)*$/i.test(String(name || '').trim());
}

function normalizeComposerConstraint(v) {
  if (v == null) return '*';
  const s0 = String(v).trim();
  if (!s0) return '*';

  const s = s0.toLowerCase();
  if (s === 'latest') return '*';

  const raw = s0.trim();

  if (/[~^*<>=|]/.test(raw) || raw.startsWith('dev-') || raw.includes('||') || raw.includes('@')) return raw;
  if (/^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$/.test(raw)) return `==${raw}`;
  if (/^\d+(\.\d+)?$/.test(raw)) return `^${raw}`;
  return raw;
}

module.exports = { normalizeVersion, isComposerPackageName, normalizeComposerConstraint };
