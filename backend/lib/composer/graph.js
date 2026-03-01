'use strict';

const { normalizeVersion } = require('./names');

function buildDependencyGraph(pkgs, rootPkgName) {
  const requiresMap = new Map();
  const nameToVersion = new Map();

  for (const p of pkgs) {
    nameToVersion.set(p.name, normalizeVersion(p.version));
    const deps = Object.keys(p.require || {}).filter(n => !/^php$|^ext-|^lib-/i.test(n));
    requiresMap.set(p.name, deps);
  }

  const scannedPkgRequires = requiresMap.get(rootPkgName) || [];

  const seen = new Set();
  const q = [{ name: rootPkgName, depth: 0 }];
  const edges = [];

  while (q.length) {
    const { name: current, depth } = q.shift();
    if (seen.has(current)) continue;
    seen.add(current);
    const deps = requiresMap.get(current) || [];
    for (const d of deps) {
      if (nameToVersion.has(d)) {
        edges.push([current, d]);
        if (!seen.has(d)) q.push({ name: d, depth: depth + 1 });
      }
    }
  }

  const directSet = new Set(scannedPkgRequires.filter(n => nameToVersion.has(n)));
  const transitiveSet = new Set([...seen].filter(n => n !== rootPkgName && !directSet.has(n)));

  return { requiresMap, nameToVersion, edges, directSet, transitiveSet, scannedPkgRequires };
}

module.exports = { buildDependencyGraph };
