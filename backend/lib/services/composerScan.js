'use strict';

const { HttpError } = require('../composer/errors');
const { isComposerPackageName, normalizeComposerConstraint, normalizeVersion } = require('../composer/names');
const { precheckPackagist, fetchPackagistInfo } = require('../composer/packagist');
const { createWorkspace, resolveLock, cleanupWorkspace } = require('../composer/workspace');
const { buildDependencyGraph } = require('../composer/graph');
const { enrichAll } = require('../composer/enrich');

async function scanComposer({ name, version, ignorePlatformReqs }) {
  if (!name || typeof name !== 'string' || !name.trim()) {
    throw new HttpError(400, '"name" is required (e.g., monolog/monolog)');
  }

  const pkg = name.trim();
  if (!isComposerPackageName(pkg)) {
    throw new HttpError(
      400,
      `Неверное имя пакета: «${pkg}». Для Composer нужно "vendor/package" (например, "symfony/console").`
    );
  }

  const constraint = normalizeComposerConstraint(version);

  const pre = await precheckPackagist(pkg, version);
  if (!pre.ok) throw new HttpError(pre.status || 404, pre.error || 'Packagist pre-check failed');

  let ws;
  try {
    ws = await createWorkspace(pkg, constraint);
    const { pkgs, resolved } = await resolveLock(ws, { ignorePlatformReqs, pkg, constraint });

    const graph = buildDependencyGraph(pkgs, pkg);
    console.log(`[composerscan] ${pkg}: direct=${graph.directSet.size}, transitive=${graph.transitiveSet.size}, total_pkgs=${pkgs.length}`);

    const rootVersionForOsv = normalizeVersion(version) || resolved;
    const info = await fetchPackagistInfo(pkg, resolved);

    const enriched = await enrichAll({
      pkg,
      resolvedVersion: resolved,
      versionForOsv: rootVersionForOsv,
      nameToVersion: graph.nameToVersion,
      directSet: graph.directSet,
      transitiveSet: graph.transitiveSet,
    });

    const all = [enriched.root, ...enriched.direct, ...enriched.transitive];
    const withVulns = all.filter(d => (d.cves || []).length > 0).length;

    return {
      package: pkg,
      system: 'COMPOSER',
      version: version || null,
      versionConstraint: constraint,
      resolvedVersion: resolved || null,
      scannedAt: new Date().toISOString(),
      toxic: enriched.root.toxic,
      info,
      summary: {
        total: graph.directSet.size + graph.transitiveSet.size,
        direct: graph.directSet.size,
        transitive: graph.transitiveSet.size,
        withVulns,
        resolvedVersion: resolved,
      },
      deps: {
        root: enriched.root,
        direct: enriched.direct,
        transitive: enriched.transitive,
        edges: graph.edges,
      },
    };
  } finally {
    if (ws?.tmpRoot) await cleanupWorkspace(ws.tmpRoot);
  }
}

module.exports = { scanComposer };
