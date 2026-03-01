'use strict';

const {
  getCisaSet,
  checkToxic,
  fetchEpss,
  fetchCvss,
  fetchPocs,
} = require('../shared');

const { osvQueryPackagist, mapVulnForApi, extractCvesFromOsv } = require('./osv');

async function enrichOne(depName, version, cisaSet) {
  const vulns = version ? await osvQueryPackagist(depName, version) : [];
  const cves = extractCvesFromOsv(vulns);
  const toxic = checkToxic(depName);
  const epss = await fetchEpss(cves);
  const cvss = await fetchCvss(cves);
  const pocs = await fetchPocs(cves);
  const kev = cves.filter(id => cisaSet.has(id));

  return {
    name: depName,
    version: version || null,
    toxic,
    vulns: vulns.map(mapVulnForApi),
    cves,
    kev,
    epss,
    cvss,
    pocs,
  };
}

async function enrichAll({ pkg, resolvedVersion, versionForOsv, nameToVersion, directSet, transitiveSet }) {
  const cisaSet = await getCisaSet();

  const rootVersion = resolvedVersion || versionForOsv;
  const root = await enrichOne(pkg, rootVersion, cisaSet);
  root._isRoot = true;

  const direct = await Promise.all([...directSet].sort().map(n => enrichOne(n, nameToVersion.get(n) || null, cisaSet)));
  const transitive = await Promise.all([...transitiveSet].sort().map(n => enrichOne(n, nameToVersion.get(n) || null, cisaSet)));

  return { root, direct, transitive };
}

module.exports = { enrichAll };
