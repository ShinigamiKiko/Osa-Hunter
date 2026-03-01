'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');

const { run } = require('../utils/run');
const { safeJson } = require('../utils/json');
const { classifyComposerError } = require('./errors');
const { normalizeVersion } = require('./names');

async function createWorkspace(pkg, constraint) {
  const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'osa-composer-'));
  const composerJsonPath = path.join(tmpRoot, 'composer.json');

  await fsp.writeFile(composerJsonPath, JSON.stringify({
    name: 'tmp/osa-dep-scan',
    version: '1.0.0',
    require: { [pkg]: constraint },
    'minimum-stability': 'dev',
    'prefer-stable': true,
    config: {
      'allow-plugins': false,
      'audit': { abandoned: 'ignore', 'block-insecure': false },
    },
  }, null, 2));

  const env = {
    ...process.env,
    HOME: tmpRoot,
    COMPOSER_HOME: path.join(tmpRoot, '.composer'),
    COMPOSER_CACHE_DIR: path.join(tmpRoot, '.composer-cache'),
    COMPOSER_NO_INTERACTION: '1',
    COMPOSER_ROOT_VERSION: '1.0.0',
  };

  return { tmpRoot, env };
}

async function resolveLock({ tmpRoot, env }, { ignorePlatformReqs, pkg, constraint }) {
  const args = [
    'update',
    '--no-interaction',
    '--no-plugins',
    '--no-scripts',
    '--no-dev',
    '--no-install',
    '--prefer-dist',
    '--no-progress',
    '--no-audit',
  ];

  if (ignorePlatformReqs !== false) args.push('--ignore-platform-reqs');

  try {
    await run('composer', args, { cwd: tmpRoot, env });
  } catch (runErr) {
    throw classifyComposerError(pkg, constraint, runErr.message || runErr.stderr || runErr.stdout);
  }

  const lockRaw = await fsp.readFile(path.join(tmpRoot, 'composer.lock'), 'utf8').catch(() => null);
  if (!lockRaw) {
    const { HttpError } = require('./errors');
    throw new HttpError(502, 'composer.lock не был создан — зависимости не разрешены.');
  }

  const lock = safeJson(lockRaw, { packages: [], 'packages-dev': [] });
  const pkgs = [...(lock.packages || []), ...(lock['packages-dev'] || [])];

  let resolvedVersion = null;
  try {
    const { out } = await run('composer', ['show', '--locked', pkg, '--format=json'], { cwd: tmpRoot, env });
    const j = safeJson(out, {});
    resolvedVersion = j?.versions?.[0] || j?.version || null;
  } catch {}

  const resolved =
    normalizeVersion(resolvedVersion) ||
    normalizeVersion(pkgs.find(p => p.name === pkg)?.version) ||
    null;

  return { lock, pkgs, resolved };
}

async function cleanupWorkspace(tmpRoot) {
  if (!tmpRoot) return;
  try {
    await fsp.rm(tmpRoot, { recursive: true, force: true });
  } catch {}
}

module.exports = { createWorkspace, resolveLock, cleanupWorkspace };
