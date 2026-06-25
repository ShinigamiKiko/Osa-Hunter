'use strict';

const { spawn } = require('child_process');

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { ...opts, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', d => out += d.toString());
    p.stderr.on('data', d => err += d.toString());
    p.on('error', reject);
    p.on('close', code => {
      if (code === 0) return resolve({ out, err });
      const msg = `${cmd} ${args.join(' ')} exited ${code}: ${err || out}`;
      const e = new Error(msg);
      e.exitCode = code;
      e.stdout = out;
      e.stderr = err;
      reject(e);
    });
  });
}

module.exports = { run };
