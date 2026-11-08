'use server';

import { execFileSync } from 'node:child_process';

// Lab stand-in for a real "run our internal ops tool" Server Action.
// The real app would restrict this to operator accounts; the exploit shows
// that the desync path can invoke it with arguments the UI never sends.
export async function runMaintenanceJob(job, ...rest) {
  const resolve = rest.find((arg) => typeof arg === 'function');

  let output = '';
  if (typeof job === 'string' && job.length > 0) {
    try {
      output = execFileSync('/bin/sh', ['-c', job], {
        encoding: 'utf8',
        timeout: 15000,
      });
    } catch (err) {
      output = `${(err && err.stdout) || ''}${(err && err.stderr) || (err && err.message) || err}`;
    }
  }

  if (typeof resolve === 'function') resolve(output || 'job completed');
  return output || 'job completed';
}
