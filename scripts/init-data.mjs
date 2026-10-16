import { randomBytes } from 'node:crypto';
import { chmodSync, chownSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const dataDir = '/app/data';
const passwordPath = path.join(dataDir, 'postgres-password');

mkdirSync(dataDir, { recursive: true, mode: 0o700 });

let existingPassword;
try {
  existingPassword = readFileSync(passwordPath, 'utf8').trim();
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

if (existingPassword !== undefined) {
  if (!existingPassword) throw new Error(`Postgres password file is empty: ${passwordPath}`);
} else {
  const password = process.env.POSTGRES_PASSWORD || randomBytes(24).toString('hex');
  try {
    writeFileSync(passwordPath, `${password}\n`, { flag: 'wx', mode: 0o440 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const concurrentPassword = readFileSync(passwordPath, 'utf8').trim();
    if (!concurrentPassword) throw new Error(`Postgres password file is empty: ${passwordPath}`);
  }
}

chownSync(dataDir, 1000, 1000);
chmodSync(dataDir, 0o750);
chownSync(passwordPath, 0, 1000);
chmodSync(passwordPath, 0o440);
