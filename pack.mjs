#!/usr/bin/env node
/**
 * Package built extensions into zips ready for Chrome Web Store / Mozilla AMO upload.
 * Output: dist/mlab-intel-{version}-chrome.zip, dist/mlab-intel-{version}-firefox.zip
 */
import { readFile, rm } from 'node:fs/promises';
import { existsSync, createWriteStream } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(await readFile(resolve(__dirname, 'package.json'), 'utf8'));
const version = pkg.version;

const targets = [
  { dir: 'dist/chrome', out: `mlab-intel-${version}-chrome.zip` },
  { dir: 'dist/firefox', out: `mlab-intel-${version}-firefox.zip` },
];

for (const { dir, out } of targets) {
  const srcDir = resolve(__dirname, dir);
  const outPath = resolve(__dirname, 'dist', out);
  if (!existsSync(srcDir)) {
    console.error(`Missing build output: ${srcDir} — run "npm run build" first.`);
    process.exit(1);
  }
  if (existsSync(outPath)) await rm(outPath);
  // Use system zip for stable, deterministic output. -r recursive, -X strip extra attrs.
  execFileSync('zip', ['-r', '-X', '-q', outPath, '.'], { cwd: srcDir, stdio: 'inherit' });
  console.log(`Packed → ${outPath}`);
}
