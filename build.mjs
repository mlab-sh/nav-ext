#!/usr/bin/env node
import { build, context } from 'esbuild';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const __dirname = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const watch = args.includes('--watch');
const targets = args.filter((a) => !a.startsWith('--'));
const browsers = targets.length ? targets : ['chrome', 'firefox'];

const ICON_SIZES = [16, 32, 48, 128];

async function generateIcons(outdir) {
  const srcPath = resolve(__dirname, 'src/assets/icons/icon.png');
  if (!existsSync(srcPath)) return;
  const srcBuf = await readFile(srcPath);
  const iconsDir = resolve(outdir, 'icons');
  await mkdir(iconsDir, { recursive: true });
  await Promise.all(
    ICON_SIZES.map((size) =>
      sharp(srcBuf)
        // ensure white background — the logo is black on transparent/white
        .flatten({ background: { r: 255, g: 255, b: 255 } })
        .resize(size, size, { fit: 'contain', background: { r: 255, g: 255, b: 255 } })
        .png()
        .toFile(resolve(iconsDir, `icon-${size}.png`))
    )
  );
  // also expose the 128px as a generic "logo.png" for inline use in popup/options
  await sharp(srcBuf)
    .flatten({ background: { r: 255, g: 255, b: 255 } })
    .resize(128, 128, { fit: 'contain', background: { r: 255, g: 255, b: 255 } })
    .png()
    .toFile(resolve(iconsDir, 'logo.png'));
}

const entryPoints = {
  'background/service-worker': 'src/background/service-worker.ts',
  'content/content': 'src/content/content.ts',
  'popup/popup': 'src/popup/popup.ts',
  'options/options': 'src/options/options.ts',
};

async function buildBrowser(browser) {
  const outdir = resolve(__dirname, 'dist', browser);
  if (existsSync(outdir)) await rm(outdir, { recursive: true });
  await mkdir(outdir, { recursive: true });

  const entries = Object.fromEntries(
    Object.entries(entryPoints).map(([k, v]) => [k, resolve(__dirname, v)])
  );

  const opts = {
    entryPoints: entries,
    bundle: true,
    format: 'iife',
    target: ['chrome110', 'firefox115'],
    outdir,
    sourcemap: 'inline',
    logLevel: 'info',
    define: { 'process.env.NODE_ENV': '"production"', BROWSER_TARGET: JSON.stringify(browser) },
  };

  if (watch) {
    const ctx = await context(opts);
    await ctx.watch();
    console.log(`[${browser}] watching…`);
  } else {
    await build(opts);
  }

  // copy static assets
  await cp(resolve(__dirname, 'src/popup/popup.html'), resolve(outdir, 'popup/popup.html'));
  await cp(resolve(__dirname, 'src/popup/popup.css'), resolve(outdir, 'popup/popup.css'));
  await cp(resolve(__dirname, 'src/options/options.html'), resolve(outdir, 'options/options.html'));
  await cp(resolve(__dirname, 'src/options/options.css'), resolve(outdir, 'options/options.css'));
  await cp(resolve(__dirname, 'src/content/highlight.css'), resolve(outdir, 'content/highlight.css'));

  // rasterize icons (SVG → PNG at 16/32/48/128)
  await generateIcons(outdir);

  // manifest tailored per browser
  const manifest = JSON.parse(await readFile(resolve(__dirname, 'manifest.json'), 'utf8'));
  if (browser === 'firefox') {
    manifest.background = { scripts: ['background/service-worker.js'] };
    manifest.browser_specific_settings = {
      gecko: { id: 'mlab-intel@mlab.sh', strict_min_version: '115.0' },
    };
  } else {
    manifest.background = { service_worker: 'background/service-worker.js' };
  }
  await writeFile(resolve(outdir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  console.log(`[${browser}] built → ${outdir}`);
}

for (const b of browsers) await buildBrowser(b);
