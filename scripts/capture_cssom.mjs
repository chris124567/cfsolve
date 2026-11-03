// Measure CSSOM serialization offline, using only a saved capture's inline styles.
// Usage: node scripts/capture_cssom.mjs <capture.json> <cssom.json>
// Pass cssom.json as build_profile's optional second argument. The builder verifies
// the measurements against the hash the captured browser actually reported.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('Supply capture.json and output cssom.json');
const capture = JSON.parse(fs.readFileSync(input, 'utf8'));
const styles = [...capture.iframeHtml.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style\s*>/gi)].map(match => match[1]);
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-cssom-'));
try {
  const encoded = Buffer.from(JSON.stringify(styles)).toString('base64');
  const document = `<!doctype html><meta charset="utf-8"><pre id="out"></pre><script>
    const sources = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob('${encoded}'), c => c.charCodeAt(0))));
    const result = sources.map(source => {
      const style = document.createElement('style');
      style.textContent = source;
      document.head.append(style);
      return { source, rules: Array.from(style.sheet.cssRules, rule => rule.cssText) };
    });
    document.getElementById('out').textContent = JSON.stringify(result);
  </script>`;
  const file = path.join(directory, 'styles.html');
  fs.writeFileSync(file, document);
  const dom = execFileSync(process.env.CHROMIUM || 'chromium', [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-background-networking',
    '--host-resolver-rules=MAP * ~NOTFOUND', `--user-data-dir=${path.join(directory, 'profile')}`,
    '--dump-dom', `file://${file}`,
  ], { encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  const found = dom.match(/<pre id="out">([\s\S]*?)<\/pre>/);
  if (!found) throw new Error('Chromium did not return CSSOM measurements');
  const decoded = found[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  const result = JSON.parse(decoded);
  if (result.length !== styles.length) throw new Error('CSSOM measurement count differs');
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
