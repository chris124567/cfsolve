#!/usr/bin/env python3
"""Measure saved iframe styles in another browser without replaying a challenge.

Usage: serve_cssom.py <output-directory> <capture.json>... [--port 8766]
Open the printed LAN URL in the browser being profiled.
"""

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PAGE = b'''<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Safari stylesheet measurement</title>
<body style="font:18px system-ui;padding:24px"><h1>Stylesheet measurement</h1>
<p id="status">Measuring this browser...</p>
<script>
(async () => {
  const captures = await (await fetch('/styles.json')).json();
  const results = [];
  for (const capture of captures) {
    const frame = document.createElement('iframe');
    frame.style.display = 'none';
    document.body.append(frame);
    const doc = frame.contentDocument;
    const sheets = capture.sources.map(source => {
      const style = doc.createElement('style');
      style.textContent = source;
      doc.head.append(style);
      return {source, rules: Array.from(style.sheet.cssRules, rule => rule.cssText)};
    });
    results.push({name: capture.name, sheets});
    frame.remove();
  }
  const response = await fetch('/measurements', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({userAgent: navigator.userAgent, results})
  });
  if (!response.ok) throw new Error(await response.text());
  document.getElementById('status').textContent = 'Saved successfully. You can close this page and tell me it is done.';
})().catch(error => document.getElementById('status').textContent = 'Measurement failed: ' + error.message);
</script>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('captures', nargs='+', type=Path)
    parser.add_argument('--port', type=int, default=8766)
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    captures = []
    for index, path in enumerate(arguments.captures):
        capture = json.loads(path.read_text())
        sources = re.findall(r'<style\b[^>]*>([\s\S]*?)</style\s*>', capture['iframeHtml'], re.I)
        if not sources:
            raise ValueError(f'No stylesheets in {path}')
        captures.append({'name': f'{index:02d}-{path.parent.name}', 'sources': sources})
    expected = {capture['name']: capture['sources'] for capture in captures}

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, content, content_type='text/plain'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            if self.path == '/':
                self.reply(200, PAGE, 'text/html; charset=utf-8')
            elif self.path == '/styles.json':
                self.reply(200, json.dumps(captures).encode(), 'application/json')
            else:
                self.reply(404, b'Not found')

        def do_POST(self):
            if self.path != '/measurements':
                return self.reply(404, b'Not found')
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length < 4_000_000:
                    raise ValueError('Invalid measurement size')
                measured = json.loads(self.rfile.read(length))
                if {result['name'] for result in measured['results']} != set(expected):
                    raise ValueError('Unexpected capture names')
                for result in measured['results']:
                    if [sheet['source'] for sheet in result['sheets']] != expected[result['name']]:
                        raise ValueError('Stylesheet sources differ')
                    if not all(isinstance(rule, str) for sheet in result['sheets'] for rule in sheet['rules']):
                        raise ValueError('Invalid CSS rules')
                # Write only after the entire measurement has validated.
                for result in measured['results']:
                    (arguments.output / f"{result['name']}.json").write_text(json.dumps(result['sheets'], indent=2) + '\n')
                (arguments.output / 'browser.json').write_text(json.dumps({'userAgent': measured['userAgent']}, indent=2) + '\n')
                print(f"Saved {len(measured['results'])} captures from {measured['userAgent']}", flush=True)
                self.reply(200, b'Saved')
            except (ValueError, KeyError, TypeError) as error:
                self.reply(400, str(error).encode())

    server = ThreadingHTTPServer(('0.0.0.0', arguments.port), Handler)
    print(f'Listening on port {arguments.port}; open this computer\'s LAN address in Safari.', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
