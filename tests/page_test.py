#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT
"""The automation page's exhaust-hold preset, in headless Chrome, with this test playing the panel.

What must hold: a hold that stands when a job first fires refuses the job, so the
"Hold jobs until the exhaust is on" preset raises its hold before a job arms. Made
from the page (the preset picked, Add pressed, a plug's kind and address filled
in, "Make the rules" pressed), it saves one rule that fires when the controller
starts and on the lid's events, never at the arm (job.arming, job.armed), and
does two things: turns the plug on, then holds jobs until the plug answers on,
watched for up to 300 s.

The page runs in a frame of a harness page that answers the page's bridge calls
the way the control panel does and its service's routes the way the package's
service does, records every rule the page saves, and writes them into its own
document, which Chrome dumps.

Needs Chrome (CHROME, or google-chrome, chromium or chrome on the PATH); without
it the test exits 77, and under GitHub Actions it fails.

Run: python3 tests/page_test.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "..", "ui", "index.html")
ID = "org.openglow.automation"

HARNESS = r"""<!doctype html>
<meta charset="utf-8">
<pre id="out"></pre>
<script>
var PAGE = %(page)s, ID = %(id)s, saved = [], f;
function service(a) {
  if (a.method === 'GET' && a.path === '/rules')
    return { status: 200, body: { rules: saved.slice(), known_events: ['job.arming', 'job.ended', 'lid', 'controller.started'] } };
  if (a.method === 'GET' && a.path === '/status')
    return { status: 200, body: { connected: true, events: [], outcomes: [], pending: [], hold: {} } };
  if (a.method === 'POST' && a.path === '/rule') {
    saved.push(a.body.rule);
    return { status: 200, body: { rules: saved.slice(), known_events: [] } };
  }
  return { status: 404, body: { error: 'no such route' } };
}
function answer(call) {
  switch (call.call) {
    case 'self': return { id: ID, version: '0', tier: 'official', capabilities: [], destinations: [] };
    case 'service.call': return service(call.args);
    case 'frame.height': return { px: call.args && call.args.px };
    default: return {};
  }
}
window.addEventListener('message', function (ev) {
  var m = ev.data;
  if (!m || m.forgefirm !== 1 || !m.id || ev.source !== f.contentWindow) return;
  ev.source.postMessage({ forgefirm: 1, id: m.id, ok: true, value: answer(m) }, '*');
});
f = document.createElement('iframe');
f.srcdoc = PAGE;
document.body.appendChild(f);
function set(d, id, v) { var e = d.getElementById(id); e.value = v; e.dispatchEvent(new Event('change', { bubbles: true })); }
setTimeout(function () {
  var d = f.contentDocument;
  set(d, 'preset', 'wait');
  d.getElementById('add').click();
  set(d, 'plugkind', 'shelly1');
  set(d, 'plugaddr', '192.0.2.40');
  d.getElementById('plugmake').click();
}, 1000);
setTimeout(function () {
  document.getElementById('out').textContent = 'RESULT ' + JSON.stringify(saved);
}, 3000);
</script>
"""

failures = 0


def check(ok, what):
    global failures
    print("  %s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        failures += 1


def chrome():
    c = os.environ.get("CHROME")
    if c:
        return c
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        p = shutil.which(name)
        if p:
            return p
    return None


def main():
    exe = chrome()
    if not exe:
        print("page_test: no Chrome (set CHROME)")
        return 1 if os.environ.get("GITHUB_ACTIONS") == "true" else 77
    page = open(PAGE, encoding="utf-8").read()
    js = lambda v: json.dumps(v).replace("</", "<\\/")  # noqa: E731
    with tempfile.TemporaryDirectory() as d:
        h = os.path.join(d, "harness.html")
        with open(h, "w", encoding="utf-8") as f:
            f.write(HARNESS % {"page": js(page), "id": js(ID)})
        out = subprocess.run(
            [exe, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
             "--user-data-dir=" + os.path.join(d, "profile"), "--virtual-time-budget=10000",
             "--dump-dom", "file://" + h],
            capture_output=True, text=True, timeout=120).stdout
    at = out.find("RESULT ")
    if at < 0:
        print("page_test: the harness wrote no result")
        print(out[-2000:])
        return 1
    rules = json.loads(out[at + 7:out.index("</pre>", at)].replace("&quot;", '"').replace("&amp;", "&")
                       .replace("&lt;", "<").replace("&gt;", ">"))
    print("the exhaust-hold preset, made from the page")
    check(len(rules) == 1, "one rule saved")
    rule = rules[0] if rules else {}
    on = rule.get("on") or []
    check(sorted(on) == ["controller.started", "lid"],
          "it fires when the controller starts and on the lid's events, never at the arm")
    acts = (rule.get("do") or []) + [{}, {}]
    on, hold = acts[0], acts[1]
    check(len(rule.get("do") or []) == 2 and on.get("type") == "http" and on.get("method") == "GET"
          and on.get("url") == "http://192.0.2.40/relay/0?turn=on", "it turns the plug on")
    check(hold.get("type") == "hold_until" and hold.get("url") == "http://192.0.2.40/relay/0"
          and hold.get("match") == '"ison":true', "then holds until the plug answers that it is on")
    check(hold.get("timeout_s") == 300 and hold.get("every_s") == 2,
          "asking every 2 s, for up to 300 s")
    if failures:
        print("saved:", json.dumps(rules, indent=1))
        print("FAIL: page_test, %d checks" % failures)
        return 1
    print("PASS: page_test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
