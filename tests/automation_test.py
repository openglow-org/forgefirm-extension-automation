#!/usr/bin/env python3
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT

"""Integration test of org.openglow.automation under the real extension host, as root.

The service is built for this computer (make host) and installed as the
package, with its own manifest, under `forgeext run`, in network and mount
namespaces of its own with the image's deny rules loaded. A peer namespace
on a veth pair holds the world it talks to: an HTTP server that stands in
for a notification service, a webhook, and a smart plug with a state, and
an MQTT broker. A stand-in for forgectrl's read-only routes publishes the
machine's events on its /events stream when the test says so. The page's
calls are made the way the panel relays them, with `forgeext call`.

It holds: the rules as the page reads and saves them, a secret never shown
back and kept by a save that does not retype it, a refusal in words; a
test action that cannot reach an address the operator has not named, and
reaches it once named; an event turned into a notification in the
service's own form, a condition that holds one back; a plug turned on at
arming and off after a job's run-on, and the run-on canceled by the next
job; an MQTT publish of every event; a job held until the plug answers
that it is on, and a hold that stands in words when it never does; the
rules kept across a restart; no secret in the host's log.

Needs root, cgroup v2, nft, ip, nsenter, unshare, curl, fwup (FWUP), the
built forgeext (FORGEEXT), the rule file (FFX_RULES), and the host build of
the service (AUTOMATION_BIN, default build/automation). Exits 77 without.
"""
import http.server
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..")
REPO = os.path.join(PKG, "..", "..")
FORGEEXT = os.environ.get("FORGEEXT") or os.path.join(REPO, "build", "forgeext")
FWUP = os.environ.get("FWUP") or shutil.which("fwup")
NFT = os.environ.get("NFT") or shutil.which("nft") or "/usr/sbin/nft"
RULES = os.environ.get("FFX_RULES") or os.path.join(REPO, "..", "forgefirm", "meta-forgefirm", "recipes-forgefirm",
                                                    "forgefirm-sandbox", "files", "ffx.nft")
BIN = os.environ.get("AUTOMATION_BIN") or os.path.join(PKG, "build", "automation")
MKFFX = os.path.join(REPO, "tools", "mkffx.sh")
CG_PARENT = "/sys/fs/cgroup/forgeext-automation-test"
HERE_ADDR, PEER_ADDR = "10.99.3.1", "10.99.3.2"
ID = "org.openglow.automation"
SKIP = 77

# The world the service talks to, in the peer namespace: every request and
# every publish it gets is a JSON line on stdout; a line on stdin sets the
# plug.
PEER = r'''
import http.server, json, socket, sys, threading
state = {"plug": False}
def say(**kw):
    print(json.dumps(kw), flush=True)
class H(http.server.BaseHTTPRequestHandler):
    def reply(self, doc, code=200):
        data = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def handle_one(self, method):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        if self.path == "/plug/on":
            state["plug"] = True
        elif self.path == "/plug/off":
            state["plug"] = False
        say(kind="http", method=method, path=self.path, body=body,
            headers={k: v for k, v in self.headers.items() if k.lower() in ("authorization", "title", "priority", "content-type")})
        if self.path.startswith("/plug"):
            return self.reply({"ison": state["plug"]})
        if self.path == "/fail":
            return self.reply({"error": "no"}, 500)
        self.reply({"ok": True})
    def do_GET(self):
        self.handle_one("GET")
    def do_POST(self):
        self.handle_one("POST")
    def do_PUT(self):
        self.handle_one("PUT")
    def log_message(self, *a):
        pass
def packet(buf, at):
    """(type byte, body, the index after it) of the MQTT packet at buf[at]."""
    n, mul, k = 0, 1, at + 1
    while True:
        n += (buf[k] & 0x7f) * mul
        if not buf[k] & 0x80:
            break
        mul *= 128
        k += 1
    return buf[at], buf[k + 1:k + 1 + n], k + 1 + n
def broker(s):
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(5)
            buf, acked = b"", False
            while True:
                k = c.recv(4096)
                if not k:
                    break
                buf += k
                if not acked and buf[:1] == b"\x10":
                    c.sendall(b"\x20\x02\x00\x00")
                    acked = True
                if buf.endswith(b"\xe0\x00"):
                    break
            kind, _connect, at = packet(buf, 0)
            kind, body, _ = packet(buf, at)
            tl = body[0] * 256 + body[1]
            say(kind="mqtt", retain=bool(kind & 1), topic=body[2:2 + tl].decode(), payload=body[2 + tl:].decode())
        except Exception as e:
            say(kind="mqtt-error", error=repr(e))
        finally:
            c.close()
print("pid", flush=True)
sys.stdin.readline()
srv = http.server.ThreadingHTTPServer(("%s", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
b = socket.socket()
b.bind(("%s", 0))
b.listen(8)
threading.Thread(target=broker, args=(b,), daemon=True).start()
say(kind="ports", http=srv.server_address[1], mqtt=b.getsockname()[1])
for line in sys.stdin:
    state["plug"] = line.strip() == "plug on"
''' % (PEER_ADDR, PEER_ADDR)

failures = []
facts = {"armed": False}
EVENTS = queue.Queue()


def check(ok, what, *args):
    text = what % args if args else what
    print("  %s  %s" % ("ok  " if ok else "FAIL", text), flush=True)
    if not ok:
        failures.append(text)


class Forgectrl(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        if self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"event: hello\ndata: {\"max_streams\": 3}\n\n")
            self.wfile.flush()
            while True:
                try:
                    name, data = EVENTS.get(timeout=5)
                except queue.Empty:
                    try:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                    except OSError:
                        return
                    continue
                try:
                    self.wfile.write(("event: %s\ndata: %s\n\n" % (name, json.dumps(data))).encode())
                    self.wfile.flush()
                except OSError:
                    EVENTS.put((name, data))
                    return
        body = {"/cool/status": {"armed": facts["armed"]},
                "/mode": {"mode": "grbl", "controller": "running", "motion": "verified"},
                "/status": {"diag": False, "state": "idle"},
                "/update/status": {"running": False}}.get(self.path)
        if body is None:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def wait_for(cond, seconds, poll=0.25):
    end = time.time() + seconds
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(poll)
    return None


def main():
    if os.environ.get("FFX_AUTO_NS") != "1":
        missing = [t for t in ("unshare", "nsenter", "ip", "mount", "curl") if not shutil.which(t)]
        need = {"forgeext": os.path.isfile(FORGEEXT), "fwup": bool(FWUP), "nft": os.path.isfile(NFT),
                "rules": os.path.isfile(RULES), "the service": os.path.isfile(BIN),
                "cgroup v2": os.path.isfile("/sys/fs/cgroup/cgroup.controllers")}
        if os.geteuid() != 0 or missing or not all(need.values()):
            print("skipped: needs root and %s; tools missing: %s" % ([k for k, v in need.items() if not v], missing))
            return SKIP
        os.execvpe("unshare", ["unshare", "-n", "-m", sys.executable, os.path.abspath(__file__)], dict(os.environ, FFX_AUTO_NS="1"))

    top = tempfile.mkdtemp(prefix="automation-test.")
    os.chmod(top, 0o755)
    root, run_dir, conf, safe = (os.path.join(top, n) for n in ("root", "run", "forgefirm.conf", "ext-safe"))
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    hosts = os.path.join(top, "hosts")
    with open(hosts, "w") as f:
        # the manifest's public destinations, each resolving to the peer, so that a start can judge them
        f.write("127.0.0.1 localhost\n%s ntfy.sh api.pushover.net api.telegram.org discord.com peer.test\n" % PEER_ADDR)
    subprocess.run(["mount", "--bind", hosts, "/etc/hosts"], check=True)
    peer = subprocess.Popen(["unshare", "-n", sys.executable, "-u", "-c", PEER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True)
    peer.stdout.readline()
    ns = ["nsenter", "-t", str(peer.pid), "-n"]
    for cmd in (["ip", "link", "add", "ffxa0", "type", "veth", "peer", "name", "ffxa1"],
                ["ip", "link", "set", "ffxa1", "netns", str(peer.pid)],
                ["ip", "addr", "add", HERE_ADDR + "/24", "dev", "ffxa0"], ["ip", "link", "set", "ffxa0", "up"],
                ns + ["ip", "addr", "add", PEER_ADDR + "/24", "dev", "ffxa1"], ns + ["ip", "link", "set", "ffxa1", "up"],
                ns + ["ip", "link", "set", "lo", "up"]):
        subprocess.run(cmd, check=True, capture_output=True)
    peer.stdin.write("go\n")
    peer.stdin.flush()
    ports = json.loads(peer.stdout.readline())
    hport, mport = ports["http"], ports["mqtt"]
    seen, seen_lock = [], threading.Lock()

    def read_peer():
        for line in peer.stdout:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            with seen_lock:
                seen.append(rec)
    threading.Thread(target=read_peer, daemon=True).start()

    def got(kind, cond=lambda r: True, since=0):
        with seen_lock:
            return [r for r in seen[since:] if r.get("kind") == kind and cond(r)]

    def mark():
        with seen_lock:
            return len(seen)

    def plug(on):
        peer.stdin.write("plug on\n" if on else "plug off\n")
        peer.stdin.flush()

    subprocess.run([NFT, "-f", RULES], check=True)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Forgectrl)
    fport = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    os.makedirs(CG_PARENT, exist_ok=True)
    with open(CG_PARENT + "/cgroup.subtree_control", "w") as f:
        f.write("+cpu +memory +pids")

    # The package's id is in OpenGlow's namespace: the test signs it with a key of its own and names that
    # key as the official one, as install_test does.
    keydir = os.path.join(top, "key")
    os.makedirs(keydir)
    subprocess.run([FWUP, "-g"], cwd=keydir, check=True, capture_output=True)
    official = os.path.join(keydir, "fwup-key.pub")

    def fx(*args):
        p = subprocess.run([FORGEEXT, "--root", root, "--fwup", FWUP, "--nft", NFT, "--no-reserve", "--official-key", official]
                           + list(args), capture_output=True, text=True)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"ok": None, "error": p.stdout[:200] + p.stderr[:200]}

    call_dir = os.path.join(top, "call")

    def call(method, path, body=None):
        args = ["call", ID, method, path] + ([json.dumps(body)] if body is not None else [])
        return fx(*(args + ["--call-dir", call_dir, "--cg-parent", CG_PARENT]))

    print("the package, built for this computer, installed from its own manifest")
    src = os.path.join(top, "pkg")
    os.makedirs(os.path.join(src, "bin"))
    os.makedirs(os.path.join(src, "ui"))
    shutil.copyfile(os.path.join(PKG, "manifest.json"), os.path.join(src, "manifest.json"))
    shutil.copyfile(os.path.join(PKG, "ui", "index.html"), os.path.join(src, "ui", "index.html"))
    shutil.copyfile(BIN, os.path.join(src, "bin", "run"))
    os.chmod(os.path.join(src, "bin", "run"), 0o755)
    archive = os.path.join(top, "automation.ffx")
    subprocess.run(["sh", MKFFX, src, archive, os.path.join(keydir, "fwup-key.priv")], check=True, capture_output=True,
                   env=dict(os.environ, FWUP=FWUP))
    r = fx("install", archive, "--grant", "hold", "--grant", "job_time.run")
    check(r.get("ok") is True and r.get("tier") == "official", "installed, official: %s", r.get("error", r.get("tier")))
    if r.get("ok") is not True:
        shutil.rmtree(top, ignore_errors=True)
        print("FAIL: automation_test, nothing to test without the package")
        return 1

    abi = int(subprocess.run([sys.executable, "-c", "import ctypes;print(ctypes.CDLL(None).syscall(444,None,0,1))"],
                             capture_output=True, text=True).stdout.strip() or 0)
    with open(conf, "w") as f:
        f.write("ext_enabled=1\n")
    log_path = os.path.join(top, "daemon.log")
    log = open(log_path, "w")
    holds_dir = os.path.join(top, "holds")
    daemon = subprocess.Popen([FORGEEXT, "--root", root, "--fwup", FWUP, "--nft", NFT, "--official-key", official, "run", "--conf",
                               conf, "--safe-file", safe,
                               "--forgectrl", "127.0.0.1:%d" % fport, "--cg-parent", CG_PARENT, "--run-dir", run_dir,
                               "--holds-dir", holds_dir, "--api-dir", os.path.join(top, "api"), "--call-dir", call_dir]
                              + (["--landlock-fs-only"] if abi < 4 else []),
                              stdout=log, stderr=log, env=dict(os.environ, FFLOG_STDERR="1", FFLOG_SOCK="/nonexistent"))

    def status():
        try:
            with open(os.path.join(run_dir, "status.json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def svc():
        return next((s for s in status().get("services", []) if s["id"] == ID), {})

    def held():
        try:
            with open(os.path.join(holds_dir, ID + ".json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def page(path="/status"):
        r = call("GET", path)
        return r.get("body") if r.get("ok") and r.get("status") == 200 else None

    def emit(name, data):
        EVENTS.put((name, data))

    try:
        check(wait_for(lambda: svc().get("state") == "running", 40), "the service runs: %s", svc())
        check(wait_for(lambda: (page() or {}).get("connected"), 30), "and follows the machine's events: %s", page())
        time.sleep(1.0)

        print("the rules, as the page reads and saves them")
        v = page("/rules") or {}
        check(v.get("rules") == [] and "job.ended" in v.get("known_events", []) and "hold_until" in v.get("action_types", []),
              "no rules yet, and what the page may offer: %s", v)
        done = {"id": "done", "name": "A job ends", "on": ["job.ended"], "if": {"result": "ended"},
                "do": [{"type": "notify", "service": "ntfy", "server": "http://%s:%d" % (PEER_ADDR, hport), "topic": "laser",
                        "title": "Job", "message": "{event}: {data.result}", "token": "SECRET1", "priority": 4}]}
        r = call("POST", "/rule", {"rule": done})
        check(r.get("ok") and r.get("status") == 200, "a rule saved: %s", r)
        shown = json.dumps(r.get("body"))
        check("SECRET1" not in shown and "__kept__" in shown, "and the page is not shown its token back: %s", shown[:300])
        kept = json.loads(json.dumps(r["body"]["rules"][0]))
        kept["do"][0]["message"] = "{event}, {data.result}"
        r = call("POST", "/rule", {"rule": kept})
        stored = json.load(open(os.path.join(root, "data", ID, "rules.json")))
        check(r.get("status") == 200 and stored["rules"][0]["do"][0]["token"] == "SECRET1"
              and stored["rules"][0]["do"][0]["message"] == "{event}, {data.result}",
              "saved again with the marker: the token kept, the message changed: %s", r.get("body", r.get("error")))
        for body, words in (({"rule": {"id": "BAD", "on": ["x"], "do": [{"type": "clear_hold"}]}}, "lowercase"),
                            ({"rule": {"id": "x", "on": ["x"], "do": [{"type": "http", "url": "file:///etc/passwd"}]}},
                             "http:// or https://"),
                            ({"rule": {"id": "y", "on": ["x"], "do": [{"type": "notify", "service": "pushover", "token": "__kept__",
                                                                     "user": "u", "message": "m"}]}}, "none to keep"),
                            ({"nothing": 1}, "names no rule")):
            r = call("POST", "/rule", body)
            words_ok = words in json.dumps(r.get("body"))
            check(r.get("ok") and r.get("status") == 400 and words_ok, "refused in words (%s): %s", words, r)
        r = call("POST", "/rule/delete", {"id": "none"})
        check(r.get("status") == 404, "deleting a rule there is none of: %s", r)
        r = call("GET", "/nowhere")
        check(r.get("status") == 404, "a page call there is none of: %s", r)

        print("a test action: only where the operator said it may go")
        m = mark()
        r = call("POST", "/test", {"rule": "done", "action": 1})
        body = r.get("body") or {}
        check(r.get("ok") and body.get("ok") is False and body.get("detail") and not got("http", since=m),
              "the peer is not a named destination: refused, and nothing reached it: %s", body)
        before = svc().get("pid")
        r = fx("dest", ID, "add", "%s:%d" % (PEER_ADDR, hport))
        check(r.get("ok"), "the operator names the peer's server: %s", r)
        r = fx("dest", ID, "add", "%s:%d" % (PEER_ADDR, mport))
        check(r.get("ok"), "and its broker: %s", r)
        check(wait_for(lambda: svc().get("state") == "running" and svc().get("pid") != before and (page() or {}).get("connected"),
                       40), "the service is started again with its way out: %s", svc())
        time.sleep(1.0)
        m = mark()
        r = call("POST", "/test", {"rule": "done", "action": 1})
        body = r.get("body") or {}
        n = wait_for(lambda: got("http", lambda x: x["path"] == "/laser", m), 5) or []
        check(body.get("ok") is True and "HTTP 200" in body.get("detail", ""), "the test reaches it: %s", body)
        h = n[0] if n else {}
        check(h.get("method") == "POST" and h.get("body") == "test, " and h.get("headers", {}).get("Authorization") == "Bearer SECRET1"
              and h.get("headers", {}).get("Title") == "Job" and h.get("headers", {}).get("Priority") == "4"
              and h.get("headers", {}).get("Content-Type", "").startswith("text/plain"),
              "in ntfy's own form, the token from the saved rule: %s", h)
        r = call("POST", "/test", {"rule": "done", "action": 9})
        check(r.get("status") == 404, "a test of an action there is none of: %s", r)

        print("events into notifications")
        m = mark()
        emit("job.ended", {"result": "alarm"})
        emit("job.ended", {"result": "ended"})
        n = wait_for(lambda: got("http", lambda x: x["path"] == "/laser", m), 15) or []
        time.sleep(1.5)
        n = got("http", lambda x: x["path"] == "/laser", m)
        check(len(n) == 1 and n[0].get("body") == "job.ended, ended", "one notification, for the job that ended well: %s",
              [x.get("body") for x in n])

        print("the exhaust: on for a job, off after its run-on, the run-on canceled by the next job")
        exhaust = {"id": "exhaust", "on": ["job.arming", "job.ended"],
                   "do": [{"type": "http", "url": "http://%s:%d/plug/on" % (PEER_ADDR, hport)}]}
        # two rules: on at arming, off two seconds after the end unless another job arms first
        on_rule = dict(exhaust, id="exhaust-on", on=["job.arming"])
        off_rule = {"id": "exhaust-off", "on": ["job.ended"],
                    "do": [{"type": "http", "url": "http://%s:%d/plug/off" % (PEER_ADDR, hport), "after_s": 2,
                            "cancel_on": ["job.arming"]}]}
        for rule in (on_rule, off_rule):
            r = call("POST", "/rule", {"rule": rule})
            check(r.get("status") == 200, "saved %s: %s", rule["id"], r.get("body", {}).get("error") if r.get("body") else r)
        m = mark()
        emit("job.arming", {})
        check(wait_for(lambda: got("http", lambda x: x["path"] == "/plug/on", m), 10), "armed: the plug is turned on")
        emit("job.ended", {"result": "ended"})
        pend = wait_for(lambda: (page() or {}).get("pending"), 3) or []
        check(any(p.get("rule") == "exhaust-off" for p in pend), "the run-on waits: %s", pend)
        check(wait_for(lambda: got("http", lambda x: x["path"] == "/plug/off", m), 8), "and turns it off after it")
        m = mark()
        emit("job.ended", {"result": "ended"})
        time.sleep(0.5)
        emit("job.arming", {})
        time.sleep(3.5)
        check(not got("http", lambda x: x["path"] == "/plug/off", m) and got("http", lambda x: x["path"] == "/plug/on", m),
              "a job armed inside the run-on keeps the exhaust on")
        check("canceled: exhaust-off 1" in open(log_path).read(), "and the service says so in its log")

        print("every event to MQTT")
        r = call("POST", "/rule", {"rule": {"id": "mqtt", "on": ["*"], "do": [
            {"type": "mqtt", "broker": "%s:%d" % (PEER_ADDR, mport), "topic": "forgefirm/{event}", "retain": True}]}})
        check(r.get("status") == 200, "saved: %s", r.get("body"))
        m = mark()
        emit("lid", {"closed": False})
        pub = wait_for(lambda: got("mqtt", lambda x: x["topic"] == "forgefirm/lid", m), 10) or []
        check(pub and pub[0].get("retain") is True and json.loads(pub[0]["payload"]) == {"event": "lid", "data": {"closed": False}},
              "published, retained, the event and its data: %s", pub)
        call("POST", "/rule/delete", {"id": "mqtt"})
        check(not any(x["id"] == "mqtt" for x in (page("/rules") or {}).get("rules", [])), "and the rule deleted")

        print("a job held until the exhaust answers that it is on")
        plug(False)
        r = call("POST", "/rule", {"rule": {"id": "wait", "on": ["job.arming"], "do": [
            {"type": "hold_until", "url": "http://%s:%d/plug/status" % (PEER_ADDR, hport), "match": "\"ison\": true",
             "timeout_s": 8, "every_s": 1}]}})
        check(r.get("status") == 200, "saved: %s", r.get("body"))
        r = call("POST", "/test", {"rule": "wait", "action": 1})
        check(r.get("status") == 400, "a hold is not tried from the page: %s", r.get("body"))
        call("POST", "/rule/delete", {"id": "exhaust-on"})
        emit("job.arming", {})
        h = wait_for(lambda: (held() or {}).get("raised") and held(), 10) or {}
        check(h.get("reason") == "waiting for the exhaust to confirm", "held, in words: %s", h)
        time.sleep(2)
        check((held() or {}).get("raised"), "and still, while the plug is off")
        plug(True)
        check(wait_for(lambda: held() is not None and not held().get("raised"), 6), "the plug answers on: the hold is clear: %s",
              held())
        plug(False)
        emit("job.ended", {"result": "ended"})
        time.sleep(1)
        emit("job.arming", {})
        check(wait_for(lambda: (held() or {}).get("raised"), 10), "the next job is held again")
        h = wait_for(lambda: "did not confirm" in (held() or {}).get("reason", "") and held(), 15) or {}
        check(h.get("raised") and h.get("reason") == "it did not confirm within 8 s", "never on: the hold stands, in words: %s", h)
        emit("job.ended", {"result": "ended"})
        check(wait_for(lambda: held() is not None and not held().get("raised"), 8), "and goes when the job ends: %s", held())

        print("what the page is shown of it")
        st = page() or {}
        check(any(o.get("type") == "hold_until" and not o.get("ok") for o in st.get("outcomes", []))
              and any(e.get("event") == "job.arming" for e in st.get("events", [])),
              "the status: outcomes and events: %s", json.dumps(st)[:300])

        print("the rules outlive a restart")
        old = svc().get("pid")
        fx("disable", ID)
        check(wait_for(lambda: svc().get("state") != "running", 15), "turned off")
        fx("enable", ID)
        check(wait_for(lambda: svc().get("state") == "running" and svc().get("pid") != old, 40), "and on")
        ids = sorted(x["id"] for x in (wait_for(lambda: page("/rules"), 10) or {}).get("rules", []))
        check(ids == ["done", "exhaust-off", "wait"], "the same rules: %s", ids)
        check("SECRET1" not in open(log_path).read(), "no secret in the host's log")
    finally:
        daemon.send_signal(signal.SIGTERM)
        try:
            daemon.wait(20)
        except subprocess.TimeoutExpired:
            daemon.kill()
        log.close()
        if failures:
            print("--- the daemon's log, its end")
            print("".join(open(log_path).readlines()[-60:]))
        server.shutdown()
        peer.kill()
        for d in os.listdir(CG_PARENT) if os.path.isdir(CG_PARENT) else []:
            p = os.path.join(CG_PARENT, d)
            try:
                open(p + "/cgroup.kill", "w").write("1")
                time.sleep(0.3)
                os.rmdir(p)
            except OSError:
                pass
        try:
            os.rmdir(CG_PARENT)
        except OSError:
            pass
        shutil.rmtree(top, ignore_errors=True)
    print("%s: automation_test, %d failure%s" % ("FAIL" if failures else "PASS", len(failures), "" if len(failures) == 1 else "s"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
