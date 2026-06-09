#!/usr/bin/env python3
"""
ccic_devmenu.py - phone-friendly button panel for the ccIC probe.

Standalone (does NOT touch openpilot/manager/panda). Rewrites /data/ccic_probe.json,
which the injector module reads & sends. Run on the comma:
  python3 /data/openpilot/opendbc_repo/opendbc/car/hyundai/ccic_devmenu.py
Then from your phone (on the comma hotspot): http://192.168.43.1:8080
Buttons write a preset; the field box sets one CCNC_0x161 signal live (sweep to find the
trigger). OFF sets enabled=false (injection stops within ~1s).
"""
import json, http.server, urllib.parse

CONFIG = "/data/ccic_probe.json"
BUS = 0
BASE_161 = {
    "LKA_ICON": 2, "LFA_ICON": 2, "HDA_ICON": 2, "FCA_ICON": 1, "DAW_ICON": 1,
    "LANELINE_LEFT": 1, "LANELINE_RIGHT": 1,
    "LANELINE_LEFT_POSITION": 8, "LANELINE_RIGHT_POSITION": 2, "LANELINE_CURVATURE": 15,
    "LANE_LEFT": 1, "LANE_RIGHT": 1, "CENTERLINE": 1,
    "LCA_LEFT_ARROW": 1, "LCA_RIGHT_ARROW": 1, "BCA_LEFT": 1, "BCA_RIGHT": 1,
    "TARGET": 1, "TARGET_DISTANCE": 250, "SETSPEED": 1, "SETSPEED_SPEED": 65,
}
BASE_162 = {"LEAD": 1, "LEAD_DISTANCE": 250, "SPEEDLIMIT": 65, "VIBRATE": 0}
state_161 = dict(BASE_161)

def write_cfg(msgs, enabled=True):
    cfg = {"enabled": enabled, "msgs": msgs}
    with open(CONFIG, "w") as f:
        json.dump(cfg, f, indent=2)
    return cfg

def m161(v): return {"name": "CCNC_0x161", "bus": BUS, "rate_hz": 50, "values": v}
def m162(v): return {"name": "CCNC_0x162", "bus": BUS, "rate_hz": 50, "values": v}

PRESETS = {
    "full":    lambda: write_cfg([m161(dict(BASE_161)), m162(dict(BASE_162))]),
    "lanes":   lambda: write_cfg([m161({k: BASE_161[k] for k in
                 ("LKA_ICON","LFA_ICON","HDA_ICON","LANELINE_LEFT","LANELINE_RIGHT",
                  "LANELINE_LEFT_POSITION","LANELINE_RIGHT_POSITION","LANELINE_CURVATURE",
                  "LANE_LEFT","LANE_RIGHT","CENTERLINE")})]),
    "icons":   lambda: write_cfg([m161({"LCA_LEFT_ARROW":1,"LCA_RIGHT_ARROW":1,"LCA_LEFT_ICON":1,
                  "LCA_RIGHT_ICON":1,"BCA_LEFT":2,"BCA_RIGHT":2,"LKA_ICON":2,"LFA_ICON":2,"HDA_ICON":2})]),
    "lead":    lambda: write_cfg([m161({"TARGET":1,"TARGET_DISTANCE":200,"DISTANCE_CAR":1}),
                                  m162({"LEAD":1,"LEAD_DISTANCE":200})]),
    "vibrate": lambda: write_cfg([m162({"VIBRATE":3})]),
    "off":     lambda: write_cfg([], enabled=False),
}

PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font:18px sans-serif;margin:16px;background:#111;color:#eee}
button{font:18px sans-serif;padding:14px 18px;margin:6px;border-radius:10px;border:0;background:#2a6;color:#fff}
button.off{background:#a33}input{font:18px;padding:8px;margin:4px;border-radius:8px}
.row{margin:10px 0}pre{background:#000;padding:10px;border-radius:8px;white-space:pre-wrap}</style>
<h2>ccIC probe</h2>
<div class=row>
<button onclick=g('full')>FULL</button><button onclick=g('lanes')>Lanes</button>
<button onclick=g('icons')>Icons/LCA/BSD</button><button onclick=g('lead')>Lead</button>
<button onclick=g('vibrate')>Vibrate</button><button class=off onclick=g('off')>OFF</button>
</div>
<div class=row>set CCNC_0x161:
<input id=k placeholder=SIGNAL_NAME size=20>=<input id=v size=4 value=1>
<button onclick=setf()>apply</button></div>
<pre id=out>ready</pre>
<script>
function show(t){document.getElementById('out').textContent=t}
function g(p){fetch('/preset?p='+p).then(r=>r.text()).then(show)}
function setf(){let k=document.getElementById('k').value,v=document.getElementById('v').value;
 fetch('/set?k='+encodeURIComponent(k)+'&v='+encodeURIComponent(v)).then(r=>r.text()).then(show)}
</script>"""

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, ctype="text/plain"):
        b = body.encode(); self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            self._send(PAGE, "text/html")
        elif u.path == "/preset":
            p = q.get("p", ["off"])[0]; cfg = PRESETS.get(p, PRESETS["off"])()
            self._send(f"preset '{p}':\n" + json.dumps(cfg, indent=2))
        elif u.path == "/set":
            k = q.get("k", [""])[0]
            try: v = int(q.get("v", ["0"])[0])
            except ValueError: v = 0
            if k:
                state_161[k] = v; cfg = write_cfg([m161(dict(state_161))])
                self._send(f"set {k}={v}:\n" + json.dumps(cfg, indent=2))
            else:
                self._send("no signal name")
        else:
            self._send("?")

if __name__ == "__main__":
    print("ccic devmenu on http://0.0.0.0:8080  (writes %s)" % CONFIG)
    http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
