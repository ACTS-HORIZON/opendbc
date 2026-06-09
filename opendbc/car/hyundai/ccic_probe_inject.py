"""
ccic_probe_inject.py - live, config-driven CAN injector for ccIC reverse engineering.

Driven by /data/ccic_probe.json (edit over SSH; reloads within ~1s, no rebuild/reflash,
manager stays up). Frames go out via pandad's normal CAN-FD path; the DBC packer fills
CHECKSUM, this module auto-increments COUNTER. Injected ADDRESSES must be in the panda
TX allowlist (see hyundai_canfd.h: 0x161/0x162 added). Set "enabled": false to stop.
"""
import json
import os
import shutil
import time

CONFIG_PATH = "/data/ccic_probe.json"
DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "ccic_probe_default.json")


class CcicProbe:
  def __init__(self):
    self._cfg = {"enabled": False, "msgs": []}
    self._mtime = None
    self._last_check = 0.0
    self._counters = {}

  def _reload(self):
    now = time.monotonic()
    if now - self._last_check < 1.0:
      return
    self._last_check = now
    if not os.path.exists(CONFIG_PATH) and os.path.exists(DEFAULT_PATH):
      try:
        shutil.copyfile(DEFAULT_PATH, CONFIG_PATH)
        print('[ccic_probe] seeded /data/ccic_probe.json from repo default')
      except Exception as e:
        print('[ccic_probe] seed failed:', e)
    try:
      m = os.path.getmtime(CONFIG_PATH)
      if m != self._mtime:
        with open(CONFIG_PATH) as f:
          self._cfg = json.load(f)
        self._mtime = m
        print(f"[ccic_probe] reloaded: enabled={self._cfg.get('enabled')} "
              f"msgs={[x.get('name') for x in self._cfg.get('msgs', [])]}")
    except FileNotFoundError:
      self._cfg = {"enabled": False, "msgs": []}
    except Exception as e:
      print(f"[ccic_probe] bad config, ignoring: {e}")

  def msgs(self, packer, frame):
    self._reload()
    if not self._cfg.get("enabled"):
      return []
    out = []
    for m in self._cfg.get("msgs", []):
      rate = m.get("rate_hz", 50)
      div = max(1, round(100.0 / rate))
      if frame % div != 0:
        continue
      name = m["name"]
      bus = m.get("bus", 0)
      vals = dict(m.get("values", {}))
      c = self._counters.get(name, 0)
      vals.setdefault("COUNTER", c)
      self._counters[name] = (c + 1) & 0xFF
      try:
        out.append(packer.make_can_msg(name, bus, vals))
      except Exception as e:
        print(f"[ccic_probe] pack {name} failed: {e}")
    return out
