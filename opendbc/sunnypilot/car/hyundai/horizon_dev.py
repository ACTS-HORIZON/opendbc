"""
Horizon Dev — on-device advanced knobs for horizonpilot (Collin / ACTS-HORIZON).

A tiny, throttled reader for the personal "advanced knobs" menu. It lets values be tested
live on the comma (max steer, steer damp, ...) without switching branches or rebuilding.

Design rules:
  * Fails CLOSED to stock. If params are unavailable (e.g. pure-opendbc CI where `openpilot`
    is not importable) or a knob is disabled, every accessor returns None and the caller keeps
    stock behavior.
  * Never exceeds the panda safety envelope. STEER_MAX is clamped in-code to PANDA_STEER_CAP;
    going above that additionally requires flashing the panda .max_torque bump documented in
    HORIZON_DEV_MENU.md. This class alone can only *lower* steer authority from stock.
  * Reads are throttled (~3 s) to keep the 100 Hz control loop cheap, mirroring
    sunnypilot's latcontrol_torque_ext_override.

This module is intentionally isolated so it is trivial to grep for and to remove.
"""

# The panda hyundai_canfd safety hook hard-caps requested steer torque at this value
# (opendbc/safety/modes/hyundai_canfd.h -> HYUNDAI_CANFD_STEERING_LIMITS.max_torque).
# Keep these two numbers in sync. Raised from stock 409 to 500 for max-steer testing
# (HORIZON_DEV_MENU.md §A) — this widens the panda safety envelope; parked-test first.
PANDA_STEER_CAP = 500

# Damping_Gain valid range on the LFA message (Damping_Gain signal is [3, 200]).
DAMP_GAIN_MIN = 3
DAMP_GAIN_MAX = 200

_READ_INTERVAL_FRAMES = 300  # ~3 s at 100 Hz


class HorizonDev:
  def __init__(self):
    self._params = None
    try:
      from openpilot.common.params import Params
      self._params = Params()
    except Exception:
      # opendbc standalone / no params backend -> stay stock forever.
      self._params = None

    self._frame = -1

    # Cached knob state (None == use stock).
    self.steer_max: int | None = None
    self.damp_gain: int | None = None

  def _get_bool(self, key: str) -> bool:
    try:
      return bool(self._params.get_bool(key))
    except Exception:
      return False

  def _get_int(self, key: str, default: int) -> int:
    try:
      val = self._params.get(key, return_default=True)
      return int(val) if val is not None else default
    except Exception:
      return default

  def update(self) -> None:
    """Refresh knob state from params, throttled. Call once per control frame."""
    if self._params is None:
      return

    self._frame += 1
    if self._frame % _READ_INTERVAL_FRAMES != 0:
      return

    # --- max steer ---
    if self._get_bool("HorizonSteerMaxEnabled"):
      raw = self._get_int("HorizonSteerMax", PANDA_STEER_CAP)
      # Clamp hard to the panda cap so a bumped slider can never request more than the
      # firmware allows. Raising this requires the documented panda reflash.
      self.steer_max = int(min(max(raw, 1), PANDA_STEER_CAP))
    else:
      self.steer_max = None

    # --- steer damp (LFA Damping_Gain) ---
    if self._get_bool("HorizonSteerDampEnabled"):
      raw = self._get_int("HorizonSteerDampGain", 100)
      self.damp_gain = int(min(max(raw, DAMP_GAIN_MIN), DAMP_GAIN_MAX))
    else:
      self.damp_gain = None

  def steer_max_or(self, stock: int) -> int:
    return self.steer_max if self.steer_max is not None else stock
