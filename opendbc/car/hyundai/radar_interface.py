import math
from dataclasses import dataclass

from opendbc.can import CANParser
from opendbc.car import Bus, structs
from opendbc.car.interfaces import RadarInterfaceBase
from opendbc.car.hyundai.values import DBC

from opendbc.sunnypilot.car.hyundai.radar_interface_ext import RadarInterfaceExt

RADAR_START_ADDR = 0x500
RADAR_MSG_COUNT = 32
MRR30_RADAR_START_ADDR = 0x210
MRR30_RADAR_MSG_COUNT = 16

HYUNDAI_MANDO_FRONT_RADAR_DBC = "hyundai_kia_mando_front_radar_generated"
HYUNDAI_MRR30_RADAR_DBC = "hyundai_mrr30_radar_generated"

# POC for parsing corner radars: https://github.com/commaai/openpilot/pull/24221/


@dataclass(frozen=True)
class RadarTrackConfig:
  start_addr: int
  msg_count: int
  radar_type: str
  bus: int = 1
  frequency: int = 50


RADAR_TRACK_CONFIGS = {
  HYUNDAI_MANDO_FRONT_RADAR_DBC: RadarTrackConfig(RADAR_START_ADDR, RADAR_MSG_COUNT, "mando"),
  # GV60 (and E-GMP) Mando MRR30: 16 frames @ 0x210, two tracks each. bus=1 (ACAN) per GV60 dump.
  HYUNDAI_MRR30_RADAR_DBC: RadarTrackConfig(MRR30_RADAR_START_ADDR, MRR30_RADAR_MSG_COUNT, "mrr30", bus=1),
}


def get_radar_track_config(car_fingerprint):
  radar_dbc = DBC[car_fingerprint].get(Bus.radar)
  return RADAR_TRACK_CONFIGS.get(radar_dbc)


def get_radar_can_parser(CP, radar_config):
  if radar_config is None:
    return None
  messages = [(f"RADAR_TRACK_{addr:x}", radar_config.frequency)
              for addr in range(radar_config.start_addr, radar_config.start_addr + radar_config.msg_count)]
  try:
    return CANParser(DBC[CP.carFingerprint][Bus.radar], messages, radar_config.bus)
  except Exception:
    # fail-soft: missing/bad radar DBC must never block car recognition (card builds this pre-carParams)
    return None


class RadarInterface(RadarInterfaceBase, RadarInterfaceExt):
  def __init__(self, CP, CP_SP):
    RadarInterfaceBase.__init__(self, CP, CP_SP)
    RadarInterfaceExt.__init__(self, CP, CP_SP)
    self.updated_messages = set()
    self.radar_config = get_radar_track_config(CP.carFingerprint)
    self.trigger_msg = (self.radar_config.start_addr + self.radar_config.msg_count - 1
                        if self.radar_config is not None else RADAR_START_ADDR)
    self.track_id = 0
    self.track_addrs = []
    if self.radar_config is not None:
      self.track_addrs = [(addr, f"RADAR_TRACK_{addr:x}")
                          for addr in range(self.radar_config.start_addr,
                                            self.radar_config.start_addr + self.radar_config.msg_count)]

    self.radar_off_can = CP.radarUnavailable
    self.rcp = get_radar_can_parser(CP, self.radar_config)

    if self.rcp is None:
      self.initialize_radar_ext(self.trigger_msg)

  def update(self, can_strings):
    if self.radar_off_can or (self.rcp is None):
      return super().update(None)

    vls = self.rcp.update(can_strings)
    self.updated_messages.update(vls)

    if self.trigger_msg not in self.updated_messages:
      return None

    rr = self._update(self.updated_messages)
    self.updated_messages.clear()

    return rr

  def _update(self, updated_messages):
    ret = structs.RadarData()
    if self.rcp is None:
      return ret

    if not self.rcp.can_valid:
      ret.errors.canError = True

    if self.use_radar_interface_ext:
      return self.update_ext(ret)

    if self.radar_config is None:
      return ret

    radar_type = self.radar_config.radar_type
    vl = self.rcp.vl

    for addr, track_name in self.track_addrs:
      msg = vl[track_name]

      if radar_type == "mrr30":
        # two tracks per frame: signals prefixed 1_ and 2_
        for i in ("1", "2"):
          track_key = addr * 2 + int(i) - 1
          valid = msg[f"{i}_STATE"] in (3, 4)
          if valid:
            pt = self.pts.get(track_key)
            if pt is None:
              pt = structs.RadarData.RadarPoint()
              pt.trackId = self.track_id
              self.track_id += 1
              self.pts[track_key] = pt
            pt.measured = True
            pt.dRel = msg[f"{i}_LONG_DIST"]
            pt.yRel = msg[f"{i}_LAT_DIST"]
            pt.vRel = msg[f"{i}_REL_SPEED"]
            pt.aRel = float('nan')
            pt.yvRel = float('nan')
          elif track_key in self.pts:
            del self.pts[track_key]
        continue

      # mando (0x500) azimuth-based
      if addr not in self.pts:
        self.pts[addr] = structs.RadarData.RadarPoint()
        self.pts[addr].trackId = self.track_id
        self.track_id += 1

      valid = msg['STATE'] in (3, 4)
      if valid:
        azimuth = math.radians(msg['AZIMUTH'])
        self.pts[addr].measured = True
        self.pts[addr].dRel = math.cos(azimuth) * msg['LONG_DIST']
        self.pts[addr].yRel = 0.5 * -math.sin(azimuth) * msg['LONG_DIST']
        self.pts[addr].vRel = msg['REL_SPEED']
        self.pts[addr].aRel = msg['REL_ACCEL']
        self.pts[addr].yvRel = float('nan')
      else:
        del self.pts[addr]

    ret.points = list(self.pts.values())
    return ret
