# Copyright 2023 kjy00302 <kjy00302@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import struct

from chirp import chirp_common, directory, errors, memmap
from chirp import bitwise
from chirp.settings import RadioSetting, RadioSettingGroup, \
    RadioSettingValueInteger, RadioSettingValueList, \
    RadioSettingValueBoolean, RadioSettingValueString, \
    RadioSettingValueMap, RadioSettingValueFloat, RadioSettings

MEM_FORMAT = """
struct string {
  u8 data[7];
  u8 len;
};

#seekto 0x0010;
struct {
  bbcd rxfreq[3];
  u8 unused1;
  u8 rxtoneind;
  u8 unused2:4,
    rptmode:2,
    rxtonemode:2;
  u8 nextmem;
  u8 prevmem;
  bbcd txfreq[3];
  u8 unused3;
  u8 txtoneind;
  u8 unused4:4,
    txpower:1,
    dtmf:1,
    txtonemode:2;
  u8 unused5:1,
    vox:1,
    tailcut:1,
    unused6:1,
    bcl:1,
    unused7:1,
    rxtxoffset:2;
  u8 pttid:2,
    scan:1,
    narrow:1,
    unused8:2,
    band_identifier:2;
} memory[200];

#seekto 0x0C90;
u8 fmvol;

#seekto 0x0D00;
struct string dtmfalias[16];

struct {
  u8 lowbatalert:1,
    beeptone:1,
    tailphase:1,
    rogertone:1,
    opentone:1,
    unused1:2,
    sidetone:1;
  u8 pttmainline:1,
    voxinhibitonrecv:1,
    ani:1,
    passwordset:1,
    keylocked:1,
    dualwatch:1,
    unused2:1,
    battsaver:1;
  u8 stunset:1,
    stuntype:1,
    unused3:1,
    autoresponse:1,
    decodesuccesstone:1,
    resettone:1,
    rxmutemode:2;
  u8 lockobj:2,
    lampmode:2,
    lampcolor:2,
    scanmode:2;
  u8 txstop:1,
    mainline:1,
    expandfreq:1,
    dwreturn:1,
    fmstrong:1,
    unused4:1,
    openmessagetype:2;
  struct {
    u8 mode:1,
      unused1:2,
      dispmode:2,
      unused2:1,
      band:2;
  } workmode[2];
  u8 linealastmemory;
  u8 lineblastmemory;
  u8 squelchlevel;
  u8 step;
  u8 voxgainlevel;
  u8 voxdelaytime;
  u8 timeouttimer;
  u8 autopoweroff;
  u8 lamptime;
  u8 prioritychannel;
  u8 resettime;
  u8 longpresstime;
  u8 dtmfspeed;
  u8 fddt;
  u8 fdt;
  u8 ahdigittime;
  u8 groupcode;
  u8 pttid_bot_len;
  u8 pttid_eot_len;
  u8 anicodelen;
  u8 stuncodelen;
  u8 sk1long;
  u8 sk1short;
  u8 sk2long;
  u8 sk2short;
  struct string password;
  struct string openmessage;
  u8 pttid_bot[16];
  u8 pttid_eot[16];
  u8 anicode[16];
  u8 stuncode[15];
} options;

u8 freqmemorycnt;
u8 dtmfcalllistlen[16];
struct {
  u8 call[16];
} dtmfcalllist[16];


struct vfo_rx {
  bbcd rxfreq[3];
  u8 unused1[5];
  bbcd txfreq[3];
  u8 unused2[4];
  u8 unused3:6,
  band_identifier:2;
};

struct vfo_rxtx {
  bbcd rxfreq[3];
  u8 unused1[5];
  bbcd txfreq[3];
  u8 unused2[2];
  u8 unused3:4,
    txpower:1,
    dtmf:1,
    unused4:2;
  u8 unused5:1,
    vox:1,
    tailcut:1,
    unused6:1,
    bcl:1,
    unused7:1,
    rxtxoffset:2;
  u8 pttid:2,
    unused8:1,
    widenarr:1,
    unused9:2,
    band_identifier:2;
};

struct vfoconfset {
  struct vfo_rx band1;
  struct vfo_rxtx band2;
  struct vfo_rx band3;
  struct vfo_rxtx band4;
  u8 padding[16];
};

struct vfoconfset vfo[2];

#seekto 0x1010;
struct string chalias[200];

struct freqrange_rx {
  u8 padding1[8];
  bbcd rxfreqmin[3];
  u8 unused1;
  bbcd rxfreqmax[3];
  u8 unused2;
};

struct freqrange_rxtx {
  bbcd rxfreqmin[3];
  u8 unused1;
  bbcd rxfreqmax[3];
  u8 unused2;
  bbcd txfreqmin[3];
  u8 unused3;
  bbcd txfreqmax[3];
  u8 unused4;
};

struct freqrange_line {
  struct freqrange_rx band1;
  struct freqrange_rxtx band2;
  struct freqrange_rx band3;
  struct freqrange_rxtx band4;
  u8 padding1[16];
};

struct freqrange_line freqrange[2];

//u8 unknown[112];
"""

BAND1 = (chirp_common.to_MHz(87.5), chirp_common.to_MHz(108))
BAND2 = (chirp_common.to_MHz(136), chirp_common.to_MHz(174))
BAND3 = (chirp_common.to_MHz(200), chirp_common.to_MHz(260))
BAND4 = (chirp_common.to_MHz(400), chirp_common.to_MHz(470))

VALID_BANDS = [BAND1, BAND2, BAND3, BAND4]

STEPS = [5.0, 6.25, 10.0, 12.5, 25.0, 50.0, 100.0, 1000.0]

CHARSET = "0123456789" + \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + \
    "abcdefghijklmnopqrstuvwxyz" + \
    "!\"#$%&'()*+, -./:;<=>?@[]^_`{|} "

DTMFCHARSET = "0123456789ABCD*#"
TONES = sorted(chirp_common.TONES + (63.0, ))
DTCS_CODES = sorted(chirp_common.DTCS_CODES + (17, 50, 645))
POWER_LEVELS = [
    chirp_common.PowerLevel("High", watts=5.00),
    chirp_common.PowerLevel("Low", watts=1.00)
]
POWER_LIST = ["High", "Low"]
PTTID_LIST = ["Off", "BOT", "EOT", "Both"]
RPTMD_LIST = ["Off", "Reverse", "Talkaround"]

AB_LIST = ["A", "B"]
BANDWIDTH_LIST = ["Wide", "Narrow"]
MODE_LIST = ["Channel", "Name", "Frequency"]
LAMPMODE_LIST = ["Disable", "Key", "Continue"]
LAMPCOLOR_LIST = ["Orange", "Blue", "Purple"]
RESUME_LIST = ["TO", "CO", "SE"]
BAND_LIST = ["Band 1", "Band 2", "Band 3", "Band 4"]
DTMFSPEED_MAP = [
    ("6digit/s", 17), ("8digit/s", 13),
    ("10digit/s", 11), ("15digit/s", 8),
]
GROUPCODE_MAP = [
    ("Off", 0xff), ("A", 0x0a), ("B", 0x0b), ("C", 0x0c),
    ("D", 0x0d), ("*", 0x0e), ("#", 0x0f),
]
WORKMODE_LIST = ["VFO Mode", "MR Mode"]
STUNTYPE_LIST = ["TX Inhibit", "Transceiver Inhibit"]

SKL_LIST = [
    "None",
    "Squelch Off",
    "Squelch Off Momentary",
    "Monitor",
    "Monitor Momentary",
    "Call",
    "Alarm",
    "1750Hz",
    "Scan Add/Del",
    "Lamp"
]

SKS_LIST = [
    "None",
    "Squelch Off",
    "Monitor",
    "Call",
    "Scan Add/Del",
    "Lamp"
]

OPENMESSAGE_LIST = ["OFF", "DC VOLT", "LOGO", "MESSAGE"]
KEYLOCK_LIST = ["PTT", "KEY", "K+S", "ALL"]
MAINLINE_LIST = ["Line A", "Line B"]
TAILPHASE_LIST = ["120D", "180D"]
RXMUTE_LIST = ["QT", "SIG", "AND", "OR"]
PRIORITY_LIST = ["None"] + \
    [str(x) for x in range(1, 201)]
TIMEOUT_LIST = ["Off"] + ["%d min" % x for x in range(1, 8)]
APO_LIST = ["Disable"] + ["%d hour" % x for x in range(1, 15)]
STEPS_LIST = ["%02.2fKHz" % x for x in STEPS]
INV_LIST = ["stunset", "dtmf"]


def _freq_to_band(freq, mul=1):
    if BAND1[0] <= freq * mul <= BAND1[1]:
        return 0
    elif BAND2[0] <= freq * mul <= BAND2[1]:
        return 1
    elif BAND3[0] <= freq * mul <= BAND3[1]:
        return 2
    elif BAND4[0] <= freq * mul <= BAND4[1]:
        return 3


def _offset_check(rx, tx):
    if rx < tx:
        return 1
    elif rx > tx:
        return 2
    else:
        return 0


def _append_checksum(data):
    checksum = 0
    for i in data:
        checksum ^= i
    return data + bytes((checksum, ))


def _validate_checksum(data):
    checksum = 0
    for i in data[0:-1]:
        checksum ^= i
    if checksum == data[-1]:
        return data[0:-1]
    else:
        return None


LT9800_SERIAL_READ = b"\x55\x49\x6A\x69\x99\x00\x52"
LT9800_SERIAL_WRITE = b"\x55\x49\x6A\x69\x99\x01\x57"
LT9800_SERIAL_OK = b"\xAA linto"


def _do_status(radio, block):
    status = chirp_common.Status()
    status.msg = "Cloning from/to radio"
    status.cur = block * 8
    status.max = radio.get_memsize()
    radio.status_fn(status)


def _do_download(radio):
    serial = radio.pipe
    serial.write(_append_checksum(LT9800_SERIAL_READ))

    if serial.read(7) != LT9800_SERIAL_OK:
        raise errors.RadioError("Initiation failed")
    mem = b""
    for ind in range(734):
        serial.write(_append_checksum(struct.pack(">cHB", b"R", ind * 8, 8)))
        head = serial.read(4)
        data = serial.read(head[3] + 1)
        if not _validate_checksum(head+data):
            raise errors.RadioError("Checksum mismatch")
        mem += data[0:-1]
        _do_status(radio, ind)
    return memmap.MemoryMapBytes(mem)


def _do_upload(radio):
    serial = radio.pipe
    serial.write(_append_checksum(LT9800_SERIAL_WRITE))
    if serial.read(7) != LT9800_SERIAL_OK:
        raise errors.RadioError("Initiation failed")
    mmap = radio.get_mmap().get_byte_compatible
    for ind in range(734):
        serial.write(_append_checksum(
            struct.pack(">cHB8s", b"W", ind * 8, 8, mmap[ind*8:(ind+1)*8])))
        resp = _validate_checksum(serial.read(5))
        if not resp:
            raise errors.RadioError("Checksum mismatch")
        if struct.unpack(">cHB", resp) != (b"R", ind*8, 8):
            raise errors.RadioError("Unexpected response at 0x%04x" % (ind*8))
        _do_status(radio, ind)


def _mem_relink(radio):  # link next and previous memory data
    filledmem = [
        radio.get_memory(x) for x in range(200)
        if not radio.get_memory(x).empty]
    for i in filledmem:
        mem = radio._memobj.memory[i.number - 1]
        nxt = filledmem[(filledmem.index(i) + 1) % len(filledmem)].number
        prv = filledmem[(filledmem.index(i) - 1) % len(filledmem)].number
        mem.prevmem, mem.nextmem = (prv, nxt)
    radio._memobj.freqmemorycnt = len([x for x in filledmem if x.skip == "S"])
    if not filledmem:
        radio._memobj.options.linealastmemory = 0xff
        radio._memobj.options.lineblastmemory = 0xff
    else:
        radio._memobj.options.linealastmemory = filledmem[0].number
        radio._memobj.options.lineblastmemory = filledmem[0].number


def setstring(setting, dataobj, lenobj,
              padding=0x5c, maxlen=7, charset=CHARSET):
    string = str(setting.value)
    if padding:
        pad = [padding] * (maxlen - len(string))
    dataobj.set_value([charset.index(x) for x in string] + pad)
    lenobj.set_value(len(string))


def setfreq(setting, obj):
    attr = setting.get_name().split("/")[-1]
    band = setting.get_name().split("/")[1]
    value = setting.value.get_value()
    if attr == "rxfreq":
        obj.rxfreq = value * 1000
        if band in ["1", "3"]:
            obj.txfreq = value * 1000
        obj.band_identifier = _freq_to_band(value, 1000000)
    elif attr == "txfreq":
        obj.txfreq = value * 1000
    else:
        obj.set_value(value * 1000)

    if (attr in ["rxfreq", "txfreq"]) and getattr(obj, "rxtxoffset", None):
        obj.rxtxoffset = _offset_check(int(obj.rxfreq), int(obj.txfreq))


def setmul(setting, obj, mul):
    value = setting.value.get_value()
    obj.set_value(value * mul)


@directory.register
class LT9800(chirp_common.CloneModeRadio, chirp_common.ExperimentalRadio):
    VENDOR = "LINTON"
    MODEL = "LT-9800"
    BAUD_RATE = 9600
    NEEDS_COMPAT_SERIAL = False
    _memsize = 0x16F0

    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_rx_dtcs = True
        rf.has_bank = False
        rf.has_tuning_step = False
        rf.has_cross = True
        rf.has_settings = True
        rf.valid_modes = ["FM", "NFM"]
        rf.valid_tmodes = ["", "Tone", "TSQL", "DTCS", "Cross"]
        rf.valid_tuning_steps = STEPS
        rf.valid_bands = VALID_BANDS
        rf.valid_skips = ["", "S"]
        rf.valid_power_levels = POWER_LEVELS
        rf.valid_characters = "".join(CHARSET)
        rf.valid_name_length = 7
        rf.valid_dtcs_codes = DTCS_CODES
        rf.valid_duplexes = ["", "-", "+", "split", "off"]
        rf.memory_bounds = (1, 200)
        rf.can_odd_split = True
        return rf

    def process_mmap(self):
        self._memobj = bitwise.parse(MEM_FORMAT, self._mmap)

    def sync_in(self):
        try:
            self._mmap = _do_download(self)
        except errors.RadioError:
            raise
        except Exception as e:
            raise errors.RadioError("Failed to communicate with radio: %s" % e)
        self.process_mmap()

    def sync_out(self):
        try:
            _do_upload(self)
        except errors.RadioError:
            raise
        except Exception as e:
            raise errors.RadioError("Failed to communicate with radio: %s" % e)

    def get_raw_memory(self, number):
        return repr(self._memobj.memory[number - 1])

    def get_memory(self, number):
        _mem = self._memobj.memory[number - 1]
        _alias = self._memobj.chalias[number - 1]

        mem = chirp_common.Memory()
        mem.number = number

        if _mem.get_raw()[0] == "\xff":
            mem.empty = True
            return mem

        rx_freq = int(_mem.rxfreq) * 1000
        tx_freq = int(_mem.txfreq) * 1000
        rx_band = _freq_to_band(rx_freq)
        tx_band = _freq_to_band(tx_freq)
        mem.freq = rx_freq

        if tx_band in [0, 2]:
            mem.duplex = "off"
            mem.offset = 0
            mem.immutable = ["duplex", "offset"]
        elif int(_mem.rxfreq) == int(_mem.txfreq):
            mem.duplex = ""
            mem.offset = 0
        elif rx_band != tx_band:
            mem.duplex = "split"
            mem.offset = tx_freq
        else:
            mem.duplex = "-" if int(_mem.rxfreq) > int(_mem.txfreq) else "+"
            mem.offset = abs(int(_mem.rxfreq) - int(_mem.txfreq)) * 1000

        mem.name = "".join(CHARSET[x] for x in _alias.data[0:int(_alias.len)])

        dtcs_pol = ["N", "N"]

        if _mem.txtonemode == 0:
            txmode = ""
        elif _mem.txtonemode == 1:
            txmode = "Tone"
            mem.rtone = TONES[int(_mem.txtoneind) - 1]
        else:
            txmode = "DTCS"
            if _mem.txtonemode == 3:
                dtcs_pol[0] = "R"
            mem.dtcs = DTCS_CODES[int(_mem.txtoneind) - 1]

        if _mem.rxtonemode == 0:
            rxmode = ""
        elif _mem.rxtonemode == 1:
            rxmode = "Tone"
            mem.ctone = TONES[int(_mem.rxtoneind) - 1]
        else:
            rxmode = "DTCS"
            if _mem.rxtonemode == 3:
                dtcs_pol[1] = "R"
            mem.rx_dtcs = DTCS_CODES[int(_mem.rxtoneind) - 1]

        if txmode == "Tone" and not rxmode:
            mem.tmode = "Tone"
        elif txmode == rxmode and txmode == "Tone" and mem.rtone == mem.ctone:
            mem.tmode = "TSQL"
        elif txmode == rxmode and txmode == "DTCS" and mem.dtcs == mem.rx_dtcs:
            mem.tmode = "DTCS"
        elif rxmode or txmode:
            mem.tmode = "Cross"
            mem.cross_mode = "%s->%s" % (txmode, rxmode)

        mem.dtcs_polarity = "".join(dtcs_pol)
        if _mem.scan:
            mem.skip = "S"
        mem.power = POWER_LEVELS[_mem.txpower]
        mem.mode = "NFM" if _mem.narrow else "FM"

        mem.extra = RadioSettingGroup("Extra", "extra")

        mem.extra.append(
            RadioSetting("rptmode", "Repeater Mode",
                         RadioSettingValueList(
                             RPTMD_LIST,
                             RPTMD_LIST[_mem.rptmode]))
            )
        mem.extra.append(
            RadioSetting("dtmf", "DTMF",
                         RadioSettingValueBoolean(not _mem.dtmf))
            )
        mem.extra.append(
            RadioSetting("vox", "Vox",
                         RadioSettingValueBoolean(_mem.vox))
            )
        mem.extra.append(
            RadioSetting("tailcut", "Tail Cut",
                         RadioSettingValueBoolean(_mem.tailcut))
            )
        mem.extra.append(
            RadioSetting("bcl", "BCL",
                         RadioSettingValueBoolean(_mem.bcl))
            )
        mem.extra.append(
            RadioSetting("pttid", "PTT ID",
                         RadioSettingValueList(
                             PTTID_LIST,
                             PTTID_LIST[_mem.pttid]))
            )
        return mem

    def set_memory(self, mem):
        _mem = self._memobj.memory[mem.number - 1]
        _alias = self._memobj.chalias[mem.number - 1]

        if mem.empty:
            _mem.set_raw("\xff" * 16)
            _alias.set_raw("\x5c" * 7 + "\x00")
            _mem_relink(self)
            return

        was_empty = False
        if _mem.get_raw()[0] == "\xff":
            was_empty = True
        else:
            prev_rptmode = _mem.rptmode.get_value()
            prev_dtmf = _mem.dtmf.get_value()
            prev_vox = _mem.vox.get_value()
            prev_tailcut = _mem.tailcut.get_value()
            prev_bcl = _mem.bcl.get_value()
            prev_pttid = _mem.pttid.get_value()

        _mem.set_raw("\x00" * 16)
        _mem.unused4 = 1
        _mem.band_identifier = _freq_to_band(mem.freq)

        _mem.rxfreq = mem.freq / 1000

        if mem.duplex == "split":
            _mem.txfreq = mem.offset / 1000
        elif mem.duplex == "+":
            _mem.txfreq = (mem.freq + mem.offset) / 1000
        elif mem.duplex == "-":
            _mem.txfreq = (mem.freq - mem.offset) / 1000
        else:
            _mem.txfreq = mem.freq / 1000

        _mem.rxtxoffset = _offset_check(int(_mem.rxfreq), int(_mem.txfreq))

        _alias.len = len(mem.name)

        for i in range(self.get_features().valid_name_length):
            try:
                _alias.data[i] = CHARSET.index(mem.name.ljust(7)[i])
            except IndexError:
                _alias.data[i] = 0x5C

        rxmode = txmode = ""
        if mem.tmode == "Tone":
            _mem.txtonemode = 1
            _mem.txtoneind = TONES.index(mem.rtone) + 1
            _mem.rxtonemode = 0
            _mem.rxtoneind = 0
        elif mem.tmode == "TSQL":
            _mem.txtonemode = 1
            _mem.txtoneind = TONES.index(mem.ctone) + 1
            _mem.rxtonemode = 1
            _mem.rxtoneind = TONES.index(mem.ctone) + 1
        elif mem.tmode == "DTCS":
            rxmode = txmode = "DTCS"
            _mem.txtonemode = 2
            _mem.txtoneind = DTCS_CODES.index(mem.dtcs) + 1
            _mem.rxtonemode = 2
            _mem.rxtoneind = DTCS_CODES.index(mem.dtcs) + 1
        elif mem.tmode == "Cross":
            txmode, rxmode = mem.cross_mode.split("->", 1)
            if txmode == "Tone":
                _mem.txtonemode = 1
                _mem.txtoneind = TONES.index(mem.rtone) + 1
            elif txmode == "DTCS":
                _mem.txtonemode = 2
                _mem.txtoneind = DTCS_CODES.index(mem.dtcs) + 1
            else:
                _mem.txtonemode = 0
                _mem.txtoneind = 0
            if rxmode == "Tone":
                _mem.rxtonemode = 1
                _mem.rxtoneind = TONES.index(mem.ctone) + 1
            elif rxmode == "DTCS":
                _mem.rxtonemode = 2
                _mem.rxtoneind = DTCS_CODES.index(mem.rx_dtcs) + 1
            else:
                _mem.rxtonemode = 0
                _mem.rxtoneind = 0
        else:
            _mem.txtonemode = 0
            _mem.txtoneind = 0
            _mem.rxtonemode = 0
            _mem.rxtoneind = 0

        if txmode == "DTCS" and mem.dtcs_polarity[0] == "R":
            _mem.txtonemode = 3
        if rxmode == "DTCS" and mem.dtcs_polarity[1] == "R":
            _mem.rxtonemode = 3

        _mem.scan = mem.skip == "S"
        _mem.narrow = mem.mode == "NFM"
        _mem.txpower = POWER_LEVELS.index(mem.power) if mem.power else 0

        if not was_empty:
            _mem.rptmode.set_value(prev_rptmode)
            _mem.dtmf.set_value(prev_dtmf)
            _mem.vox.set_value(prev_vox)
            _mem.tailcut.set_value(prev_tailcut)
            _mem.bcl.set_value(prev_bcl)
            _mem.pttid.set_value(prev_pttid)

        for setting in mem.extra:
            val = setting.value
            if setting.get_name() in ["dtmf"]:
                val = not val
            setattr(_mem, setting.get_name(), val)

        _mem_relink(self)

    def get_settings(self):
        _settings = self._memobj.options
        _vfosettings = self._memobj.vfo
        workmode = RadioSettingGroup("workmode", "Work Mode Settings")
        vfoa = RadioSettingGroup("vfoa", "Line A VFO Settings")
        vfob = RadioSettingGroup("vfob", "Line B VFO Settings")
        optional = RadioSettingGroup("optional", "Optional Settings")
        keyassign = RadioSettingGroup("keyassign", "Key Assignment")
        dtmf = RadioSettingGroup("dtmf", "DTMF Settings")
        freqrange = RadioSettingGroup("freqrange", "Frequency Range")

        group = RadioSettings(workmode, optional, dtmf, keyassign, freqrange)

        for line, vfo in zip(AB_LIST, [vfoa, vfob]):

            workmode.append(RadioSetting(
                "workmode.%s/mode" % line, "Line%s VFO/MR Mode" % line,
                RadioSettingValueList(
                    WORKMODE_LIST,
                    WORKMODE_LIST[
                        _settings.workmode[AB_LIST.index(line)].mode
                        ]
                    ))
                )
            workmode.append(RadioSetting(
                "workmode.%s/dispmode" % line, "Line%s Display Mode" % line,
                RadioSettingValueList(
                    MODE_LIST,
                    MODE_LIST[
                        _settings.workmode[AB_LIST.index(line)].dispmode
                        ]
                    ))
                )
            workmode.append(RadioSetting(
                "workmode.%s/band" % line, "Line%s VFO Band" % line,
                RadioSettingValueList(
                    BAND_LIST,
                    BAND_LIST[_settings.workmode[AB_LIST.index(line)].band]
                    ))
                )

            linevfo = _vfosettings[AB_LIST.index(line)]
            workmode.append(vfo)
            for band in range(1, 5):
                bandvfo = getattr(linevfo, "band%d" % band)
                b = (line, band)
                minf, maxf = VALID_BANDS[band - 1]
                minf /= 1000000
                maxf /= 1000000
                rs = RadioSetting(
                    "vfo.%s/%d/rxfreq" % b,
                    "Line%s Band %d RX Frequency" % b,
                    RadioSettingValueFloat(
                        minf, maxf, int(bandvfo.rxfreq)/1000.0, 0.005, 3)
                    )
                rs.set_apply_callback(setfreq, bandvfo)
                vfo.append(rs)
                if band in [2, 4]:
                    rs = RadioSetting(
                        "vfo.%s/%d/txfreq" % b,
                        "Line%s Band %d TX Frequency" % b,
                        RadioSettingValueFloat(
                            minf, maxf, int(bandvfo.txfreq)/1000.0, 0.005, 3))
                    rs.set_apply_callback(setfreq, bandvfo)
                    vfo.append(rs)

                    vfo.append(RadioSetting(
                        "vfo.%s/%d/txpower" % b,
                        "Line%s Band %d TX power" % b,
                        RadioSettingValueList(
                            POWER_LIST, POWER_LIST[bandvfo.txpower])))

                    vfo.append(RadioSetting(
                        "vfo.%s/%d/dtmf" % b,
                        "Line%s Band %d DTMF" % b,
                        RadioSettingValueBoolean(not bandvfo.dtmf)))

                    vfo.append(RadioSetting(
                        "vfo.%s/%d/vox" % b,
                        "Line%s Band %d Vox" % b,
                        RadioSettingValueBoolean(bandvfo.vox)))

                    vfo.append(RadioSetting(
                        "vfo.%s/%d/tailcut" % b,
                        "Line%s Band %d Tail Cut" % b,
                        RadioSettingValueBoolean(bandvfo.tailcut)))

                    vfo.append(RadioSetting(
                        "vfo.%s/%d/bcl" % b,
                        "Line%s Band %d BCL" % b,
                        RadioSettingValueBoolean(bandvfo.bcl)))

                    vfo.append(RadioSetting(
                        "vfo.%s/%d/widenarr" % b,
                        "Line%s Band %d Bandwidth" % b,
                        RadioSettingValueList(
                            BANDWIDTH_LIST,
                            BANDWIDTH_LIST[bandvfo.widenarr])))

        dtmf.append(RadioSetting(
            "dtmfspeed", "DTMF Speed",
            RadioSettingValueMap(DTMFSPEED_MAP, _settings.dtmfspeed)))

        rs = RadioSetting(
            "fddt", "First Digit Delay Time",
            RadioSettingValueInteger(0, 1000, _settings.fddt*10, 10))
        rs.set_apply_callback(setmul, _settings.fddt, 0.1)
        dtmf.append(rs)

        rs = RadioSetting(
            "fdt", "First Digit Time",
            RadioSettingValueInteger(100, 1000, _settings.fdt*10, 100))
        rs.set_apply_callback(setmul, _settings.fdt, 0.1)
        dtmf.append(rs)

        rs = RadioSetting(
            "ahdigittime", "* and # Digit Time",
            RadioSettingValueInteger(100, 1000, _settings.ahdigittime*10, 100))
        rs.set_apply_callback(setmul, _settings.ahdigittime, 0.1)
        dtmf.append(rs)

        dtmf.append(RadioSetting(
            "sidetone", "Side Tone",
            RadioSettingValueBoolean(_settings.sidetone)))

        ani = "".join(
            DTMFCHARSET[x] for x in _settings.anicode[0:_settings.anicodelen])
        rs = RadioSetting(
            "anicode", "ANI Code",
            RadioSettingValueString(0, 16, ani, False, DTMFCHARSET))
        rs.set_apply_callback(
            setstring, _settings.anicode, _settings.anicodelen, 0xff, 16)
        dtmf.append(rs)

        dtmf.append(RadioSetting(
            "groupcode", "Group Code",
            RadioSettingValueMap(GROUPCODE_MAP, _settings.groupcode)))

        dtmf.append(RadioSetting(
            "autoresponse", "Auto Response",
            RadioSettingValueBoolean(_settings.autoresponse)))

        dtmf.append(RadioSetting(
            "stunset", "Stun Activation",
            RadioSettingValueBoolean(not _settings.stunset)))

        stuncode = "".join(
            DTMFCHARSET[x]
            for x in _settings.stuncode[0:_settings.stuncodelen])
        rs = RadioSetting(
            "stuncode", "Stun Code",
            RadioSettingValueString(0, 15, stuncode, False, DTMFCHARSET))
        rs.set_apply_callback(
            setstring, _settings.stuncode,
            _settings.stuncodelen, 0xff, 15, DTMFCHARSET)
        dtmf.append(rs)

        dtmf.append(RadioSetting(
            "stuntype", "Stun Type",
            RadioSettingValueList(
                STUNTYPE_LIST, STUNTYPE_LIST[_settings.stuntype])))

        dtmfcalllist = RadioSettingGroup("dtmfcalllist", "DTMF Call List")
        for i in range(16):
            call = "".join(
                DTMFCHARSET[x] for x in self._memobj.dtmfcalllist[i]
                .call[0:self._memobj.dtmfcalllistlen[i]])
            _alias = self._memobj.dtmfalias[i]

            alias = "".join(CHARSET[x] for x in _alias.data[0:_alias.len])
            rs = RadioSetting(
                "calllist%d" % (i+1), "Call List #%d" % (i+1),
                RadioSettingValueString(0, 16, call, False, DTMFCHARSET))
            rs.set_apply_callback(
                setstring, self._memobj.dtmfcalllist[i].call,
                self._memobj.dtmfcalllistlen[i], 0xff, 16, DTMFCHARSET)
            dtmfcalllist.append(rs)

            rs = RadioSetting(
                "calllistalias%d" % (i+1), "Call List Alias #%d" % (i+1),
                RadioSettingValueString(0, 7, alias, False, CHARSET))
            rs.set_apply_callback(setstring, _alias.data, _alias.len)
            dtmfcalllist.append(rs)

        dtmf.append(dtmfcalllist)

        rs = RadioSetting(
            "longpresstime", "Long Press Time",
            RadioSettingValueFloat(
                0.5, 2.5, _settings.longpresstime/100.0, 0.1, 1))
        rs.set_apply_callback(setmul, _settings.longpresstime, 100)
        keyassign.append(rs)

        for i in range(1, 3):
            keyassign.append(RadioSetting(
                "sk%dlong" % i, "SK%d Long" % i,
                RadioSettingValueList(
                    SKL_LIST, SKL_LIST[getattr(_settings, "sk%dlong" % i)])))
            keyassign.append(RadioSetting(
                "sk%dshort" % i, "SK%d Short" % i,
                RadioSettingValueList(
                    SKS_LIST, SKS_LIST[getattr(_settings, "sk%dshort" % i)])))

        optional.append(RadioSetting(
            "openmessagetype", "Open Message",
            RadioSettingValueList(
                OPENMESSAGE_LIST,
                OPENMESSAGE_LIST[_settings.openmessagetype])))

        _openmessage = _settings.openmessage
        openmessage = "".join(
            CHARSET[x] for x in _openmessage.data[0:_openmessage.len])
        rs = RadioSetting(
            "openmessage", "Message",
            RadioSettingValueString(0, 7, openmessage, False, CHARSET))
        rs.set_apply_callback(setstring, _openmessage.data, _openmessage.len)
        optional.append(rs)

        optional.append(RadioSetting(
            "passwordset", "Password Enable",
            RadioSettingValueBoolean(_settings.passwordset)))

        _password = _settings.password
        password = "".join(
            DTMFCHARSET[x] for x in _password.data[0:_password.len])
        rs = RadioSetting(
            "password", "Password",
            RadioSettingValueString(0, 7, password, False, DTMFCHARSET[0:10]))
        rs.set_apply_callback(setstring, _password.data, _password.len)
        optional.append(rs)

        optional.append(RadioSetting(
            "keylocked", "Key Locked",
            RadioSettingValueBoolean(_settings.keylocked)))

        optional.append(RadioSetting(
            "lockobj", "Lock Obj",
            RadioSettingValueList(
                KEYLOCK_LIST, KEYLOCK_LIST[_settings.lockobj])))

        optional.append(RadioSetting(
            "mainline", "Main Line",
            RadioSettingValueList(
                MAINLINE_LIST, MAINLINE_LIST[_settings.mainline])))

        optional.append(RadioSetting(
            "prioritychannel", "Priority Channel",
            RadioSettingValueList(
                PRIORITY_LIST, PRIORITY_LIST[_settings.prioritychannel])))

        optional.append(RadioSetting(
            "squelchlevel", "Squelch Level",
            RadioSettingValueInteger(0, 9, _settings.squelchlevel)))

        optional.append(RadioSetting(
            "step", "Frequency Step",
            RadioSettingValueList(STEPS_LIST, STEPS_LIST[_settings.step])))

        optional.append(RadioSetting(
            "tailphase", "Tail Phase",
            RadioSettingValueList(
                TAILPHASE_LIST, TAILPHASE_LIST[_settings.tailphase])))

        optional.append(RadioSetting(
            "scanmode", "Scan Mode",
            RadioSettingValueList(
                RESUME_LIST, RESUME_LIST[_settings.scanmode])))

        optional.append(RadioSetting(
            "timeouttimer", "Timeout Timer",
            RadioSettingValueList(
                TIMEOUT_LIST, TIMEOUT_LIST[_settings.timeouttimer])))

        optional.append(RadioSetting(
            "autopoweroff", "Auto Power Off",
            RadioSettingValueList(
                APO_LIST, APO_LIST[_settings.autopoweroff])))

        optional.append(RadioSetting(
            "battsaver", "Power Save",
            RadioSettingValueBoolean(_settings.battsaver)))

        optional.append(RadioSetting(
            "rxmutemode", "Rx Mute Mode",
            RadioSettingValueList(
                RXMUTE_LIST, RXMUTE_LIST[_settings.rxmutemode])))

        optional.append(RadioSetting(
            "fmvol", "FM Volume",
            RadioSettingValueInteger(1, 10, self._memobj.fmvol)))

        optional.append(RadioSetting(
            "beeptone", "Beep Tone",
            RadioSettingValueBoolean(_settings.beeptone)))

        optional.append(RadioSetting(
            "opentone", "Open Tone",
            RadioSettingValueBoolean(_settings.opentone)))

        optional.append(RadioSetting(
            "dualwatch", "Dual Watch",
            RadioSettingValueBoolean(_settings.dualwatch)))

        optional.append(RadioSetting(
            "rogertone", "Roger Tone",
            RadioSettingValueBoolean(_settings.rogertone)))

        optional.append(RadioSetting(
            "ani", "ANI",
            RadioSettingValueBoolean(_settings.ani)))

        optional.append(RadioSetting(
            "lowbatalert", "Low Bat Alert",
            RadioSettingValueBoolean(_settings.lowbatalert)))

        optional.append(RadioSetting(
            "dwreturn", "DW Return",
            RadioSettingValueBoolean(_settings.dwreturn)))

        optional.append(RadioSetting(
            "txstop", "Tx Stop",
            RadioSettingValueBoolean(_settings.txstop)))

        optional.append(RadioSetting(
            "fmstrong", "FM Strong",
            RadioSettingValueBoolean(_settings.fmstrong)))

        optional.append(RadioSetting(
            "expandfreq", "Expanded Freq",
            RadioSettingValueBoolean(_settings.expandfreq)))

        optional.append(RadioSetting(
            "pttmainline", "PTT Main Line",
            RadioSettingValueBoolean(_settings.pttmainline)))

        optional.append(RadioSetting(
            "lampmode", "Lamp Mode",
            RadioSettingValueList(
                LAMPMODE_LIST, LAMPMODE_LIST[_settings.lampmode])))

        optional.append(RadioSetting(
            "lampcolor", "Lamp Color",
            RadioSettingValueList(
                LAMPCOLOR_LIST, LAMPCOLOR_LIST[_settings.lampcolor])))

        optional.append(RadioSetting(
            "lamptime", "Lamp Time",
            RadioSettingValueInteger(1, 10, _settings.lamptime)))

        optional.append(RadioSetting(
            "voxgainlevel", "Vox Gain Level",
            RadioSettingValueInteger(1, 4, _settings.voxgainlevel)))

        optional.append(RadioSetting(
            "voxdelaytime", "Vox Delay Time",
            RadioSettingValueInteger(1, 4, _settings.voxdelaytime)))

        optional.append(RadioSetting(
            "voxinhibitonrecv", "Vox Inhibit On Receive",
            RadioSettingValueBoolean(_settings.voxinhibitonrecv)))

        pttid_bot = "".join(
            DTMFCHARSET[x] for x in
            _settings.pttid_bot[0:_settings.pttid_bot_len])
        rs = RadioSetting(
            "pttid_bot", "PTT-ID BOT",
            RadioSettingValueString(0, 16, pttid_bot, False, DTMFCHARSET))
        rs.set_apply_callback(
            setstring, _settings.pttid_bot, _settings.pttid_bot_len,
            0xff, 16, DTMFCHARSET)
        optional.append(rs)

        _password = _settings.password
        pttid_eot = "".join(
            DTMFCHARSET[x] for x in
            _settings.pttid_eot[0:_settings.pttid_eot_len])
        rs = RadioSetting(
            "pttid_eot", "PTT-ID EOT",
            RadioSettingValueString(0, 16, pttid_eot, False, DTMFCHARSET))
        rs.set_apply_callback(
            setstring, _settings.pttid_eot, _settings.pttid_eot_len,
            0xff, 16, DTMFCHARSET)
        optional.append(rs)

        optional.append(RadioSetting(
            "decodesuccesstone", "Decode Success Tone",
            RadioSettingValueBoolean(_settings.decodesuccesstone)))

        optional.append(RadioSetting(
            "resettime", "Reset Time",
            RadioSettingValueInteger(3, 60, _settings.resettime)))

        optional.append(RadioSetting(
            "resettone", "Reset Tone Enable",
            RadioSettingValueBoolean(_settings.resettone)))

        for line in AB_LIST:
            _freqrange = self._memobj.freqrange[AB_LIST.index(line)]
            for band in range(1, 5):
                bandrange = getattr(_freqrange, "band%d" % band)
                b = (line, band)
                minf, maxf = VALID_BANDS[band - 1]
                minf /= 1000000.0
                maxf /= 1000000.0

                rs = RadioSetting(
                    "freqrange.%s/%d/rx/min" % b,
                    "Line%s Band %d RX Frequency Min" % b,
                    RadioSettingValueFloat(
                        minf, maxf, int(bandrange.rxfreqmin)/1000.0, 0.005, 3))
                rs.set_apply_callback(setfreq, bandrange.rxfreqmin)
                freqrange.append(rs)

                rs = RadioSetting(
                    "freqrange.%s/%d/rx/max" % b,
                    "Line%s Band %d RX Frequency Max" % b,
                    RadioSettingValueFloat(
                        minf, maxf, int(bandrange.rxfreqmax)/1000.0,
                        0.005, 3))
                rs.set_apply_callback(setfreq, bandrange.rxfreqmax)
                freqrange.append(rs)

                if band in [2, 4]:
                    rs = RadioSetting(
                        "freqrange.%s/%d/tx/min" % b,
                        "Line%s Band %d TX Frequency Min" % b,
                        RadioSettingValueFloat(
                            minf, maxf, int(bandrange.txfreqmin)/1000.0,
                            0.005, 3))
                    rs.set_apply_callback(setfreq, bandrange.txfreqmin)
                    freqrange.append(rs)

                    rs = RadioSetting(
                        "freqrange.%s/%d/tx/max" % b,
                        "Line%s Band %d TX Frequency Max" % b,
                        RadioSettingValueFloat(
                            minf, maxf, int(bandrange.txfreqmax)/1000.0,
                            0.005, 3))
                    rs.set_apply_callback(setfreq, bandrange.txfreqmax)
                    freqrange.append(rs)

        return group

    def set_settings(self, settings):
        _mem = self._memobj

        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue
            else:
                name = element.get_name()
                if "." in name:
                    group, string = name.split(".")
                    if group == "workmode":
                        line, attr = string.split("/")
                        obj = _mem.options.workmode[AB_LIST.index(line)]
                    elif group == "vfo":
                        line, band, attr = string.split("/")
                        obj = getattr(
                            _mem.vfo[AB_LIST.index(line)],
                            "band%s" % band)
                    elif group == "freqrange":
                        line, band, mode, limit = string.split("/")
                        obj = getattr(
                            _mem.freqrange[AB_LIST.index(line)],
                            "band%s" % band)
                        attr = "%sfreq%s" % (mode, limit)
                    else:
                        print(group, string)
                else:
                    obj = _mem.options
                    attr = element.get_name()
                    if attr == "fmvol":
                        obj = _mem

                if element.has_apply_callback():
                    element.run_apply_callback()
                elif element.value.get_mutable():
                    if attr in INV_LIST:
                        setattr(obj, attr, not element.value)
                    else:
                        setattr(obj, attr, element.value)
