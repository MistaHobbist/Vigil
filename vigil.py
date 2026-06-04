#!/usr/bin/env python3
"""Vigil - zero-dependency Linux mesh monitor. Requires Python 3.4+."""

from __future__ import print_function, division

import collections
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import socketserver
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer  # type: ignore
    import SocketServer as socketserver  # type: ignore

# ---------------------------------------------------------------------------
# Configuration — edit these directly
# ---------------------------------------------------------------------------
HTTP_PORT     = 7700
UDP_PORT      = 7701
TICK_INTERVAL = 1.0
HISTORY_DEPTH = 1200
PEER_TIMEOUT  = 15
PEER_DROP     = 60
TOP_PROCS     = 10
GPU_ENABLED   = True
STATIC_PEERS  = []      # e.g. ["192.168.1.11", "192.168.1.12"]

# ---------------------------------------------------------------------------
# Ring buffer
# ---------------------------------------------------------------------------
class RingBuffer(object):
    def __init__(self, maxlen):
        self._buf = collections.deque(maxlen=maxlen)

    def append(self, item):
        self._buf.append(item)

    def get(self):
        return list(self._buf)

    def __len__(self):
        return len(self._buf)


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_lock        = threading.Lock()
_history     = {}   # ip -> RingBuffer of sample dicts
_peers       = {}   # ip -> {host, port, last_seen}
_latest_self = {}   # most recent snapshot of this node
_my_ip       = '127.0.0.1'
_my_host     = socket.gethostname()


# ---------------------------------------------------------------------------
# File helpers (module-level so tests can patch them)
# ---------------------------------------------------------------------------
def _read(path):
    try:
        with open(path, 'r') as fh:
            return fh.read()
    except (IOError, OSError):
        return ''

def _read_lines(path):
    return _read(path).splitlines()

def _listdir(path):
    try:
        return os.listdir(path)
    except (IOError, OSError):
        return []

def _statvfs(path):
    return os.statvfs(path)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
class Collector(object):
    """Holds delta state between ticks; call collect() each tick."""

    def __init__(self):
        self._prev_cpu        = None   # {name: (total_ticks, idle_ticks)}
        self._prev_disk       = None   # {dev: (read_sectors, write_sectors)}
        self._prev_net        = None   # {iface: (rx_bytes, tx_bytes)}
        self._prev_procs      = None   # {pid_str: total_ticks}
        self._prev_self_ticks = None   # total ticks for vigil's own pid
        self._prev_rapl       = None   # {zone_id: (energy_uj, max_energy_uj)}
        self._rapl_available  = None   # None=untried, True=working, False=disabled
        self._gpu_available   = None   # None=untried, True=working, False=disabled
        self._prev_time       = None
        self._clk_tck         = _get_clk_tck()

    # --- CPU ---

    def _parse_stat(self):
        result = {}
        for line in _read_lines('/proc/stat'):
            if not line.startswith('cpu'):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                vals = [int(x) for x in parts[1:]]
            except ValueError:
                continue
            idle  = vals[3] + (vals[4] if len(vals) > 4 else 0)
            total = sum(vals)
            result[parts[0]] = (total, idle)
        return result

    def _collect_cpu(self):
        cur = self._parse_stat()
        cores = sorted(k for k in cur if k != 'cpu')

        if self._prev_cpu is None:
            self._prev_cpu = cur
            return {
                'count':     len(cores),
                'usage_pct': [0.0] * len(cores),
                'total_pct': 0.0,
                'freq_mhz':  _cpu_freq(),
            }

        def _delta_pct(name):
            if name not in self._prev_cpu or name not in cur:
                return 0.0
            dtotal = cur[name][0] - self._prev_cpu[name][0]
            didle  = cur[name][1] - self._prev_cpu[name][1]
            if dtotal <= 0:
                return 0.0
            return round(max(0.0, min(100.0, (1.0 - didle / dtotal) * 100.0)), 1)

        per_core   = [_delta_pct(c) for c in cores]
        total_pct  = _delta_pct('cpu')
        self._prev_cpu = cur
        return {
            'count':     len(per_core),
            'usage_pct': per_core,
            'total_pct': total_pct,
            'freq_mhz':  _cpu_freq(),
        }

    # --- Memory ---

    @staticmethod
    def _collect_mem():
        info = {}
        for line in _read_lines('/proc/meminfo'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    info[parts[0].rstrip(':')] = int(parts[1])
                except ValueError:
                    pass

        def to_mb(kb):
            return round(kb / 1024.0, 1)

        def pct(used_kb, total_kb):
            return round(used_kb / total_kb * 100.0, 1) if total_kb else 0.0

        total = info.get('MemTotal', 0)
        avail = info.get('MemAvailable', 0)
        used  = total - avail
        stot  = info.get('SwapTotal', 0)
        sfree = info.get('SwapFree', 0)
        sused = stot - sfree

        return {
            'mem': {
                'total_mb':     to_mb(total),
                'used_mb':      to_mb(used),
                'available_mb': to_mb(avail),
                'used_pct':     pct(used, total),
            },
            'swap': {
                'total_mb': to_mb(stot),
                'used_mb':  to_mb(sused),
                'used_pct': pct(sused, stot),
            },
        }

    # --- Disks ---

    _SKIP_FS = frozenset({
        'tmpfs', 'devtmpfs', 'sysfs', 'proc', 'cgroup', 'cgroup2',
        'pstore', 'securityfs', 'debugfs', 'hugetlbfs', 'mqueue',
        'fusectl', 'binfmt_misc', 'configfs', 'tracefs', 'ramfs',
        'overlay', 'aufs', 'nsfs', 'rpc_pipefs',
    })

    def _collect_disks(self, elapsed):
        # Parse /proc/diskstats
        disk_io = {}
        for line in _read_lines('/proc/diskstats'):
            parts = line.split()
            if len(parts) < 14:
                continue
            dev = parts[2]
            try:
                disk_io[dev] = (int(parts[5]), int(parts[9]))
            except (ValueError, IndexError):
                pass

        disks = []
        seen  = set()
        for line in _read_lines('/proc/mounts'):
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mount, fstype = parts[0], parts[1], parts[2]
            if fstype in self._SKIP_FS:
                continue
            if not device.startswith('/'):
                continue
            if mount in seen:
                continue
            seen.add(mount)

            try:
                st = _statvfs(mount)
            except (OSError, IOError):
                continue

            total_gb = round(st.f_frsize * st.f_blocks / 1024.0**3, 1)
            avail_gb = round(st.f_frsize * st.f_bavail / 1024.0**3, 1)
            used_gb  = round(total_gb - avail_gb, 1)
            used_pct = round(used_gb / total_gb * 100.0, 1) if total_gb else 0.0

            dev_name  = os.path.basename(device)
            read_mbs  = 0.0
            write_mbs = 0.0
            if self._prev_disk is not None and dev_name in disk_io and elapsed > 0:
                prev = self._prev_disk.get(dev_name)
                cur  = disk_io[dev_name]
                if prev is not None:
                    d_r = max(0, cur[0] - prev[0])
                    d_w = max(0, cur[1] - prev[1])
                    read_mbs  = round(d_r * 512.0 / 1024.0**2 / elapsed, 2)
                    write_mbs = round(d_w * 512.0 / 1024.0**2 / elapsed, 2)

            disks.append({
                'device':    dev_name,
                'mount':     mount,
                'total_gb':  total_gb,
                'used_gb':   used_gb,
                'used_pct':  used_pct,
                'read_mb_s': read_mbs,
                'write_mb_s': write_mbs,
            })

        self._prev_disk = disk_io
        return disks

    # --- Network ---

    def _collect_net(self, elapsed):
        cur = {}
        for line in _read_lines('/proc/net/dev')[2:]:
            if ':' not in line:
                continue
            name, rest = line.split(':', 1)
            name = name.strip()
            if name == 'lo':
                continue
            parts = rest.split()
            if len(parts) < 9:
                continue
            try:
                cur[name] = (int(parts[0]), int(parts[8]))
            except ValueError:
                pass

        result = []
        for name, (rx_b, tx_b) in cur.items():
            rx_mbs = 0.0
            tx_mbs = 0.0
            if self._prev_net is not None and name in self._prev_net and elapsed > 0:
                prx, ptx = self._prev_net[name]
                rx_mbs = round(max(0, rx_b - prx) / 1024.0**2 / elapsed, 3)
                tx_mbs = round(max(0, tx_b - ptx) / 1024.0**2 / elapsed, 3)
            result.append({
                'iface':       name,
                'rx_mb_s':     rx_mbs,
                'tx_mb_s':     tx_mbs,
                'rx_total_gb': round(rx_b / 1024.0**3, 3),
                'tx_total_gb': round(tx_b / 1024.0**3, 3),
            })

        self._prev_net = cur
        return result

    # --- GPU ---

    def _collect_gpu(self):
        if not GPU_ENABLED or self._gpu_available is False:
            return []
        try:
            fields = ('index,name,utilization.gpu,memory.used,memory.total,'
                      'temperature.gpu,power.draw,power.limit,fan.speed')
            raw = subprocess.check_output(
                ['nvidia-smi', '--query-gpu=' + fields,
                 '--format=csv,noheader,nounits'],
                stderr=subprocess.DEVNULL,
                timeout=3,
            ).decode('utf-8', errors='replace')
        except Exception:
            if self._gpu_available is None:
                self._gpu_available = False
            return []

        def _i(s):
            try:
                return int(float(s))
            except (ValueError, TypeError):
                return 0

        def _f(s):
            try:
                return float(s)
            except (ValueError, TypeError):
                return 0.0

        gpus = []
        for line in raw.strip().splitlines():
            p = [x.strip() for x in line.split(',')]
            if len(p) < 9:
                continue
            mu, mt = _i(p[3]), _i(p[4])
            gpus.append({
                'index':         _i(p[0]),
                'name':          p[1],
                'util_pct':      _i(p[2]),
                'mem_used_mb':   mu,
                'mem_total_mb':  mt,
                'mem_used_pct':  round(mu / mt * 100.0, 1) if mt else 0.0,
                'temp_c':        _i(p[5]),
                'power_w':       _f(p[6]),
                'power_limit_w': _f(p[7]),
                'fan_pct':       _i(p[8]),
            })
        if self._gpu_available is None:
            self._gpu_available = len(gpus) > 0
        return gpus

    # --- Top processes ---

    def _collect_top(self, elapsed):
        cur_ticks = {}
        procs = []

        for pid in _listdir('/proc'):
            if not pid.isdigit():
                continue
            stat_raw = _read('/proc/{}/stat'.format(pid))
            if not stat_raw:
                continue

            # comm is between first '(' and last ')'
            j = stat_raw.find('(')
            k = stat_raw.rfind(')')
            if j == -1 or k == -1:
                continue
            name = stat_raw[j + 1:k]
            rest = stat_raw[k + 2:].split()
            # rest[11]=utime, rest[12]=stime (0-indexed after state field)
            if len(rest) < 13:
                continue
            try:
                utime = int(rest[11])
                stime = int(rest[12])
            except ValueError:
                continue
            total_ticks = utime + stime
            cur_ticks[pid] = total_ticks

            mem_mb = 0.0
            for sl in _read_lines('/proc/{}/status'.format(pid)):
                if sl.startswith('VmRSS:'):
                    sp = sl.split()
                    if len(sp) >= 2:
                        try:
                            mem_mb = round(int(sp[1]) / 1024.0, 1)
                        except ValueError:
                            pass
                    break

            cpu_pct = 0.0
            if (self._prev_procs is not None and pid in self._prev_procs
                    and elapsed > 0 and self._clk_tck > 0):
                d = total_ticks - self._prev_procs[pid]
                cpu_pct = round(max(0.0, d / self._clk_tck / elapsed * 100.0), 1)

            procs.append({'pid': int(pid), 'name': name,
                          'cpu_pct': cpu_pct, 'mem_mb': mem_mb})

        self._prev_procs = cur_ticks
        procs.sort(key=lambda p: p['cpu_pct'], reverse=True)
        return procs[:TOP_PROCS]

    # --- System ---

    @staticmethod
    def _collect_system():
        uptime_s = 0.0
        parts = _read('/proc/uptime').split()
        if parts:
            try:
                uptime_s = float(parts[0])
            except ValueError:
                pass

        load_avg = [0.0, 0.0, 0.0]
        parts = _read('/proc/loadavg').split()
        if len(parts) >= 3:
            try:
                load_avg = [float(parts[i]) for i in range(3)]
            except ValueError:
                pass

        return int(uptime_s), load_avg

    # --- RAPL CPU power ---

    def _collect_rapl(self, elapsed):
        if self._rapl_available is False:
            return []

        base = '/sys/class/powercap'
        cur = {}     # zone_id -> (energy_uj, max_energy_uj)
        result = []

        for zone_id in sorted(_listdir(base)):
            if not zone_id.startswith('intel-rapl:'):
                continue
            zpath = os.path.join(base, zone_id)
            name = _read(os.path.join(zpath, 'name')).strip() or zone_id

            raw = _read(os.path.join(zpath, 'energy_uj')).strip()
            if not raw:
                continue
            try:
                energy = int(raw)
            except ValueError:
                continue

            try:
                max_e = int(_read(os.path.join(zpath, 'max_energy_range_uj')).strip() or '0')
            except ValueError:
                max_e = 0

            cur[zone_id] = (energy, max_e)

            watts = 0.0
            if self._prev_rapl is not None and zone_id in self._prev_rapl and elapsed > 0:
                prev_e = self._prev_rapl[zone_id][0]
                delta  = energy - prev_e
                if delta < 0 and max_e > 0:   # counter wrapped
                    delta += max_e
                if delta >= 0:
                    watts = round(delta / 1000000.0 / elapsed, 2)

            result.append({'name': name, 'zone': zone_id, 'watts': watts})

        if self._rapl_available is None:
            self._rapl_available = len(result) > 0

        self._prev_rapl = cur
        return result

    # --- Vigil self-usage ---

    def _collect_self(self, elapsed):
        pid = str(os.getpid())
        cpu_pct = 0.0
        rss_mb  = 0.0

        stat_raw = _read('/proc/{}/stat'.format(pid))
        if stat_raw:
            k = stat_raw.rfind(')')
            if k != -1:
                rest = stat_raw[k + 2:].split()
                if len(rest) >= 13:
                    try:
                        ticks = int(rest[11]) + int(rest[12])
                        if self._prev_self_ticks is not None and elapsed > 0 and self._clk_tck > 0:
                            cpu_pct = round(max(0.0, (ticks - self._prev_self_ticks) / self._clk_tck / elapsed * 100.0), 2)
                        self._prev_self_ticks = ticks
                    except ValueError:
                        pass

        for line in _read_lines('/proc/{}/status'.format(pid)):
            if line.startswith('VmRSS:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        rss_mb = round(int(parts[1]) / 1024.0, 1)
                    except ValueError:
                        pass
                break

        return {'pid': int(pid), 'cpu_pct': cpu_pct, 'rss_mb': rss_mb}

    # --- Main collect entry point ---

    def collect(self):
        now     = time.time()
        elapsed = (now - self._prev_time) if self._prev_time is not None else TICK_INTERVAL
        self._prev_time = now

        cpu_data        = self._collect_cpu()
        mem_data        = self._collect_mem()
        disks           = self._collect_disks(elapsed)
        net             = self._collect_net(elapsed)
        gpu             = self._collect_gpu()
        top             = self._collect_top(elapsed)
        uptime_s, load  = self._collect_system()
        vigil_self      = self._collect_self(elapsed)
        rapl            = self._collect_rapl(elapsed)

        return {
            'host':       _my_host,
            'ts':         int(now),
            'cpu':        cpu_data,
            'mem':        mem_data['mem'],
            'swap':       mem_data['swap'],
            'disks':      disks,
            'net':        net,
            'gpu':        gpu,
            'top':        top,
            'uptime_s':   uptime_s,
            'load_avg':   load,
            'vigil_self': vigil_self,
            'rapl':       rapl,
        }


# ---------------------------------------------------------------------------
# Helpers used by Collector (module-level so they can be patched in tests)
# ---------------------------------------------------------------------------
def _get_clk_tck():
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        val = libc.sysconf(2)   # _SC_CLK_TCK
        return val if val > 0 else 100
    except Exception:
        return 100

def _cpu_freq():
    total = 0
    count = 0
    base = '/sys/devices/system/cpu'
    for entry in _listdir(base):
        if not re.match(r'^cpu\d+$', entry):
            continue
        path = os.path.join(base, entry, 'cpufreq', 'scaling_cur_freq')
        raw = _read(path).strip()
        if raw:
            try:
                total += int(raw)
                count += 1
            except ValueError:
                pass
    return int(total / count / 1000) if count else 0


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access log

    def _send(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split('?')[0]
        if path == '/data':
            with _lock:
                snap = dict(_latest_self)
            self._send(200, 'application/json', json.dumps(snap))
        elif path == '/peers':
            now = time.time()
            with _lock:
                peer_list = [
                    {'ip': ip, 'host': v['host'],
                     'last_seen': int(v['last_seen']), 'port': v['port']}
                    for ip, v in _peers.items()
                ]
            self._send(200, 'application/json',
                       json.dumps({'self': _my_ip, 'peers': peer_list}))
        elif path == '/history':
            with _lock:
                rb = _history.get(_my_ip)
                samples = rb.get() if rb else []
            self._send(200, 'application/json', json.dumps(samples))
        elif path == '/ui':
            self._send(200, 'text/html; charset=utf-8', _UI_HTML)
        else:
            self._send(404, 'text/plain', 'not found')


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads    = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# UDP mesh discovery
# ---------------------------------------------------------------------------
def _detect_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def _broadcast_addr(ip):
    parts = ip.split('.')
    if len(parts) == 4:
        return '.'.join(parts[:3]) + '.255'
    return '255.255.255.255'

def _udp_broadcaster(ip):
    bcast = _broadcast_addr(ip)
    msg   = json.dumps({'host': _my_host, 'ip': ip, 'port': HTTP_PORT}).encode('utf-8')
    sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while True:
        try:
            sock.sendto(msg, (bcast, UDP_PORT))
        except Exception:
            pass
        time.sleep(5)

def _udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore
    except AttributeError:
        pass
    sock.bind(('', UDP_PORT))
    sock.settimeout(1.0)

    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            _expire_peers()
            continue
        except Exception:
            continue

        try:
            msg = json.loads(data.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            continue

        ip   = msg.get('ip', addr[0])
        host = msg.get('host', ip)
        port = int(msg.get('port', HTTP_PORT))

        if ip == _my_ip:
            continue

        with _lock:
            _peers[ip] = {'host': host, 'port': port, 'last_seen': time.time()}

        _expire_peers()

def _expire_peers():
    now = time.time()
    with _lock:
        drop = [ip for ip, v in _peers.items()
                if now - v['last_seen'] > PEER_DROP]
        for ip in drop:
            del _peers[ip]


# ---------------------------------------------------------------------------
# Static peer seeding
# ---------------------------------------------------------------------------
def _seed_peers():
    ips = list(STATIC_PEERS)
    try:
        with open('peers.txt', 'r') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#'):
                    ips.append(line)
    except IOError:
        pass
    with _lock:
        for ip in ips:
            if ip not in _peers:
                _peers[ip] = {'host': ip, 'port': HTTP_PORT, 'last_seen': 0.0}


# ---------------------------------------------------------------------------
# Embedded UI (no styling)
# ---------------------------------------------------------------------------
_UI_HTML = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vigil</title>
</head>
<body>
<h1>Vigil</h1>
<p id="status">Loading...</p>
<div id="mesh"></div>
<script>
var POLL_MS     = 2000;
var SPARK_WIDTH = 60;
var LOG_ROWS    = 20;

var nodeHistory    = {};
var historyFetched = {};

function get(url, cb) {
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function() {
    if (xhr.readyState !== 4) return;
    if (xhr.status === 200) {
      try { cb(null, JSON.parse(xhr.responseText)); }
      catch (e) { cb(e); }
    } else {
      cb(new Error('HTTP ' + xhr.status));
    }
  };
  xhr.open('GET', url);
  xhr.send();
}

function mergeHistory(ip, samples) {
  if (!nodeHistory[ip]) nodeHistory[ip] = [];
  var seen = {};
  nodeHistory[ip].forEach(function(s) { seen[s.ts] = true; });
  samples.forEach(function(s) {
    if (!seen[s.ts]) { nodeHistory[ip].push(s); seen[s.ts] = true; }
  });
  nodeHistory[ip].sort(function(a, b) { return a.ts - b.ts; });
  if (nodeHistory[ip].length > 1200) nodeHistory[ip] = nodeHistory[ip].slice(-1200);
}

function appendLive(ip, sample) {
  if (!nodeHistory[ip]) nodeHistory[ip] = [];
  var hist = nodeHistory[ip];
  if (!hist.length || hist[hist.length - 1].ts !== sample.ts) {
    hist.push(sample);
    if (hist.length > 1200) hist.shift();
  }
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function fmtUptime(s) {
  var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  var parts = [];
  if (d) parts.push(d + 'd');
  if (h) parts.push(h + 'h');
  parts.push(m + 'm');
  return parts.join(' ');
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

function tbl(cols, rows) {
  var h = '<table border="1"><tr>' + cols.map(function(c) { return '<th>' + esc(c) + '</th>'; }).join('') + '</tr>';
  rows.forEach(function(row) {
    h += '<tr>' + row.map(function(cell) { return '<td>' + esc(cell) + '</td>'; }).join('') + '</tr>';
  });
  return h + '</table>';
}

var BLOCKS = '\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588';

// fixedMax: use a known ceiling (e.g. 100 for %) so bar height is absolute, not relative
function sparkline(vals, fixedMax) {
  if (!vals || !vals.length) return '';
  var max = (fixedMax !== undefined) ? fixedMax
          : vals.reduce(function(m, v) { return Math.max(m, v); }, 0.001);
  if (max <= 0) max = 0.001;
  return vals.map(function(v, i) {
    var bar = BLOCKS[Math.min(7, Math.max(0, Math.round(v / max * 7)))];
    return (i > 0 && i % 10 === 0) ? ' ' + bar : bar;
  }).join('');
}

function sparkStats(vals) {
  if (!vals.length) return {min: 0, avg: 0, max: 0};
  var mn = vals[0], mx = vals[0], sum = 0;
  for (var i = 0; i < vals.length; i++) {
    if (vals[i] < mn) mn = vals[i];
    if (vals[i] > mx) mx = vals[i];
    sum += vals[i];
  }
  var r = function(v) { return Math.round(v * 10) / 10; };
  return {min: r(mn), avg: r(sum / vals.length), max: r(mx)};
}

function renderNode(d, hist, offline, lastSeenAgo) {
  var h = '<hr>';
  h += '<h2>' + esc(d.host);
  if (offline) h += ' [OFFLINE - last seen ' + Math.round(lastSeenAgo) + 's ago]';
  h += '</h2>';
  h += '<p>Uptime: ' + fmtUptime(d.uptime_s) + ' | Load avg (1m / 5m / 15m): ' + d.load_avg.join(' / ') + '</p>';

  h += '<h3>CPU</h3>';
  h += '<p>Total: ' + d.cpu.total_pct + '% | Cores: ' + d.cpu.count + ' | Freq: ' + d.cpu.freq_mhz + ' MHz</p>';
  if (d.cpu.usage_pct && d.cpu.usage_pct.length) {
    h += '<p>' + d.cpu.usage_pct.map(function(v, i) { return 'cpu' + i + ': ' + v + '%'; }).join(' | ') + '</p>';
  }
  if (d.rapl && d.rapl.length) {
    h += '<p>Power (RAPL): ' + d.rapl.map(function(z) { return z.name + ': ' + z.watts + ' W'; }).join(' | ') + '</p>';
  }

  h += '<h3>Memory</h3>';
  h += '<p>RAM: ' + d.mem.used_mb + ' / ' + d.mem.total_mb + ' MB (' + d.mem.used_pct + '%) | Available: ' + d.mem.available_mb + ' MB</p>';
  h += '<p>Swap: ' + d.swap.used_mb + ' / ' + d.swap.total_mb + ' MB (' + d.swap.used_pct + '%)</p>';

  if (d.disks && d.disks.length) {
    h += '<h3>Disks</h3>';
    h += tbl(['Device','Mount','Used GB','Total GB','%','Read MB/s','Write MB/s'],
      d.disks.map(function(dk) {
        return [dk.device, dk.mount, dk.used_gb, dk.total_gb, dk.used_pct, dk.read_mb_s, dk.write_mb_s];
      }));
  }

  if (d.net && d.net.length) {
    h += '<h3>Network</h3>';
    h += tbl(['Interface','RX MB/s','TX MB/s','RX Total GB','TX Total GB'],
      d.net.map(function(n) {
        return [n.iface, n.rx_mb_s, n.tx_mb_s, n.rx_total_gb, n.tx_total_gb];
      }));
  }

  if (d.gpu && d.gpu.length) {
    h += '<h3>GPU</h3>';
    h += tbl(['#','Name','Util %','VRAM Used MB','VRAM Total MB','VRAM %','Temp C','Power W','Limit W','Fan %'],
      d.gpu.map(function(g) {
        return [g.index, g.name, g.util_pct, g.mem_used_mb, g.mem_total_mb,
                g.mem_used_pct, g.temp_c, g.power_w, g.power_limit_w, g.fan_pct];
      }));
  }

  if (d.top && d.top.length) {
    h += '<h3>Top Processes</h3>';
    h += tbl(['PID','Name','CPU %','RAM MB'],
      d.top.map(function(p) { return [p.pid, p.name, p.cpu_pct, p.mem_mb]; }));
  }

  if (d.vigil_self) {
    h += '<h3>Vigil process</h3>';
    h += '<p>PID: ' + d.vigil_self.pid + ' | CPU: ' + d.vigil_self.cpu_pct + '% | RAM: ' + d.vigil_self.rss_mb + ' MB</p>';
  }

  if (hist && hist.length > 1) {
    var n = hist.length;
    h += '<h3>History (' + n + ' samples / ~' + Math.round(n / 60) + ' min)</h3>';

    var cpuVals    = hist.map(function(s) { return s.cpu       ? s.cpu.total_pct  : 0; });
    var memVals    = hist.map(function(s) { return s.mem       ? s.mem.used_pct   : 0; });
    var loadVals   = hist.map(function(s) { return s.load_avg  ? s.load_avg[0]    : 0; });
    var gpuVals    = hist.map(function(s) { return s.gpu && s.gpu[0] ? s.gpu[0].util_pct : 0; });
    var vigilVals  = hist.map(function(s) { return s.vigil_self ? s.vigil_self.rss_mb : 0; });
    var hasGpu     = gpuVals.some(function(v) { return v > 0; });
    var raplVals   = hist.map(function(s) { return s.rapl && s.rapl[0] ? s.rapl[0].watts : 0; });
    var hasRapl    = raplVals.some(function(v) { return v > 0; });
    var maxRaplW   = Math.max.apply(null, raplVals) * 1.5 || 1;
    var maxVigilMb = Math.max.apply(null, vigilVals) * 1.5 || 1;  // headroom above peak

    var w = Math.min(n, SPARK_WIDTH);
    var wCpu  = cpuVals.slice(-w),  stCpu  = sparkStats(wCpu);
    var wMem  = memVals.slice(-w),  stMem  = sparkStats(wMem);
    var wLoad = loadVals.slice(-w), stLoad = sparkStats(wLoad);
    var wVig  = vigilVals.slice(-w);

    // sparkline helper with stats suffix: bar + min/avg/max
    function sl(vals, fixedMax, unit) {
      var st = sparkStats(vals);
      return esc(sparkline(vals, fixedMax)) + '  ' +
             'min:' + st.min + unit + ' avg:' + st.avg + unit + ' max:' + st.max + unit;
    }

    h += '<pre>';
    h += 'CPU  [' + w + 's]: ' + sl(wCpu,  100, '%') + '  now:' + d.cpu.total_pct + '%\n\n';
    h += 'MEM  [' + w + 's]: ' + sl(wMem,  100, '%') + '  now:' + d.mem.used_pct  + '%\n\n';
    h += 'LOAD [' + w + 's]: ' + sl(wLoad, undefined, '') + '  now:' + d.load_avg[0] + '\n\n';
    if (hasGpu) {
      var wGpu = gpuVals.slice(-w);
      h += 'GPU  [' + w + 's]: ' + sl(wGpu, 100, '%') + '  now:' + (d.gpu[0] ? d.gpu[0].util_pct : 0) + '%\n\n';
    }
    if (hasRapl) {
      var wRapl = raplVals.slice(-w);
      h += 'RAPL [' + w + 's]: ' + sl(wRapl, maxRaplW, 'W') + '  now:' + (d.rapl && d.rapl[0] ? d.rapl[0].watts : 0) + 'W\n\n';
    }
    h += 'VIGIL[' + w + 's]: ' + sl(wVig, maxVigilMb, 'MB') + '  now:' + (d.vigil_self ? d.vigil_self.rss_mb : 0) + 'MB\n';
    h += '</pre>';

    var logCols = ['Time','CPU %','MHz','RAM %','Swap %','Load 1m','Vigil MB'];
    if (hasGpu)  { logCols.push('GPU %', 'GPU C'); }
    if (hasRapl) { logCols.push('CPU W'); }
    var recent  = hist.slice(-LOG_ROWS).reverse();
    var logRows = recent.map(function(s) {
      var row = [
        fmtTime(s.ts),
        s.cpu  ? s.cpu.total_pct  : 0,
        s.cpu  ? s.cpu.freq_mhz   : 0,
        s.mem  ? s.mem.used_pct   : 0,
        s.swap ? s.swap.used_pct  : 0,
        s.load_avg ? s.load_avg[0] : 0,
        s.vigil_self ? s.vigil_self.rss_mb : 0,
      ];
      if (hasGpu) {
        row.push(s.gpu && s.gpu[0] ? s.gpu[0].util_pct : 0);
        row.push(s.gpu && s.gpu[0] ? s.gpu[0].temp_c   : 0);
      }
      if (hasRapl) {
        row.push(s.rapl && s.rapl[0] ? s.rapl[0].watts : 0);
      }
      return row;
    });
    h += '<h4>Recent log</h4>';
    h += tbl(logCols, logRows);
  }

  return h;
}

function refresh() {
  get('/peers', function(err, peerData) {
    if (err) {
      document.getElementById('status').textContent = 'Error: ' + err.message;
      return;
    }
    var selfIp = peerData.self;
    var nowSec = Date.now() / 1000;
    var nodes  = [{ip: selfIp, port: 7700, isSelf: true}];
    (peerData.peers || []).forEach(function(p) {
      nodes.push({ip: p.ip, port: p.port, host: p.host, last_seen: p.last_seen, isSelf: false});
    });

    var liveData = {};
    var pending  = nodes.length;

    function done() {
      if (--pending > 0) return;
      var html = '';
      nodes.forEach(function(node) {
        var d = liveData[node.ip];
        if (d) {
          html += renderNode(d, nodeHistory[node.ip] || [], false, 0);
        } else if (!node.isSelf && node.last_seen) {
          var placeholder = {
            host: node.host || node.ip, uptime_s: 0, load_avg: [0,0,0],
            cpu:  {total_pct:0, freq_mhz:0, count:0, usage_pct:[]},
            mem:  {used_mb:0, total_mb:0, available_mb:0, used_pct:0},
            swap: {used_mb:0, total_mb:0, used_pct:0},
            disks:[], net:[], gpu:[], top:[]
          };
          html += renderNode(placeholder, nodeHistory[node.ip] || [], true, nowSec - node.last_seen);
        }
      });
      document.getElementById('mesh').innerHTML = html;
      document.getElementById('status').textContent =
        'Updated: ' + new Date().toLocaleTimeString() + ' | Nodes: ' + nodes.length;
    }

    nodes.forEach(function(node) {
      var base = 'http://' + node.ip + ':' + node.port;
      if (!historyFetched[node.ip]) {
        historyFetched[node.ip] = true;
        get(base + '/history', function(err, hist) {
          if (!err && Array.isArray(hist)) mergeHistory(node.ip, hist);
        });
      }
      get(base + '/data', function(err, data) {
        if (!err) { liveData[node.ip] = data; appendLive(node.ip, data); }
        done();
      });
    });
  });
}

setInterval(refresh, POLL_MS);
refresh();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global _my_ip, _my_host

    _my_host = socket.gethostname()
    _my_ip   = _detect_local_ip()

    _seed_peers()

    collector = Collector()

    # First snapshot
    snap = collector.collect()
    with _lock:
        _latest_self.update(snap)
        _history.setdefault(_my_ip, RingBuffer(HISTORY_DEPTH)).append(snap)

    # UDP broadcaster
    t = threading.Thread(target=_udp_broadcaster, args=(_my_ip,))
    t.daemon = True
    t.name   = 'udp-broadcast'
    t.start()

    # UDP listener
    t = threading.Thread(target=_udp_listener)
    t.daemon = True
    t.name   = 'udp-listen'
    t.start()

    # HTTP server
    server = _ThreadedHTTPServer(('', HTTP_PORT), _Handler)
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.name   = 'http'
    t.start()

    print('Vigil running on http://{}:{}/ui'.format(_my_ip, HTTP_PORT))

    try:
        while True:
            time.sleep(TICK_INTERVAL)
            snap = collector.collect()
            with _lock:
                _latest_self.clear()
                _latest_self.update(snap)
                _history.setdefault(_my_ip, RingBuffer(HISTORY_DEPTH)).append(snap)
    except KeyboardInterrupt:
        print('\nStopping.')
        server.shutdown()


if __name__ == '__main__':
    main()
