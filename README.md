# Vigil

Single-file Linux mesh monitor. Zero dependencies — stdlib only. Requires Python 3.4+.

## What it does

- Collects CPU, RAM, swap, disk, network, GPU, and process stats once per second
- Exposes a browser UI at `http://<host>:7700/ui` showing live data and sparkline history for every node
- Auto-discovers other Vigil nodes on the same subnet via UDP broadcast — open the UI on any one node and see all of them
- Tracks Vigil's own CPU and RAM footprint (`~25 MB RSS`)
- Reads Intel RAPL CPU power (watts) if `/sys/class/powercap` is accessible
- Keeps ~20 minutes of history per node in RAM via a ring buffer

## What it cannot do

- **Not cross-platform** — reads `/proc` and `/sys` directly; will not run on Windows or macOS
- No authentication or TLS — intended for trusted LANs only
- No persistent storage — history is lost on restart
- GPU monitoring requires `nvidia-smi` in PATH; AMD GPUs are not supported
- RAPL power requires read access to `/sys/class/powercap/intel-rapl*/energy_uj` (may need `sudo` or a udev rule)
- Nodes on different subnets/VLANs won't auto-discover; use `peers.txt` instead

## Usage

```bash
python3 vigil.py
# → Vigil running on http://192.168.1.10:7700/ui
```

Open the printed URL in any browser. All other Vigil nodes on the subnet appear automatically within a few seconds.

**Static peers** (different subnets): create `peers.txt` next to `vigil.py`, one IP per line.

**Firewall**: open TCP 7700 (UI/API) and UDP 7701 (discovery).

## Configuration

Edit the constants at the top of `vigil.py` — no config files, no CLI flags:

| Variable | Default | Purpose |
|---|---|---|
| `HTTP_PORT` | 7700 | HTTP server port |
| `UDP_PORT` | 7701 | UDP discovery port |
| `TICK_INTERVAL` | 1.0 | Seconds between collections |
| `HISTORY_DEPTH` | 1200 | Samples kept per node (~20 min) |
| `PEER_TIMEOUT` | 15 | Seconds before marking a node offline |
| `PEER_DROP` | 60 | Seconds before removing a node from the table |
| `TOP_PROCS` | 10 | Processes shown in the top table |
| `GPU_ENABLED` | True | Set False to skip nvidia-smi entirely |
| `STATIC_PEERS` | [] | Hardcode peer IPs, e.g. `["10.0.1.5"]` |

## API

| Endpoint | Returns |
|---|---|
| `/data` | Current snapshot for this node (JSON) |
| `/peers` | Known peer table (JSON) |
| `/history` | Ring buffer of snapshots for this node (JSON array) |
| `/ui` | Browser dashboard (HTML) |

## Entirely made with Claude Code.