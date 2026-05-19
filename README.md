# OCM — OpenClaw Multi-Instance Manager

**CLI tool for creating, isolating, and managing OpenClaw agent instances with
systemd sandboxing, config inheritance, and health monitoring.**

![Python](https://img.shields.io/badge/python-3.8+-blue)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![systemd](https://img.shields.io/badge/systemd-user%20services-green)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

---

## Overview

OCM manages the full lifecycle of sandboxed OpenClaw agent instances on a Linux
host. Each instance gets its own state directory, config file, port, and
hardened systemd user service — no containers, no overhead. Config (providers,
models, API keys) is inherited from the main instance, so new instances are
ready to use immediately.

Designed for running multiple isolated AI agents on a single machine with strict
filesystem boundaries and per-instance access control.

---

## Architecture

```
┌──────────────────────────────────────────┐
│               ocm CLI                     │
│  deploy  create  start  stop  delete ... │
└──────────────────┬───────────────────────┘
                   │
     ┌─────────────┼─────────────┐
     ▼             ▼             ▼
┌─────────┐ ┌──────────┐ ┌──────────────┐
│ Registry│ │  Config  │ │  Systemd     │
│  JSON   │ │Inheritor │ │  Manager     │
│ ~/.ocm/ │ │ templates│ │  hardened    │
│registry │ │  + main  │ │  .service    │
│  .json  │ │  config  │ │  units       │
└────┬────┘ └────┬─────┘ └──────┬───────┘
     │           │              │
     ▼           ▼              ▼
┌──────────────────────────────────────────┐
│          INSTANCES (per-profile)          │
│                                          │
│  Instance "worker1"     port 18789       │
│  ├── ~/.openclaw-worker1/                │
│  │   ├── workspace/                      │
│  │   └── agents/main/sessions/           │
│  ├── ~/.openclaw/openclaw-worker1.json   │
│  └── systemd: openclaw-gateway-worker1   │
│                                          │
│  Instance "worker2"     port 19009       │
│  ├── ~/.openclaw-worker2/                │
│  │   ├── workspace/                      │
│  │   └── agents/main/sessions/           │
│  ├── ~/.openclaw/openclaw-worker2.json   │
│  └── systemd: openclaw-gateway-worker2   │
└──────────────────────────────────────────┘
```

### Key Design Decisions

**No containers.** Instances use systemd's native sandboxing (`ProtectSystem=strict`,
`ReadWritePaths`, `PrivateTmp`, `NoNewPrivileges`) instead of Docker. This means zero
container overhead, native journald logging, and straightforward filesystem paths.

**Config inheritance, not duplication.** New instances inherit providers, API keys, and
model catalog from the main OpenClaw config. You configure models once — all instances
inherit them. Templates (`~/.openclaw/openclaw.json.templ`) override inheritance when present.

**Deterministic port allocation.** Ports follow the sequence 18789, 19009, 19029, ... (base
18789 + n×20). The registry tracks the counter. No port scanning needed.

**JSON registry.** Instance metadata lives in `~/.openclaw-manager/registry.json` —
human-readable, easy to inspect, no database dependency.

---

## Installation

```bash
# Clone
git clone https://github.com/lostsock1/ocm.git
cd ocm

# Make executable
chmod +x ocm.py

# Optional: symlink to PATH
ln -s "$(pwd)/ocm.py" /usr/local/bin/ocm
```

**Prerequisites:**
- Python 3.8+
- Linux with systemd (user services enabled)
- OpenClaw installed at `~/.npm-global/bin/openclaw`
- Main OpenClaw config at `~/.openclaw/openclaw.json`

No pip packages needed — OCM uses only the Python standard library.

---

## Quick Start

```bash
# Deploy an instance (create + start + health check, all in one)
ocm deploy worker1

# Deploy with a specific model
ocm deploy worker2 --model openai/gpt-4

# List all instances
ocm list
# Instance        Port     Status     Autostart   Model
# worker1         18789    active     enabled     default
# worker2         19009    active     enabled     openai/gpt-4

# Run a command in an instance's context
ocm use worker1 agent --agent main --message "Summarize this file"

# Check health of all instances
ocm health
```

---

## CLI Reference

### Lifecycle

| Command | Description |
|---------|-------------|
| `ocm deploy <name> [--model <m>]` | Create + start + verify (one-step) |
| `ocm create <name> [--model <m>] [--autostart]` | Create instance only |
| `ocm delete <name> [--force]` | Stop service, remove files, clean registry |
| `ocm start <name>` | Start via systemd |
| `ocm stop <name>` | Stop via systemd |
| `ocm restart <name>` | Stop then start |

### Config & Autostart

| Command | Description |
|---------|-------------|
| `ocm enable <name>` | Enable autostart on boot |
| `ocm disable <name>` | Disable autostart |
| `ocm edit <name> <key> <value>` | Edit config JSON (e.g. `agents.defaults.model`) |

### Inspection

| Command | Description |
|---------|-------------|
| `ocm list` | Table of all instances |
| `ocm status <name>` | Detailed view: port, paths, service state |
| `ocm health` | TCP port probe on all instances |
| `ocm logs <name> [-f]` | journalctl for the instance (tail or follow) |

### Interaction

| Command | Description |
|---------|-------------|
| `ocm use <name> <args...>` | Run `openclaw` with `--profile=<name>` |
| `ocm enter <name>` | Interactive shell in the instance workspace |
| `ocm update-models` | Fetch latest model catalog from PPQ AI API |

---

## Security Model

Each instance's systemd unit applies these hardening directives:

```ini
[Service]
ProtectSystem=strict          # /usr, /boot, /etc read-only
ReadWritePaths=<state_dir> /tmp /var/tmp   # only these paths writable
BindPaths=<config_path>       # only its own config readable
PrivateTmp=yes               # isolated /tmp and /var/tmp
NoNewPrivileges=yes          # no setuid, no privilege escalation
ProtectKernelTunables=yes    # no sysctl modifications
ProtectKernelModules=yes     # no module loading
ProtectControlGroups=yes     # no cgroup manipulation
RestrictSUIDSGID=yes         # no SUID/SGID
RestrictRealtime=yes         # no realtime scheduling
RestrictNamespaces=yes       # no namespace creation
LockPersonality=yes          # no personality(2) changes
MemoryDenyWriteExecute=no    # allow JIT (needed for JS runtime)
```

OpenClaw sandbox config (per-instance):

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main",
        "scope": "agent",
        "workspaceAccess": "rw"
      }
    }
  },
  "session": {
    "dmScope": "per-channel-peer"
  }
}
```

**Result:** Instance A cannot read Instance B's files. No instance can modify
system binaries. No instance can escalate privileges. Each instance has its own
`/tmp` and `/var/tmp`.

---

## Project Structure

```
ocm/
├── ocm.py          # Single-file implementation (~600 loc)
│
│   Classes:
│   ├── Instance           # dataclass: name, port, profile, paths
│   ├── Registry           # JSON file read/write for instance metadata
│   ├── PortManager        # deterministic port allocation (18789 + n×20)
│   ├── ConfigInheritor    # merges main config + template + instance overrides
│   ├── SystemdManager     # .service file generation with hardening directives
│   ├── OpenClawManager    # orchestrates all operations
│   └── PPQModelUpdater    # fetches model catalog from PPQ AI API
│
└── README.md
```

**Zero dependencies.** The entire tool is one Python file using only stdlib:
`json`, `subprocess`, `pathlib`, `argparse`, `urllib`, `socket`, `shutil`.

---

## Model Sync

```bash
ocm update-models
```

Fetches the current model catalog from PPQ AI (`api.ppq.ai/v1/models`) and
updates the main OpenClaw config's `models.providers` section. New instances
automatically inherit updated models.

---

## License

MIT — see [LICENSE](LICENSE).
