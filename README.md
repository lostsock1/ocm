# OpenClaw Multi-Instance Manager (OCM)

A CLI tool for managing isolated OpenClaw instances using profile-based isolation.

## Features

- **Profile-based isolation** - Each instance has its own state, config, and port
- **Auto port assignment** - Automatically finds available ports (18789, 19001, 19021...)
- **UFW integration** - Automatically adds/removes firewall rules
- **Systemd services** - Per-instance user services with autostart support
- **Config inheritance** - Inherits providers, API keys, and models from main instance
- **Backup/Restore** - Full instance backup with restore capability
- **Instance shell** - Run openclaw commands in instance context with `use` command
- **Model sync** - Fetch available models from PPQ AI API
- **Strict sandbox isolation** - Instances are isolated with systemd security hardening
- **Per-instance filesystem restrictions** - Each instance can only access its own files

## Security Features

### Strict Sandbox Isolation

All new instances are deployed with strict security hardening:

```ini
# Systemd service restrictions
ProtectSystem=strict          # System dirs read-only
ReadWritePaths=<instance_dir> # Only instance state + temp
BindPaths=<config_file>       # Only own config file
PrivateTmp=yes               # Isolated temp files
NoNewPrivileges=yes          # No privilege escalation
ProtectKernelTunables=yes    # Protected kernel
ProtectControlGroups=yes    # Protected cgroups
RestrictNamespaces=yes      # Isolated namespaces
```

### OpenClaw Sandbox Configuration

Each instance automatically gets:

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

### Instance Isolation

| Access Level | Paths |
|-------------|-------|
| **READ/WRITE** | `~/.openclaw-<name>/*`, `/tmp/*`, `/var/tmp/*` |
| **READ-ONLY** | `/usr/*`, `/boot/*`, `/etc/*` (ProtectSystem=strict) |
| **NO ACCESS** | Main config, credentials, logs, other instances |

Each instance can **only** access:
- Its own state directory (`~/.openclaw-<name>/`)
- Its own config file (`~/.openclaw/openclaw-<name>.json`)
- Temporary directories

## Requirements

- Python 3.10+
- OpenClaw installed (`~/.npm-global/bin/openclaw`)
- systemd (Linux)
- UFW (optional, for firewall management)

## Installation

```bash
git clone https://github.com/lostsock1/ocm.git
cd ocm
chmod +x ocm.py
```

## Usage

Run OCM directly:
```bash
./ocm.py <command> [arguments]
```

Or with Python:
```bash
python3 ocm.py <command> [arguments]
```

### Quick Deploy (Create + Start + Verify)
```bash
./ocm.py deploy worker1
./ocm.py deploy worker2 --model minimax/minimax-m2.5
```

### Update Models from PPQ AI
```bash
./ocm.py update-models    # Fetch all available models and update config
```

### Create Instance
```bash
./ocm.py create worker1 --model minimax/minimax-m2.5
```

### Manage Instance
```bash
./ocm.py start worker1     # Start instance
./ocm.py stop worker1      # Stop instance
./ocm.py restart worker1   # Restart instance
./ocm.py status worker1    # Show detailed status
./ocm.py logs worker1      # View logs
./ocm.py health            # Health check all instances
./ocm.py enable worker1    # Enable autostart
./ocm.py disable worker1   # Disable autostart
```

### Run OpenClaw Commands in Instance Context
```bash
./ocm.py use worker1 health              # Run health check
./ocm.py use worker1 status              # Get status
./ocm.py use worker1 logs --follow       # Follow logs
```

### Enter Interactive Shell
```bash
./ocm.py enter worker1  # Open shell for instance
```

### Backup and Restore
```bash
./ocm.py backup worker1                           # Backup to default location
./ocm.py restore ~/backups/mybackup.tar.gz        # Restore from archive
```

### Edit Configuration
```bash
./ocm.py edit worker1 agents.defaults.model "minimax/minimax-m2.5"
```

## Commands

| Command | Description |
|---------|-------------|
| `deploy <name>` | Create, start, and verify instance |
| `create <name>` | Create new instance |
| `delete <name>` | Delete instance |
| `edit <name> <key> <value>` | Edit config |
| `list` | List all instances |
| `start <name>` | Start instance |
| `stop <name>` | Stop instance |
| `restart <name>` | Restart instance |
| `enable <name>` | Enable autostart |
| `disable <name>` | Disable autostart |
| `status <name>` | Show instance status |
| `logs <name>` | View instance logs |
| `-f, --follow` | Follow logs in real-time |
| `health` | Health check all instances |
| `update-models` | Fetch models from PPQ AI API |
| `backup <name>` | Backup instance |
| `restore <archive>` | Restore from archive |
| `use <name> <cmd>` | Run openclaw command |
| `enter <name>` | Interactive shell |

## Instance Independence

Each instance runs completely independently:

- **Separate process** - Each instance has its own gateway process
- **Separate port** - Unique port allocation (18789 + 20n)
- **Separate config** - Own config file with isolated settings
- **Separate state** - Own state directory with workspace
- **Separate systemd service** - Can be started/stopped independently

The main gateway (port 18789) is **optional** - instances can run without it.

## Filesystem Access

### Per-Instance Restrictions

When you create an instance named `worker1`:

```
✅ Can Write:
  - /home/debian/.openclaw-worker1/ (state directory)
  - /home/debian/.openclaw/openclaw-worker1.json (config)
  - /tmp/*, /var/tmp/* (temp)

❌ Cannot Access:
  - /home/debian/.openclaw/openclaw.json (main config)
  - /home/debian/.openclaw/credentials/ (API keys)
  - /home/debian/.openclaw/logs/ (audit logs)
  - Other instances' directories
```

## License

MIT
