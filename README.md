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

## Requirements

- Python 3.10+
- OpenClaw installed (`~/.npm-global/bin/openclaw`)
- systemd (Linux)
- UFW (optional, for firewall management)

## Installation

```bash
git clone https://github.com/lostsock1/ocm.git
cd ocm
chmod +x openclaw_manager.py
./openclaw_manager.py install-aliases
source ~/.bashrc
```

## Usage

### Create Instance
```bash
ocm create worker1 --model minimax/minimax-m2.5
```

### Manage Instance
```bash
ocm start worker1     # Start instance
ocm stop worker1      # Stop instance
ocm restart worker1   # Restart instance
ocm status worker1    # Show detailed status
ocm logs worker1      # View logs
ocm health            # Health check all instances
```

### Run OpenClaw Commands in Instance Context
```bash
ocm use worker1 health              # Run health check
ocm use worker1 status              # Get status
ocm use worker1 logs --follow       # Follow logs
```

### Enter Interactive Shell
```bash
ocm enter  # Select instance and open shell
```

### Backup and Restore
```bash
ocm backup worker1                           # Backup to default location
ocm restore ~/backups/mybackup.tar.gz        # Restore from archive
```

## Commands

| Command | Description |
|---------|-------------|
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
| `health` | Health check all |
| `backup <name>` | Backup instance |
| `restore <archive>` | Restore from archive |
| `use <name> <cmd>` | Run openclaw command |
| `enter` | Interactive shell |
| `install-aliases` | Install shell aliases |

## License

MIT