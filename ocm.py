#!/usr/bin/env python3
"""
OpenClaw Multi-Instance Manager

Manages isolated OpenClaw instances using profile-based isolation.
Each instance has its own state, config, port, and systemd service.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Constants
REGISTRY_DIR = Path.home() / ".openclaw-manager"
REGISTRY_FILE = REGISTRY_DIR / "registry.json"
OPENCLAW_BIN = Path.home() / ".npm-global/bin/openclaw"
SYSTEMD_USER_DIR = Path.home() / ".config/systemd/user"
BASE_PORT = 18789
PORT_INCREMENT = 20
MAIN_PROFILE = "main"


@dataclass
class Instance:
    """Represents an OpenClaw instance"""

    name: str
    port: int
    profile: str
    created_at: str
    autostart: bool = False
    status: str = "stopped"
    model: str = ""

    def state_dir(self) -> Path:
        return Path.home() / f".openclaw-{self.name}"

    def config_path(self) -> Path:
        return Path.home() / ".openclaw" / f"openclaw-{self.name}.json"

    def workspace(self) -> Path:
        return self.state_dir() / "workspace"

    def service_name(self) -> str:
        return f"openclaw-gateway-{self.name}.service"

    def service_path(self) -> Path:
        return SYSTEMD_USER_DIR / self.service_name()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "port": self.port,
            "profile": self.profile,
            "created_at": self.created_at,
            "autostart": self.autostart,
            "status": self.status,
            "model": self.model,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Instance":
        return cls(**data)


class Registry:
    """Manages instance registry"""

    def __init__(self):
        self._ensure_dirs()
        self._data = self._load()

    def _ensure_dirs(self):
        REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
        SYSTEMD_USER_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict:
        if REGISTRY_FILE.exists():
            with open(REGISTRY_FILE, "r") as f:
                return json.load(f)
        return {"instances": {}, "port_counter": 0}

    def _save(self):
        with open(REGISTRY_FILE, "w") as f:
            json.dump(self._data, f, indent=2)

    def get_all(self) -> Dict[str, Instance]:
        return {k: Instance.from_dict(v) for k, v in self._data["instances"].items()}

    def get(self, name: str) -> Optional[Instance]:
        if name in self._data["instances"]:
            return Instance.from_dict(self._data["instances"][name])
        return None

    def add(self, instance: Instance):
        self._data["instances"][instance.name] = instance.to_dict()
        self._save()

    def remove(self, name: str):
        if name in self._data["instances"]:
            del self._data["instances"][name]
            self._save()

    def update(self, instance: Instance):
        self._data["instances"][instance.name] = instance.to_dict()
        self._save()

    def next_port(self) -> int:
        """Get next available port (checks registry and system)"""
        instances = self.get_all()
        used_ports = {i.port for i in instances.values()}

        port = BASE_PORT
        while port in used_ports or self.is_port_listening(port):
            port += PORT_INCREMENT
        return port

    def port_in_use(self, port: int) -> bool:
        """Check if port is already assigned in registry"""
        return any(i.port == port for i in self.get_all().values())

    @staticmethod
    def is_port_listening(port: int) -> bool:
        """Check if port is actually listening on the system"""
        try:
            result = subprocess.run(
                f"ss -tlnp | grep ':{port}'", capture_output=True, text=True, shell=True
            )
            return result.returncode == 0 and str(port) in result.stdout
        except:
            return False


class UFWManager:
    """Manages UFW firewall rules"""

    @staticmethod
    def is_enabled() -> bool:
        """Check if UFW is enabled"""
        try:
            result = subprocess.run(
                ["sudo", "ufw", "status"], capture_output=True, text=True
            )
            return "Status: active" in result.stdout
        except:
            return False

    @staticmethod
    def allow_port(port: int, name: str) -> bool:
        """Allow port through UFW"""
        try:
            result = subprocess.run(
                ["sudo", "ufw", "allow", str(port), "comment", f"OpenClaw {name}"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Warning: Failed to add UFW rule: {e}")
            return False

    @staticmethod
    def delete_port(port: int) -> bool:
        """Remove UFW rule for port"""
        try:
            # Delete rules by port - ufw will handle both IPv4 and IPv6
            # Using 'delete allow' syntax without confirmation
            subprocess.run(
                ["sudo", "ufw", "delete", "allow", str(port)],
                capture_output=True,
                text=True,
            )
            return True
        except Exception as e:
            print(f"Warning: Failed to remove UFW rule: {e}")
            return False

    @staticmethod
    def list_rules():
        """List all UFW rules"""
        try:
            result = subprocess.run(
                ["sudo", "ufw", "status", "numbered"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except:
            return "Unable to get UFW rules"


class ConfigInheritor:
    """Handles configuration inheritance from main instance"""

    # Keys to inherit from main config
    INHERIT_KEYS = [
        "agent.model",
        "providers",
        "models",  # Custom model definitions
    ]

    # Keys to explicitly exclude (even if nested)
    EXCLUDE_PATTERNS = [
        "tailscale",
        "gateway.tailscale",
        "tailscale.*",
    ]

    @classmethod
    def load_main_config(cls) -> dict:
        """Load main instance config"""
        main_config_path = Path.home() / ".openclaw" / "openclaw.json"
        if main_config_path.exists():
            with open(main_config_path, "r") as f:
                return json.load(f)
        return {}

    @classmethod
    def extract_inheritable(cls, config: dict) -> dict:
        """Extract only inheritable settings"""
        inherited = {}

        # Copy agents.defaults (model config, workspace settings)
        if "agents" in config and "defaults" in config["agents"]:
            defaults = config["agents"]["defaults"]
            inherited["agents"] = {"defaults": {}}

            # Copy model configuration
            if "model" in defaults:
                inherited["agents"]["defaults"]["model"] = defaults["model"]
            if "models" in defaults:
                inherited["agents"]["defaults"]["models"] = defaults["models"]

        # Copy providers (excluding tailscale-related)
        if "providers" in config:
            inherited["providers"] = {}
            for provider_name, provider_config in config["providers"].items():
                if "tailscale" not in provider_name.lower():
                    inherited["providers"][provider_name] = {
                        k: v
                        for k, v in provider_config.items()
                        if k in ["baseURL", "apiKey", "models", "baseUrl", "api"]
                    }

        # Copy models if defined
        if "models" in config:
            inherited["models"] = config["models"]

        return inherited

    @classmethod
    def create_instance_config(cls, name: str, port: int) -> dict:
        """Create new instance config inheriting from main"""
        main_config = cls.load_main_config()
        inherited = cls.extract_inheritable(main_config)

        # Base config for new instance
        new_config = {
            "meta": {
                "lastTouchedVersion": "2026.2.15",
                "lastTouchedAt": datetime.now().isoformat() + "Z",
            },
            "gateway": {
                "mode": "local",
                "port": port,
                "bind": "loopback",
                "auth": {"mode": "token", "token": os.urandom(24).hex()},
            },
            "agents": {
                "defaults": {
                    "workspace": str(Path.home() / f".openclaw-{name}" / "workspace"),
                    "compaction": {"mode": "safeguard"},
                    "maxConcurrent": 4,
                    "subagents": {"maxConcurrent": 8},
                }
            },
        }

        # Merge inherited settings
        new_config.update(inherited)

        # Remove deprecated keys if modern format is present
        if "agent" in new_config and "agents" in new_config:
            if (
                "defaults" in new_config["agents"]
                and "model" in new_config["agents"]["defaults"]
            ):
                del new_config["agent"]  # Remove deprecated agent.*

        return new_config


class SystemdManager:
    """Manages systemd services for instances"""

    SERVICE_TEMPLATE = """[Unit]
Description=OpenClaw Gateway - {name} (v2026.2.15)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={node_path} {openclaw_path} --profile {profile} gateway --port {port}
Restart=always
RestartSec=5
KillMode=process
Environment=HOME={home}
Environment=PATH={path}
Environment=OPENCLAW_GATEWAY_PORT={port}
Environment=OPENCLAW_PROFILE={profile}
Environment=OPENCLAW_STATE_DIR={state_dir}
Environment=OPENCLAW_CONFIG_PATH={config_path}

[Install]
WantedBy=default.target
"""

    @staticmethod
    def _get_node_path() -> str:
        """Find node executable"""
        result = subprocess.run(["which", "node"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return "/usr/bin/node"

    @staticmethod
    def _get_path_env() -> str:
        """Get PATH environment variable"""
        path_parts = [
            str(Path.home() / ".npm-global/bin"),
            str(Path.home() / ".local/bin"),
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ]
        return ":".join(path_parts)

    @classmethod
    def create_service(cls, instance: Instance) -> bool:
        """Create systemd service file for instance"""
        try:
            service_content = cls.SERVICE_TEMPLATE.format(
                name=instance.name,
                profile=instance.name,
                port=instance.port,
                node_path=cls._get_node_path(),
                openclaw_path=str(OPENCLAW_BIN),
                home=str(Path.home()),
                path=cls._get_path_env(),
                state_dir=str(instance.state_dir()),
                config_path=str(instance.config_path()),
            )

            with open(instance.service_path(), "w") as f:
                f.write(service_content)

            # Reload systemd
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
            return True
        except Exception as e:
            print(f"Error creating service: {e}")
            return False

    @classmethod
    def delete_service(cls, instance: Instance) -> bool:
        """Delete systemd service file"""
        try:
            if instance.service_path().exists():
                instance.service_path().unlink()
                subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
            return True
        except Exception as e:
            print(f"Error deleting service: {e}")
            return False

    @classmethod
    def enable_autostart(cls, instance: Instance) -> bool:
        """Enable service to start on boot"""
        try:
            subprocess.run(
                ["systemctl", "--user", "enable", instance.service_name()], check=True
            )
            instance.autostart = True
            return True
        except Exception as e:
            print(f"Error enabling autostart: {e}")
            return False

    @classmethod
    def disable_autostart(cls, instance: Instance) -> bool:
        """Disable service from starting on boot"""
        try:
            subprocess.run(
                ["systemctl", "--user", "disable", instance.service_name()], check=True
            )
            instance.autostart = False
            return True
        except Exception as e:
            print(f"Error disabling autostart: {e}")
            return False

    @classmethod
    def start(cls, instance: Instance) -> bool:
        """Start the service"""
        try:
            subprocess.run(
                ["systemctl", "--user", "start", instance.service_name()], check=True
            )
            instance.status = "running"
            return True
        except Exception as e:
            print(f"Error starting service: {e}")
            return False

    @classmethod
    def stop(cls, instance: Instance) -> bool:
        """Stop the service"""
        try:
            subprocess.run(
                ["systemctl", "--user", "stop", instance.service_name()], check=True
            )
            instance.status = "stopped"
            return True
        except Exception as e:
            print(f"Error stopping service: {e}")
            return False

    @classmethod
    def restart(cls, instance: Instance) -> bool:
        """Restart the service"""
        try:
            subprocess.run(
                ["systemctl", "--user", "restart", instance.service_name()], check=True
            )
            instance.status = "running"
            return True
        except Exception as e:
            print(f"Error restarting service: {e}")
            return False

    @classmethod
    def get_status(cls, instance: Instance) -> str:
        """Get service status"""
        try:
            result = subprocess.run(
                ["systemctl", "--user", "is-active", instance.service_name()],
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except:
            return "unknown"


class OpenClawManager:
    """Main manager class"""

    def __init__(self):
        self.registry = Registry()
        self.ufw = UFWManager()

    def create_instance(
        self, name: str, port: Optional[int] = None, model: Optional[str] = None
    ) -> bool:
        """Create a new OpenClaw instance"""

        # Validate name
        if not re.match(r"^[a-zA-Z0-9_-]+$", name):
            print(
                f"Error: Invalid instance name '{name}'. Use only alphanumeric, hyphens, and underscores."
            )
            return False

        if name == MAIN_PROFILE:
            print(f"Error: Cannot create instance named '{MAIN_PROFILE}' (reserved)")
            return False

        if self.registry.get(name):
            print(f"Error: Instance '{name}' already exists")
            return False

        # Determine port
        if port is None:
            port = self.registry.next_port()
        elif self.registry.port_in_use(port):
            print(f"Error: Port {port} is already in use")
            return False

        print(f"Creating instance '{name}' on port {port}...")

        # Create directories
        instance = Instance(
            name=name,
            port=port,
            profile=name,
            created_at=datetime.now().isoformat(),
            model=model or "",
        )

        try:
            # Create state directory structure
            instance.state_dir().mkdir(parents=True, exist_ok=True)
            (instance.state_dir() / "workspace").mkdir(exist_ok=True)
            (instance.state_dir() / "agents").mkdir(exist_ok=True)
            (instance.state_dir() / "agents" / "main").mkdir(exist_ok=True)
            (instance.state_dir() / "agents" / "main" / "sessions").mkdir(exist_ok=True)
            (instance.state_dir() / "credentials").mkdir(exist_ok=True)

            # Create config
            config = ConfigInheritor.create_instance_config(name, port)
            if model:
                # Set model in new format
                if "agents" not in config:
                    config["agents"] = {"defaults": {}}
                if "defaults" not in config["agents"]:
                    config["agents"]["defaults"] = {}
                config["agents"]["defaults"]["model"] = {"primary": model}
                instance.model = model

            with open(instance.config_path(), "w") as f:
                json.dump(config, f, indent=2)

            # Create systemd service
            if not SystemdManager.create_service(instance):
                raise Exception("Failed to create systemd service")

            # Add UFW rule
            if self.ufw.is_enabled():
                self.ufw.allow_port(port, name)

            # Register instance
            self.registry.add(instance)

            print(f"✓ Instance '{name}' created successfully")
            print(f"  Port: {port}")
            print(f"  Config: {instance.config_path()}")
            print(f"  State: {instance.state_dir()}")
            print(f"  Service: {instance.service_name()}")

            return True

        except Exception as e:
            print(f"Error creating instance: {e}")
            # Cleanup on failure
            self._cleanup_partial(instance)
            return False

    def _cleanup_partial(self, instance: Instance):
        """Cleanup partial creation"""
        try:
            if instance.state_dir().exists():
                shutil.rmtree(instance.state_dir())
            if instance.config_path().exists():
                instance.config_path().unlink()
        except:
            pass

    def delete_instance(self, name: str, force: bool = False) -> bool:
        """Delete an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        if name == MAIN_PROFILE:
            print(f"Error: Cannot delete main instance")
            return False

        if not force:
            confirm = input(f"Delete instance '{name}'? This cannot be undone [y/N]: ")
            if confirm.lower() != "y":
                print("Cancelled")
                return False

        print(f"Deleting instance '{name}'...")

        try:
            # Stop service if running
            SystemdManager.stop(instance)

            # Disable autostart
            SystemdManager.disable_autostart(instance)

            # Delete service file
            SystemdManager.delete_service(instance)

            # Remove UFW rule
            self.ufw.delete_port(instance.port)

            # Remove directories
            if instance.state_dir().exists():
                shutil.rmtree(instance.state_dir())
            if instance.config_path().exists():
                instance.config_path().unlink()

            # Remove from registry
            self.registry.remove(name)

            print(f"✓ Instance '{name}' deleted successfully")
            return True

        except Exception as e:
            print(f"Error deleting instance: {e}")
            return False

    def edit_instance(self, name: str, key: str, value: str) -> bool:
        """Edit an instance config value"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        try:
            # Load config
            with open(instance.config_path(), "r") as f:
                config = json.load(f)

            # Set nested key (e.g., "agent.model")
            keys = key.split(".")
            target = config
            for k in keys[:-1]:
                if k not in target:
                    target[k] = {}
                target = target[k]

            # Try to parse value as JSON
            try:
                parsed_value = json.loads(value)
            except:
                parsed_value = value

            target[keys[-1]] = parsed_value

            # Save config
            with open(instance.config_path(), "w") as f:
                json.dump(config, f, indent=2)

            print(f"✓ Updated {key} = {value}")

            # Restart if running
            status = SystemdManager.get_status(instance)
            if status == "active":
                print("Restarting service...")
                SystemdManager.restart(instance)

            return True

        except Exception as e:
            print(f"Error editing instance: {e}")
            return False

    def list_instances(self, verbose: bool = False):
        """List all instances"""
        instances = self.registry.get_all()

        if not instances:
            print("No instances found")
            return

        print(
            f"{'Instance':<15} {'Port':<8} {'Status':<10} {'Autostart':<10} {'Model'}"
        )
        print("-" * 70)

        for name in sorted(instances.keys()):
            inst = instances[name]
            status = SystemdManager.get_status(inst)
            autostart = "enabled" if inst.autostart else "disabled"
            model = inst.model or "default"

            print(
                f"{inst.name:<15} {inst.port:<8} {status:<10} {autostart:<10} {model}"
            )

            if verbose:
                print(f"  Config: {inst.config_path()}")
                print(f"  State:  {inst.state_dir()}")
                print(f"  Service: {inst.service_name()}")
                print()

    def start_instance(self, name: str) -> bool:
        """Start an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        if SystemdManager.start(instance):
            self.registry.update(instance)
            print(f"✓ Instance '{name}' started")
            return True
        return False

    def stop_instance(self, name: str) -> bool:
        """Stop an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        if SystemdManager.stop(instance):
            self.registry.update(instance)
            print(f"✓ Instance '{name}' stopped")
            return True
        return False

    def restart_instance(self, name: str) -> bool:
        """Restart an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        if SystemdManager.restart(instance):
            self.registry.update(instance)
            print(f"✓ Instance '{name}' restarted")
            return True
        return False

    def enable_autostart(self, name: str) -> bool:
        """Enable autostart for instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        if SystemdManager.enable_autostart(instance):
            self.registry.update(instance)
            print(f"✓ Autostart enabled for '{name}'")
            return True
        return False

    def disable_autostart(self, name: str) -> bool:
        """Disable autostart for instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        if SystemdManager.disable_autostart(instance):
            self.registry.update(instance)
            print(f"✓ Autostart disabled for '{name}'")
            return True
        return False

    def status_instance(self, name: str):
        """Show detailed status"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return

        service_status = SystemdManager.get_status(instance)

        print(f"\nInstance: {instance.name}")
        print(f"Port: {instance.port}")
        print(f"Profile: {instance.profile}")
        print(f"Service Status: {service_status}")
        print(f"Autostart: {'enabled' if instance.autostart else 'disabled'}")
        print(f"Created: {instance.created_at}")
        print(f"\nPaths:")
        print(f"  Config: {instance.config_path()}")
        print(f"  State:  {instance.state_dir()}")
        print(f"  Service: {instance.service_path()}")

        # Show config summary
        if instance.config_path().exists():
            with open(instance.config_path(), "r") as f:
                config = json.load(f)

            if "agent" in config and "model" in config["agent"]:
                print(f"\nModel: {config['agent']['model']}")

            if "providers" in config:
                print(f"\nProviders: {', '.join(config['providers'].keys())}")

    def logs_instance(self, name: str, follow: bool = False):
        """Show instance logs"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return

        cmd = ["journalctl", "--user", "-u", instance.service_name()]
        if follow:
            cmd.append("-f")
        else:
            cmd.extend(["-n", "100"])

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass

    def health_check(self):
        """Health check all instances"""
        instances = self.registry.get_all()

        print("\nHealth Check:")
        print("-" * 50)

        for name in sorted(instances.keys()):
            inst = instances[name]
            status = SystemdManager.get_status(inst)

            if status == "active":
                print(f"✓ {name}: healthy (port {inst.port})")
            else:
                print(f"✗ {name}: {status} (port {inst.port})")

    def backup_instance(self, name: str, output: Optional[str] = None) -> bool:
        """Backup instance to archive"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        # Determine output path
        if output is None:
            backup_dir = Path.home() / "openclaw-backups"
            backup_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = str(backup_dir / f"{name}-{timestamp}.tar.gz")

        print(f"Backing up instance '{name}' to {output}...")

        try:
            # Create backup archive
            import tarfile

            with tarfile.open(output, "w:gz") as tar:
                # Add state directory
                if instance.state_dir().exists():
                    tar.add(instance.state_dir(), arcname=f"state")

                # Add config
                if instance.config_path().exists():
                    tar.add(instance.config_path(), arcname="config.json")

                # Add service file
                if instance.service_path().exists():
                    tar.add(instance.service_path(), arcname="service")

                # Add metadata
                metadata = {
                    "name": instance.name,
                    "port": instance.port,
                    "profile": instance.profile,
                    "model": instance.model,
                    "created_at": instance.created_at,
                    "backup_date": datetime.now().isoformat(),
                }
                import io

                metadata_bytes = json.dumps(metadata, indent=2).encode()
                metadata_info = tarfile.TarInfo(name="metadata.json")
                metadata_info.size = len(metadata_bytes)
                tar.addfile(metadata_info, io.BytesIO(metadata_bytes))

            print(f"✓ Backup created: {output}")
            print(f"  Size: {Path(output).stat().st_size / 1024:.1f} KB")
            return True

        except Exception as e:
            print(f"Error creating backup: {e}")
            return False

    def restore_instance(
        self, archive: str, name: Optional[str] = None, force: bool = False
    ) -> bool:
        """Restore instance from archive"""
        archive_path = Path(archive)
        if not archive_path.exists():
            print(f"Error: Archive not found: {archive}")
            return False

        try:
            import tarfile

            with tarfile.open(archive, "r:gz") as tar:
                # Read metadata
                metadata_file = tar.extractfile("metadata.json")
                if metadata_file:
                    metadata = json.load(metadata_file)
                    orig_name = metadata.get("name", "unknown")
                    orig_port = metadata.get("port", BASE_PORT)
                else:
                    print("Error: Invalid backup archive (no metadata)")
                    return False

                # Determine instance name
                restore_name = name if name else orig_name

                # Check if instance exists
                if self.registry.get(restore_name) and not force:
                    print(
                        f"Error: Instance '{restore_name}' already exists. Use --force to overwrite."
                    )
                    return False

                print(f"Restoring instance '{restore_name}' from {archive}...")

                # Delete existing instance if force
                if force and self.registry.get(restore_name):
                    self.delete_instance(restore_name, force=True)

                # Create new instance
                port = self.registry.next_port()
                instance = Instance(
                    name=restore_name,
                    port=port,
                    profile=restore_name,
                    created_at=datetime.now().isoformat(),
                    model=metadata.get("model", ""),
                )

                # Create directories
                instance.state_dir().mkdir(parents=True, exist_ok=True)

                # Extract state to temp location first
                temp_extract = instance.state_dir().parent / f"temp_restore_{name}"
                # Extract state to temp location first
                temp_extract = (
                    instance.state_dir().parent / f"temp_restore_{restore_name}"
                )
                temp_extract.mkdir(exist_ok=True)

                state_members = [
                    m for m in tar.getmembers() if m.name.startswith("state/")
                ]
                for member in state_members:
                    tar.extract(member, path=temp_extract)

                # Move extracted state dir to final location
                extracted = temp_extract / "state"
                if extracted.exists():
                    # Copy contents from extracted state to instance state dir
                    for item in extracted.iterdir():
                        dest = instance.state_dir() / item.name
                        if item.is_dir():
                            shutil.copytree(item, dest, dirs_exist_ok=True)
                        else:
                            shutil.copy2(item, dest)
                    # Cleanup temp
                    shutil.rmtree(temp_extract)

                # Extract config
                for member in tar.getmembers():
                    if member.name == "config.json":
                        config_file = tar.extractfile(member)
                        if config_file:
                            config = json.load(config_file)
                            # Update port in restored config
                            config["gateway"]["port"] = port
                            with open(instance.config_path(), "w") as f:
                                json.dump(config, f, indent=2)
                        break

                # Create systemd service
                SystemdManager.create_service(instance)

                # Register instance
                self.registry.add(instance)

                print(f"✓ Instance '{restore_name}' restored successfully")
                print(f"  Port: {port}")
                print(f"  Config: {instance.config_path()}")
                print(f"  State: {instance.state_dir()}")

                return True

        except Exception as e:
            print(f"Error restoring backup: {e}")
            return False


    def use_instance(self, name: str, args: List[str]) -> bool:
        """Run openclaw command within an instance's context"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        # Build environment with instance-specific variables
        env = os.environ.copy()
        env["OPENCLAW_PROFILE"] = instance.profile
        env["OPENCLAW_CONFIG_PATH"] = str(instance.config_path())
        env["OPENCLAW_STATE_DIR"] = str(instance.state_dir())
        env["OPENCLAW_GATEWAY_PORT"] = str(instance.port)

        # Build command
        cmd = [str(OPENCLAW_BIN)] + args

        print(f"Running in context of '{name}': {' '.join(cmd)}")
        print(f"  Profile: {instance.profile}")
        print(f"  Config: {instance.config_path()}")
        print(f"  State: {instance.state_dir()}")
        print("-" * 50)

        try:
            # Run the command
            result = subprocess.run(
                cmd,
                env=env,
                cwd=str(instance.workspace()),
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Error running command: {e}")
            return False

    def use_interactive(self) -> bool:
        """Enter interactive mode for selected instance"""
        instances = self.registry.get_all()

        if not instances:
            print("No instances found")
            return False

        print("\nSelect an instance:")
        print("-" * 50)
        for i, inst_name in enumerate(sorted(instances.keys()), 1):
            status = SystemdManager.get_status(instances[inst_name])
            print(f"  {i}) {inst_name} (port {instances[inst_name].port}) [{status}]")

        print(f"\n  0) Cancel")

        try:
            choice = input("Enter selection: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled")
            return False

        if choice == "0" or choice == "":
            print("Cancelled")
            return False

        try:
            idx = int(choice)
            if idx < 1 or idx > len(instances):
                print(f"Invalid selection: {choice}")
                return False
            name = sorted(instances.keys())[idx - 1]
        except ValueError:
            if choice not in instances:
                print(f"Instance '{choice}' not found")
                return False
            name = choice

        return self.enter_instance_shell(name)

    def enter_instance_shell(self, name: str) -> bool:
        """Enter interactive shell for an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        print(f"\nEntering interactive mode for '{name}'")
        print("Type 'exit' to quit, 'help' for commands")
        print("-" * 50)

        # Build environment
        env = os.environ.copy()
        env["OPENCLAW_PROFILE"] = instance.profile
        env["OPENCLAW_CONFIG_PATH"] = str(instance.config_path())
        env["OPENCLAW_STATE_DIR"] = str(instance.state_dir())
        env["OPENCLAW_GATEWAY_PORT"] = str(instance.port)

        # Run interactive shell
        try:
            # Use bash with custom prompt
            subprocess.run(
                ["/bin/bash", "--norc", "--noprofile"],
                env=env,
                cwd=str(instance.workspace()),
            )
        except KeyboardInterrupt:
            pass

        return True


def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw Multi-Instance Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create new instance
  %(prog)s create worker1
  
  # Create with specific model
  %(prog)s create worker2 --model openai/gpt-4
  
  # List all instances
  %(prog)s list
  
  # Start/stop instance
  %(prog)s start worker1
  %(prog)s stop worker1
  
  # Enable autostart
  %(prog)s enable worker1
  
  # Edit config
  %(prog)s edit worker1 agent.model openai/gpt-4
  
  # Delete instance
  %(prog)s delete worker1 --force
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create
    create_parser = subparsers.add_parser("create", help="Create new instance")
    create_parser.add_argument("name", help="Instance name")
    create_parser.add_argument(
        "--port", type=int, help="Custom port (auto-assigned if not specified)"
    )
    create_parser.add_argument("--model", help="Default model for instance")

    # Delete
    delete_parser = subparsers.add_parser("delete", help="Delete instance")
    delete_parser.add_argument("name", help="Instance name")
    delete_parser.add_argument("--force", action="store_true", help="Skip confirmation")

    # Edit
    edit_parser = subparsers.add_parser("edit", help="Edit instance config")
    edit_parser.add_argument("name", help="Instance name")
    edit_parser.add_argument("key", help="Config key (dot notation, e.g., agent.model)")
    edit_parser.add_argument("value", help="Config value")

    # List
    list_parser = subparsers.add_parser("list", help="List instances")
    list_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )

    # Start/Stop/Restart
    subparsers.add_parser("start", help="Start instance").add_argument(
        "name", help="Instance name"
    )
    subparsers.add_parser("stop", help="Stop instance").add_argument(
        "name", help="Instance name"
    )
    subparsers.add_parser("restart", help="Restart instance").add_argument(
        "name", help="Instance name"
    )

    # Enable/Disable autostart
    subparsers.add_parser("enable", help="Enable autostart").add_argument(
        "name", help="Instance name"
    )
    subparsers.add_parser("disable", help="Disable autostart").add_argument(
        "name", help="Instance name"
    )

    # Status
    subparsers.add_parser("status", help="Show instance status").add_argument(
        "name", help="Instance name"
    )

    # Logs
    logs_parser = subparsers.add_parser("logs", help="Show instance logs")
    logs_parser.add_argument("name", help="Instance name")
    logs_parser.add_argument(
        "--follow", "-f", action="store_true", help="Follow log output"
    )

    # Health
    subparsers.add_parser("health", help="Health check all instances")

    # Backup/Restore
    backup_parser = subparsers.add_parser("backup", help="Backup instance to archive")
    backup_parser.add_argument("name", help="Instance name")
    backup_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: ~/openclaw-backups/<name>-<timestamp>.tar.gz)",
    )

    restore_parser = subparsers.add_parser(
        "restore", help="Restore instance from archive"
    )
    restore_parser.add_argument("archive", help="Backup archive path")
    restore_parser.add_argument(
        "--name", "-n", help="New instance name (default: from archive)"
    )
    restore_parser.add_argument(
        "--force", action="store_true", help="Overwrite if instance exists"
    )


    # Use - Run openclaw commands in instance context
    use_parser = subparsers.add_parser(
        "use", help="Run openclaw command in instance context"
    )
    use_parser.add_argument("name", help="Instance name")
    use_parser.add_argument("cmd_args", nargs="...", help="OpenClaw command and args")

    # Enter - Interactive shell for instance
    subparsers.add_parser("enter", help="Enter interactive shell for instance")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    manager = OpenClawManager()

    # Handle use command specially (variable args)
    if args.command == "use":
        cmd_args = list(args.cmd_args) if args.cmd_args else []
        success = manager.use_instance(args.name, cmd_args)
        sys.exit(0 if success else 1)
    elif args.command == "enter":
        success = manager.use_interactive()
        sys.exit(0 if success else 1)
    else:
        commands = {
            "create": lambda: manager.create_instance(args.name, args.port, args.model),
            "delete": lambda: manager.delete_instance(args.name, args.force),
            "edit": lambda: manager.edit_instance(args.name, args.key, args.value),
            "list": lambda: manager.list_instances(args.verbose),
            "start": lambda: manager.start_instance(args.name),
            "stop": lambda: manager.stop_instance(args.name),
            "restart": lambda: manager.restart_instance(args.name),
            "enable": lambda: manager.enable_autostart(args.name),
            "disable": lambda: manager.disable_autostart(args.name),
            "status": lambda: manager.status_instance(args.name),
            "logs": lambda: manager.logs_instance(args.name, args.follow),
            "health": lambda: manager.health_check(),
            "backup": lambda: manager.backup_instance(args.name, args.output),
            "restore": lambda: manager.restore_instance(
                args.archive, args.name, args.force
            ),
        }

        if args.command in commands:
            success = commands[args.command]()
            sys.exit(0 if success else 1)
        else:
            parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()
