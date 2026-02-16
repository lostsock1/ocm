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
import urllib.request
import ssl
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

    def update_port_counter(self, value: int):
        self._data["port_counter"] = value
        self._save()

    def get_port_counter(self) -> int:
        return self._data.get("port_counter", 0)


class PortManager:
    """Manages port allocation for instances"""

    def __init__(self, registry: Registry):
        self.registry = registry

    def allocate_port(self) -> int:
        """Allocate next available port"""
        used_ports = {instance.port for instance in self.registry.get_all().values()}
        counter = self.registry.get_port_counter()

        while True:
            port = BASE_PORT + (counter * PORT_INCREMENT)
            if port not in used_ports:
                self.registry.update_port_counter(counter + 1)
                return port
            counter += 1

    def get_port_for_instance(self, name: str) -> int:
        """Get or allocate port for instance"""
        instance = self.registry.get(name)
        if instance:
            return instance.port
        return self.allocate_port()


class ConfigInheritor:
    """Handles configuration inheritance from main instance"""

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
        """Extract settings that should be inherited by new instances"""
        inherited = {}

        # Inherit agent defaults (models)
        if "agents" in config and "defaults" in config["agents"]:
            defaults = config["agents"]["defaults"]
            inherited["agents"] = {"defaults": {}}

            # Copy model configuration
            if "model" in defaults:
                inherited["agents"]["defaults"]["model"] = defaults["model"]
            if "models" in defaults:
                inherited["agents"]["defaults"]["models"] = defaults["models"]

        # Inherit providers (without sensitive data like API keys)
        if "providers" in config:
            inherited["providers"] = {}
            for provider_name, provider_config in config["providers"].items():
                # Only copy safe provider settings (not API keys)
                if "baseUrl" in provider_config:
                    inherited["providers"][provider_name] = {
                        "baseUrl": provider_config["baseUrl"],
                        "api": provider_config.get("api", "openai"),
                    }

        # Inherit models configuration
        if "models" in config:
            inherited["models"] = config["models"]

        return inherited

    TEMPLATE_PATH = Path.home() / ".openclaw" / "openclaw.json.templ"

    @classmethod
    def create_instance_config(
        cls, name: str, port: int, model: Optional[str] = None
    ) -> dict:
        """Create new instance config using template or inheriting from main"""
        # First try to load the template file
        if cls.TEMPLATE_PATH.exists():
            try:
                with open(cls.TEMPLATE_PATH, "r") as f:
                    new_config = json.load(f)
                print(f"  Using template: {cls.TEMPLATE_PATH}")
            except Exception as e:
                print(f"  Warning: Failed to load template, using defaults: {e}")
                new_config = {}
        else:
            new_config = {}

        # Build instance-specific overrides
        instance_meta = {
            "lastTouchedVersion": "2026.2.15",
            "lastTouchedAt": datetime.now().isoformat() + "Z",
        }

        instance_gateway = {
            "mode": "local",
            "port": port,
            "bind": "loopback",
            "auth": {"mode": "token", "token": os.urandom(24).hex()},
        }

        instance_agents_defaults = {
            "workspace": str(Path.home() / f".openclaw-{name}" / "workspace"),
            "compaction": {"mode": "safeguard"},
            "maxConcurrent": 4,
            "subagents": {"maxConcurrent": 8},
            "sandbox": {
                "mode": "non-main",
                "scope": "agent",
                "workspaceAccess": "rw"
            },
        }

        # If model is specified, set it as primary
        if model:
            instance_agents_defaults["model"] = {"primary": model}

        # Deep merge the instance-specific settings
        # Update meta
        if "meta" not in new_config:
            new_config["meta"] = {}
        new_config["meta"].update(instance_meta)

        # Update gateway
        if "gateway" not in new_config:
            new_config["gateway"] = {}
        new_config["gateway"].update(instance_gateway)

        # Update agents defaults
        if "agents" not in new_config:
            new_config["agents"] = {}
        if "defaults" not in new_config["agents"]:
            new_config["agents"]["defaults"] = {}
        new_config["agents"]["defaults"].update(instance_agents_defaults)

        # Add session security settings
        if "session" not in new_config:
            new_config["session"] = {}
        new_config["session"]["dmScope"] = "per-channel-peer"


        # If no template was used, try to inherit from main config
        if not cls.TEMPLATE_PATH.exists():
            main_config = cls.load_main_config()
            inherited = cls.extract_inheritable(main_config)
            new_config.update(inherited)

        # Clean up old 'agent' key if we have new 'agents' structure
        if "agent" in new_config and "agents" in new_config:
            if (
                "defaults" in new_config["agents"]
                and "model" in new_config["agents"]["defaults"]
            ):
                del new_config["agent"]

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

# STRICT ISOLATION: Instance can only access its own files
ProtectSystem=strict
# ProtectHome disabled for user service

# Read-Write: Only instance state directory and temp
ReadWritePaths={state_dir} /tmp /var/tmp

# Read-Only: Only this instance config file (bind-mounted)
BindPaths={config_path}:{config_path}

PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false

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
            node_path = cls._get_node_path()
            path_env = cls._get_path_env()
            home = str(Path.home())

            service_content = cls.SERVICE_TEMPLATE.format(
                name=instance.name,
                node_path=node_path,
                openclaw_path=str(OPENCLAW_BIN),
                profile=instance.name,
                port=instance.port,
                home=home,
                path=path_env,
                state_dir=str(instance.state_dir()),
                config_path=str(instance.config_path()),
            )

            # Write service file
            instance.service_path().write_text(service_content)

            # Set permissions
            os.chmod(instance.service_path(), 0o644)

            # Reload systemd
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)

            return True

        except Exception as e:
            print(f"  Error creating service: {e}")
            return False

    @classmethod
    def start_service(cls, instance: Instance) -> bool:
        """Start the systemd service"""
        try:
            result = subprocess.run(
                ["systemctl", "--user", "start", instance.service_name()],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception as e:
            print(f"  Error starting service: {e}")
            return False

    @classmethod
    def stop_service(cls, instance: Instance) -> bool:
        """Stop the systemd service"""
        try:
            result = subprocess.run(
                ["systemctl", "--user", "stop", instance.service_name()],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception as e:
            print(f"  Error stopping service: {e}")
            return False

    @classmethod
    def enable_service(cls, instance: Instance) -> bool:
        """Enable service to start on boot"""
        try:
            result = subprocess.run(
                ["systemctl", "--user", "enable", instance.service_name()],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception as e:
            print(f"  Error enabling service: {e}")
            return False

    @classmethod
    def disable_service(cls, instance: Instance) -> bool:
        """Disable service from starting on boot"""
        try:
            result = subprocess.run(
                ["systemctl", "--user", "disable", instance.service_name()],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception as e:
            print(f"  Error disabling service: {e}")
            return False

    @classmethod
    def get_service_status(cls, instance: Instance) -> str:
        """Get service status"""
        try:
            result = subprocess.run(
                ["systemctl", "--user", "is-active", instance.service_name()],
                capture_output=True,
                text=True,
            )
            return result.stdout.strip() if result.returncode == 0 else "inactive"
        except Exception:
            return "unknown"

    @classmethod
    def remove_service(cls, instance: Instance) -> bool:
        """Remove systemd service file"""
        try:
            # Stop and disable first
            cls.stop_service(instance)
            cls.disable_service(instance)

            # Remove service file
            if instance.service_path().exists():
                instance.service_path().unlink()

            # Reload systemd
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)

            return True

        except Exception as e:
            print(f"  Error removing service: {e}")
            return False


class OpenClawManager:
    """Main manager class for OpenClaw instances"""

    def __init__(self):
        self.registry = Registry()
        self.port_manager = PortManager(self.registry)
        self.config_inheritor = ConfigInheritor()

    def create_instance(
        self, name: str, model: Optional[str] = None, autostart: bool = False
    ) -> bool:
        """Create a new OpenClaw instance"""
        print(f"Creating instance '{name}'...")

        # Validate name
        if not re.match(r"^[a-zA-Z0-9_-]+$", name):
            print("  Error: Name must contain only alphanumeric characters, hyphens, and underscores")
            return False

        # Check if instance already exists
        if self.registry.get(name):
            print(f"  Error: Instance '{name}' already exists")
            return False

        # Allocate port
        port = self.port_manager.allocate_port()
        print(f"  Allocated port: {port}")

        try:
            # Create instance object
            instance = Instance(
                name=name,
                port=port,
                profile=name,
                created_at=datetime.now().isoformat(),
                autostart=autostart,
                status="stopped",
                model=model or "",
            )

            # Create state directory
            instance.state_dir().mkdir(parents=True, exist_ok=True)
            (instance.state_dir() / "workspace").mkdir(exist_ok=True)
            (instance.state_dir() / "agents").mkdir(exist_ok=True)
            (instance.state_dir() / "agents" / "main").mkdir(exist_ok=True)
            (instance.state_dir() / "agents" / "main" / "sessions").mkdir(exist_ok=True)

            # Set permissions
            os.chmod(instance.state_dir(), 0o700)

            # Create config
            config = ConfigInheritor.create_instance_config(name, port, model)

            # Write config file
            with open(instance.config_path(), "w") as f:
                json.dump(config, f, indent=2)

            # Set config file permissions
            os.chmod(instance.config_path(), 0o600)
            print(f"  Config: {instance.config_path()}")

            # Create systemd service
            if not SystemdManager.create_service(instance):
                print("  Error: Failed to create systemd service")
                # Cleanup
                shutil.rmtree(instance.state_dir(), ignore_errors=True)
                if instance.config_path().exists():
                    instance.config_path().unlink()
                return False

            print(f"  Service: {instance.service_path()}")

            # Add to registry
            self.registry.add(instance)

            # Enable autostart if requested
            if autostart:
                SystemdManager.enable_service(instance)
                print("  Autostart: enabled")

            print(f"✓ Instance '{name}' created successfully")
            print(f"  Port: {port}")
            print(f"  Start with: ocm start {name}")

            return True

        except Exception as e:
            print(f"  Error creating instance: {e}")
            # Cleanup on error
            try:
                shutil.rmtree(instance.state_dir(), ignore_errors=True)
                if instance.config_path().exists():
                    instance.config_path().unlink()
            except:
                pass
            return False

    def delete_instance(self, name: str, force: bool = False) -> bool:
        """Delete an OpenClaw instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        # Check if running
        if SystemdManager.get_service_status(instance) == "active":
            if not force:
                print(f"Error: Instance '{name}' is running. Stop it first or use --force")
                return False
            print(f"Stopping running instance '{name}'...")
            self.stop_instance(name)

        print(f"Deleting instance '{name}'...")

        try:
            # Remove systemd service
            SystemdManager.remove_service(instance)

            # Remove state directory
            if instance.state_dir().exists():
                shutil.rmtree(instance.state_dir())
                print(f"  Removed: {instance.state_dir()}")

            # Remove config file
            if instance.config_path().exists():
                instance.config_path().unlink()
                print(f"  Removed: {instance.config_path()}")

            # Remove workspace link
            workspace_link = Path.home() / ".openclaw" / f"workspace-{name}"
            if workspace_link.exists():
                workspace_link.unlink()
                print(f"  Removed: {workspace_link}")

            # Remove from registry
            self.registry.remove(name)

            print(f"✓ Instance '{name}' deleted successfully")
            return True

        except Exception as e:
            print(f"  Error deleting instance: {e}")
            return False

    def start_instance(self, name: str) -> bool:
        """Start an OpenClaw instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        print(f"Starting instance '{name}'...")

        if SystemdManager.start_service(instance):
            instance.status = "active"
            self.registry.add(instance)
            print(f"✓ Instance '{name}' started")
            return True
        else:
            print(f"✗ Failed to start instance '{name}'")
            return False

    def stop_instance(self, name: str) -> bool:
        """Stop an OpenClaw instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        print(f"Stopping instance '{name}'...")

        if SystemdManager.stop_service(instance):
            instance.status = "stopped"
            self.registry.add(instance)
            print(f"✓ Instance '{name}' stopped")
            return True
        else:
            print(f"✗ Failed to stop instance '{name}'")
            return False

    def restart_instance(self, name: str) -> bool:
        """Restart an OpenClaw instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        print(f"Restarting instance '{name}'...")
        self.stop_instance(name)
        return self.start_instance(name)

    def list_instances(self) -> None:
        """List all instances"""
        instances = self.registry.get_all()

        if not instances:
            print("No instances found")
            return

        print(f"{'Instance':<15} {'Port':<8} {'Status':<10} {'Autostart':<10} {'Model'}")
        print("-" * 70)

        for name, instance in sorted(instances.items()):
            status = SystemdManager.get_service_status(instance)
            autostart = "enabled" if instance.autostart else "disabled"
            model = instance.model or "default"
            print(f"{name:<15} {instance.port:<8} {status:<10} {autostart:<10} {model}")

    def show_status(self, name: str) -> None:
        """Show detailed status of an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return

        status = SystemdManager.get_service_status(instance)

        print(f"\nInstance: {instance.name}")
        print(f"Port: {instance.port}")
        print(f"Profile: {instance.profile}")
        print(f"Service Status: {status}")
        print(f"Autostart: {'enabled' if instance.autostart else 'disabled'}")
        print(f"Created: {instance.created_at}")
        print(f"\nPaths:")
        print(f"  Config: {instance.config_path()}")
        print(f"  State:  {instance.state_dir()}")
        print(f"  Service: {instance.service_path()}")

        if status == "active":
            print(f"\n  Access: http://localhost:{instance.port}")

    def enable_autostart(self, name: str) -> bool:
        """Enable autostart for an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        if SystemdManager.enable_service(instance):
            instance.autostart = True
            self.registry.add(instance)
            print(f"✓ Autostart enabled for '{name}'")
            return True
        else:
            print(f"✗ Failed to enable autostart for '{name}'")
            return False

    def disable_autostart(self, name: str) -> bool:
        """Disable autostart for an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        if SystemdManager.disable_service(instance):
            instance.autostart = False
            self.registry.add(instance)
            print(f"✓ Autostart disabled for '{name}'")
            return True
        else:
            print(f"✗ Failed to disable autostart for '{name}'")
            return False

    def edit_config(self, name: str, key: str, value: str) -> bool:
        """Edit instance configuration"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        try:
            # Load config
            with open(instance.config_path(), "r") as f:
                config = json.load(f)

            # Parse key path (e.g., "agents.defaults.model")
            keys = key.split(".")
            current = config

            for k in keys[:-1]:
                if k not in current:
                    current[k] = {}
                current = current[k]

            # Set value
            try:
                # Try to parse as JSON for complex values
                current[keys[-1]] = json.loads(value)
            except json.JSONDecodeError:
                # Use as string
                current[keys[-1]] = value

            # Save config
            with open(instance.config_path(), "w") as f:
                json.dump(config, f, indent=2)

            print(f"✓ Updated {key} = {value}")
            return True

        except Exception as e:
            print(f"  Error editing config: {e}")
            return False

    def show_logs(self, name: str, follow: bool = False) -> None:
        """Show logs for an instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return

        cmd = ["journalctl", "--user", "-u", instance.service_name()]
        if follow:
            cmd.append("-f")
        else:
            cmd.extend(["-n", "50"])

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass

    def use_instance(self, name: str, args: List[str]) -> bool:
        """Run openclaw command with instance profile"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        # Check if running
        if SystemdManager.get_service_status(instance) != "active":
            print(f"Error: Instance '{name}' is not running")
            print(f"Start it with: ocm start {name}")
            return False

        # Build command
        cmd = [str(OPENCLAW_BIN), f"--profile={name}"] + args

        try:
            result = subprocess.run(cmd)
            return result.returncode == 0
        except Exception as e:
            print(f"Error running command: {e}")
            return False

    def enter_instance_shell(self, name: str) -> bool:
        """Enter interactive shell for instance"""
        instance = self.registry.get(name)
        if not instance:
            print(f"Error: Instance '{name}' not found")
            return False

        # Check if running
        if SystemdManager.get_service_status(instance) != "active":
            print(f"Error: Instance '{name}' is not running")
            print(f"Start it with: ocm start {name}")
            return False

        print(f"Entering interactive shell for '{name}'...")
        print(f"Profile: {name}")
        print(f"Port: {instance.port}")
        print(f"Workspace: {instance.workspace()}")
        print("")
        print("Available commands:")
        print(f"  openclaw --profile {name} <command>")
        print("")

        # Set up environment
        env = os.environ.copy()
        env["OPENCLAW_PROFILE"] = name
        env["OPENCLAW_GATEWAY_PORT"] = str(instance.port)

        # Start shell
        shell = os.environ.get("SHELL", "/bin/bash")
        try:
            subprocess.run(
                [shell],
                cwd=str(instance.workspace()),
                env=env,
            )
            return True
        except Exception as e:
            print(f"Error starting shell: {e}")
            return False

    def health_check(self) -> None:
        """Check health of all instances"""
        instances = self.registry.get_all()

        if not instances:
            print("No instances to check")
            return

        print("\nHealth Check:")
        print("-" * 50)

        for name, instance in sorted(instances.items()):
            status = SystemdManager.get_service_status(instance)

            if status == "active":
                # Try to connect to port
                import socket

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex(("localhost", instance.port))
                    sock.close()

                    if result == 0:
                        print(f"✓ {name}: healthy (port {instance.port})")
                    else:
                        print(f"⚠ {name}: running but port {instance.port} not responding")
                except Exception as e:
                    print(f"⚠ {name}: error checking port - {e}")
            else:
                print(f"✗ {name}: not running (expected: port {instance.port})")

    def deploy_instance(self, name: str, model: Optional[str] = None) -> bool:
        """One-step deployment: create, start, and verify an instance"""
        print(f"Deploying instance '{name}'...")
        print()

        # Step 1: Create
        if not self.create_instance(name, model, autostart=True):
            print("\n✗ Deployment failed at creation step")
            return False

        print()

        # Step 2: Start
        if not self.start_instance(name):
            print("\n✗ Deployment failed at start step")
            return False

        # Step 3: Wait for service
        print("Waiting for service to be ready...")
        import time

        for i in range(10):
            time.sleep(1)
            status = SystemdManager.get_service_status(self.registry.get(name))
            if status == "active":
                break

        # Step 4: Verify
        print("\nVerifying deployment...")
        self.health_check()

        instance = self.registry.get(name)
        if instance and SystemdManager.get_service_status(instance) == "active":
            print(f"\n✓ Instance '{name}' deployed successfully!")
            print(f"  Access: http://localhost:{instance.port}")
            print(f"  Profile: {name}")
            return True
        else:
            print(f"\n⚠ Instance '{name}' created but may not be fully ready")
            print(f"  Check status with: ocm status {name}")
            return False


class PPQModelUpdater:
    """Updates model configurations from PPQ AI API"""

    API_URL = "https://api.ppq.ai/v1/models"

    @classmethod
    def fetch_models(cls) -> Optional[dict]:
        """Fetch available models from PPQ AI"""
        print("Fetching models from PPQ AI...")

        try:
            # Create SSL context that doesn't verify certificates (for compatibility)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                cls.API_URL,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "OCM/1.0",
                },
            )

            with urllib.request.urlopen(req, context=ssl_context, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))
                return data

        except Exception as e:
            print(f"  Error fetching models: {e}")
            return None

    @classmethod
    def update_main_config(cls) -> bool:
        """Update main instance config with PPQ models"""
        models_data = cls.fetch_models()
        if not models_data:
            return False

        main_config_path = Path.home() / ".openclaw" / "openclaw.json"

        try:
            # Load existing config
            if main_config_path.exists():
                with open(main_config_path, "r") as f:
                    config = json.load(f)
            else:
                config = {}

            # Update models section
            if "models" not in config:
                config["models"] = {}

            # Add PPQ provider models
            config["models"]["providers"] = {
                "custom-api-ppq-ai": {
                    "baseUrl": "https://api.ppq.ai",
                    "apiKey": "${PPQ_API_KEY}",
                    "api": "openai-completions",
                    "models": [],
                }
            }

            # Parse and add models
            if "data" in models_data:
                for model in models_data["data"]:
                    model_entry = {
                        "id": model.get("id", ""),
                        "name": model.get("name", ""),
                        "contextWindow": model.get("context_length", 8192),
                    }
                    config["models"]["providers"]["custom-api-ppq-ai"][
                        "models"
                    ].append(model_entry)

            # Save config
            with open(main_config_path, "w") as f:
                json.dump(config, f, indent=2)

            print(f"✓ Updated {len(models_data.get('data', []))} models in {main_config_path}")
            return True

        except Exception as e:
            print(f"  Error updating config: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw Multi-Instance Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick deploy (create + start + test)
  ocm deploy worker1
  ocm deploy worker2 --model custom-api-ppq-ai/gpt-5.1

  # Create new instance
  ocm create worker1

  # Create with specific model
  ocm create worker2 --model openai/gpt-4

  # List all instances
  ocm list

  # Start/stop instance
  ocm start worker1
  ocm stop worker1

  # Enable autostart
  ocm enable worker1

  # Edit config
  ocm edit worker1 agent.model openai/gpt-4

  # Delete instance
  ocm delete worker1 --force

  # Run openclaw command in instance context
  ocm use worker1 agent --agent main --message "Hello"

  # Interactive shell
  ocm enter worker1
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Deploy (one-step create + start + verify)
    deploy_parser = subparsers.add_parser(
        "deploy", help="Create, start, and verify an instance (one-step deployment)"
    )
    deploy_parser.add_argument("name", help="Instance name")
    deploy_parser.add_argument("--model", help="Primary model to use")

    # Create
    create_parser = subparsers.add_parser("create", help="Create new instance")
    create_parser.add_argument("name", help="Instance name")
    create_parser.add_argument("--model", help="Primary model to use")
    create_parser.add_argument(
        "--autostart", action="store_true", help="Enable autostart"
    )

    # Delete
    delete_parser = subparsers.add_parser("delete", help="Delete instance")
    delete_parser.add_argument("name", help="Instance name")
    delete_parser.add_argument("--force", action="store_true", help="Force delete if running")

    # List
    subparsers.add_parser("list", help="List all instances")

    # Start/Stop/Restart
    subparsers.add_parser("start", help="Start instance").add_argument("name", help="Instance name")
    subparsers.add_parser("stop", help="Stop instance").add_argument("name", help="Instance name")
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
    status_parser = subparsers.add_parser("status", help="Show instance status")
    status_parser.add_argument("name", help="Instance name")

    # Logs
    logs_parser = subparsers.add_parser("logs", help="Show instance logs")
    logs_parser.add_argument("name", help="Instance name")
    logs_parser.add_argument("-f", "--follow", action="store_true", help="Follow logs")

    # Health check
    subparsers.add_parser("health", help="Health check all instances")

    # Edit
    edit_parser = subparsers.add_parser("edit", help="Edit instance config")
    edit_parser.add_argument("name", help="Instance name")
    edit_parser.add_argument("key", help="Config key (e.g., agents.defaults.model)")
    edit_parser.add_argument("value", help="Config value")

    # Use
    use_parser = subparsers.add_parser(
        "use", help="Run openclaw command in instance context"
    )
    use_parser.add_argument("name", help="Instance name")
    use_parser.add_argument("args", nargs=argparse.REMAINDER, help="Command arguments")

    # Enter
    enter_parser = subparsers.add_parser("enter", help="Enter interactive shell for instance")
    enter_parser.add_argument("name", help="Instance name")

    # Update models
    subparsers.add_parser("update-models", help="Fetch and update models from PPQ AI")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    manager = OpenClawManager()

    if args.command == "deploy":
        manager.deploy_instance(args.name, args.model)

    elif args.command == "create":
        manager.create_instance(args.name, args.model, args.autostart)

    elif args.command == "delete":
        manager.delete_instance(args.name, args.force)

    elif args.command == "list":
        manager.list_instances()

    elif args.command == "start":
        manager.start_instance(args.name)

    elif args.command == "stop":
        manager.stop_instance(args.name)

    elif args.command == "restart":
        manager.restart_instance(args.name)

    elif args.command == "enable":
        manager.enable_autostart(args.name)

    elif args.command == "disable":
        manager.disable_autostart(args.name)

    elif args.command == "status":
        manager.show_status(args.name)

    elif args.command == "logs":
        manager.show_logs(args.name, args.follow)

    elif args.command == "health":
        manager.health_check()

    elif args.command == "edit":
        manager.edit_config(args.name, args.key, args.value)

    elif args.command == "use":
        manager.use_instance(args.name, args.args)

    elif args.command == "enter":
        manager.enter_instance_shell(args.name)

    elif args.command == "update-models":
        PPQModelUpdater.update_main_config()


if __name__ == "__main__":
    main()
