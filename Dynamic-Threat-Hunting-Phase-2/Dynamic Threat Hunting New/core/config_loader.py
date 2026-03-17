"""
Configuration Loader.

Loads config from config/config.yaml and provides helper functions
for accessing nested configuration values.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


_config_cache: dict | None = None


def get_config(config_path: str | None = None) -> dict:
    """
    Load and cache the configuration from YAML.

    Args:
        config_path: Path to config file. Defaults to config/config.yaml
                     relative to the project root.

    Returns:
        Configuration dictionary.
    """
    global _config_cache

    if _config_cache is not None and config_path is None:
        return _config_cache

    if config_path is None:
        # Find project root (where config/ directory lives)
        project_root = Path(__file__).parent.parent
        config_path = str(project_root / "config" / "config.yaml")

    if not os.path.exists(config_path):
        # Return sensible defaults if no config file
        _config_cache = _default_config()
        return _config_cache

    with open(config_path, "r") as f:
        _config_cache = yaml.safe_load(f)

    return _config_cache


def get_nested(config: dict, *keys: str, default: Any = None) -> Any:
    """
    Safely access nested config values.

    Args:
        config: Configuration dictionary.
        *keys: Chain of keys to traverse.
        default: Value to return if any key is missing.

    Returns:
        The nested value, or default if not found.

    Example:
        get_nested(cfg, "simulation", "num_vehicles", default=25)
    """
    current = config
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def reload_config() -> dict:
    """Force reload configuration from disk."""
    global _config_cache
    _config_cache = None
    return get_config()


def _default_config() -> dict:
    """Return sensible defaults when no config file exists."""
    return {
        "simulation": {
            "num_vehicles": 25,
            "num_steps": 300,
            "dt": 0.1,
            "seed": 42,
        },
        "rsu": {
            "position_x": 500.0,
            "position_y": 500.0,
            "max_cpu_pct": 100.0,
            "base_memory_mb": 256.0,
        },
        "v2x": {
            "communication_range_m": 300.0,
            "packet_loss_rate": 0.02,
            "max_latency_ms": 50.0,
            "bsm_interval_ms": 100.0,
        },
        "threats": {
            "poisoning_start_step": 30,
            "ghost_start_step": 80,
            "sponge_start_step": 150,
        },
        "detection": {
            "gcl_threshold": 0.5,
            "ood_energy_threshold": -5.0,
            "agent_confidence_threshold": 0.7,
        },
    }
