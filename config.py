import yaml
import os

_config = None

def load_config(path="config.yaml"):
    """Load and return config from YAML file."""
    global _config
    if _config is not None:
        return _config

    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r") as f:
        _config = yaml.safe_load(f)

    print(f"[*] Config loaded from {path}")
    return _config

def get(section, key, default=None):
    """Get a config value by section and key."""
    cfg = load_config()
    return cfg.get(section, {}).get(key, default)