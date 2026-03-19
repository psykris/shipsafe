# Intentionally vulnerable: unsafe YAML loading
import yaml


def load_config(path):
    with open(path) as f:
        # VULNERABLE: yaml.load() without SafeLoader allows arbitrary code execution
        return yaml.load(f)


def parse_input(data):
    # VULNERABLE: yaml.unsafe_load explicitly bypasses safety checks
    return yaml.unsafe_load(data)


def load_user_config(user_data):
    # VULNERABLE: yaml.load() with user-supplied data
    config = yaml.load(user_data)
    return config
