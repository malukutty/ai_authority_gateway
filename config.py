import os
from dotenv import load_dotenv

# Load variables from .env into the process environment
load_dotenv()


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


KILL_SWITCH = env_bool("KILL_SWITCH", default=False)
DENY_PROD = env_bool("DENY_PROD", default=False)
