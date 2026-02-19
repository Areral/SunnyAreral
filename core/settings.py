import os
import yaml
from pydantic_settings import BaseSettings
from typing import List, Optional

class AppSettings(BaseSettings):
    # Telegram Secrets (Auto-loaded from Env)
    TG_BOT_TOKEN: Optional[str] = None
    TG_CHAT_ID: Optional[str] = None
    TG_TOPIC_ID: Optional[str] = None
    
    # Sources (Auto-loaded from Env)
    SUBSCRIPTION_SOURCES: Optional[str] = None

    # Config structure matches YAML
    system: dict
    checking: dict
    app: dict

    @classmethod
    def load(cls):
        # Load YAML
        config_path = "config/settings.yaml"
        with open(config_path, "r") as f:
            yaml_config = yaml.safe_load(f)
        
        # Load Env Vars & Merge
        return cls(**yaml_config)

# Global Instance
CONFIG = AppSettings.load()
