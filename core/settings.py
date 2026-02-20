import os
import yaml
from pydantic_settings import BaseSettings
from typing import Optional

class AppSettings(BaseSettings):
    TG_BOT_TOKEN: Optional[str] = None
    TG_CHAT_ID: Optional[str] = None
    TG_TOPIC_ID: Optional[str] = None
    SUBSCRIPTION_SOURCES: Optional[str] = None

    system: dict
    checking: dict
    app: dict
    
    # НОВАЯ НАСТРОЙКА: Размер пакета (сколько прокси проверять за 1 запуск sing-box)
    # 50 - оптимально для GitHub Actions (не забивает порты)
    BATCH_SIZE: int = 50 

    @classmethod
    def load(cls):
        config_path = "config/settings.yaml"
        if not os.path.exists(config_path):
            # Fallback defaults if file missing
            return cls(
                system={"threads": 20, "tcp_timeout": 4, "http_timeout": 20},
                checking={"min_speed": 2.5, "speedtest_url": "", "connectivity_urls": []},
                app={"public_url": "", "template_path": ""}
            )
            
        with open(config_path, "r") as f:
            yaml_config = yaml.safe_load(f)
        return cls(**yaml_config)

CONFIG = AppSettings.load()
