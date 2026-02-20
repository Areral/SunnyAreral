from pydantic import BaseModel, Field
from typing import Optional, Literal

class ProxyConfig(BaseModel):
    """Базовая модель конфигурации прокси"""
    server: str
    port: int = Field(ge=1, le=65535)
    
    # Common fields (ИСПРАВЛЕНО: добавлено)
    uuid: Optional = None
    password: Optional = None
    method: Optional = None
    
    # Transport (ИСПРАВЛЕНО: добавлены все типы)
    type: Literal = "tcp"
    path: str = "/"
    host: Optional = None
    service_name: Optional = None
    
    # Security (ИСПРАВЛЕНО)
    security: Literal = "none"
    sni: Optional = None
    fp: str = "chrome"
    pbk: Optional = None
    sid: Optional = None
    flow: Optional = None
    spx: Optional = None

class ProxyNode(BaseModel):
    """Объект прокси в системе"""
    protocol: Literal
    config: ProxyConfig
    raw_uri: str
    
    # Dynamic Stats
    country: str = "UN"
    city: str = ""
    speed: float = 0.0
    latency: int = 0
    is_alive: bool = False

    @property
    def unique_id(self) -> str:
        """Умный отпечаток (Fingerprint) для дедупликации"""
        uid = f"{self.protocol}://{self.config.server}:{self.config.port}"
        if self.config.uuid:
            uid += f"@{self.config.uuid}"
        elif self.config.password:
            uid += f"@{self.config.password}"
            
        if self.config.path and self.config.path != "/":
            uid += f"{self.config.path}"
            
        if self.config.service_name:
            uid += f"?svc={self.config.service_name}"
            
        return uid
