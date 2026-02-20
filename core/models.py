from pydantic import BaseModel, Field
from typing import Optional, Literal

class ProxyConfig(BaseModel):
    """Базовая модель конфигурации прокси"""
    server: str
    port: int = Field(ge=1, le=65535)
    
    # Common fields
    uuid: Optional[str] = None
    password: Optional[str] = None
    
    # Transport (Добавлены современные типы xhttp и httpupgrade)
    type: Literal["tcp", "ws", "grpc", "xhttp", "httpupgrade"] = "tcp"
    path: str = "/"
    host: Optional[str] = None
    service_name: Optional[str] = None
    
    # Security
    security: Literal["none", "tls", "reality", "auto"] = "none"
    sni: Optional[str] = None
    fp: str = "chrome"
    pbk: Optional[str] = None
    sid: Optional[str] = None
    flow: Optional[str] = None

class ProxyNode(BaseModel):
    """Объект прокси в системе"""
    protocol: Literal["vless", "vmess", "trojan", "ss", "hysteria2"]
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
        """Уникальный отпечаток для защиты от дубликатов"""
        return f"{self.protocol}://{self.config.server}:{self.config.port}"
