from pydantic import BaseModel, Field
from typing import Optional, Literal

class ProxyConfig(BaseModel):
    """
    Базовая модель конфигурации прокси.
    Описывает все возможные параметры для Sing-box конфига.
    """
    server: str
    port: int = Field(ge=1, le=65535)
    
    # Авторизация (VLESS/VMess -> uuid, Trojan/SS/Hysteria -> password)
    uuid: Optional[str] = None
    password: Optional[str] = None
    method: Optional[str] = None  # Для Shadowsocks
    
    # Транспорт (Добавлены современные типы xhttp и httpupgrade)
    type: Literal["tcp", "ws", "grpc", "xhttp", "httpupgrade"] = "tcp"
    path: str = "/"
    host: Optional[str] = None
    service_name: Optional[str] = None
    
    # Безопасность (TLS / Reality)
    security: Literal["none", "tls", "reality", "auto"] = "none"
    sni: Optional[str] = None
    fp: str = "chrome"
    pbk: Optional[str] = None  # Reality Public Key
    sid: Optional[str] = None  # Reality Short ID
    flow: Optional[str] = None # XTLS Flow (Vision)

class ProxyNode(BaseModel):
    """
    Объект узла в системе.
    Хранит конфиг и динамические метрики после проверки.
    """
    protocol: Literal["vless", "vmess", "trojan", "ss", "hysteria2"]
    config: ProxyConfig
    raw_uri: str
    
    # Динамические метрики (заполняются после теста)
    country: str = "UN"
    city: str = ""
    speed: float = 0.0
    latency: int = 0
    is_alive: bool = False

    @property
    def unique_id(self) -> str:
        """
        Умный отпечаток (Fingerprint) для дедупликации.
        
        Логика:
        1. Если IP и Порт одинаковые, но разные UUID/Пароли -> Это РАЗНЫЕ прокси (оставляем оба).
        2. Если всё одинаковое, но разные пути (Path/ServiceName) -> Это РАЗНЫЕ прокси.
        3. Если совпадают IP, Порт, Учетка и Путь -> Это ДУБЛИКАТ (удаляем).
        """
        # База: Протокол://IP:Port
        uid = f"{self.protocol}://{self.config.server}:{self.config.port}"
        
        # Добавляем учетные данные (UUID или Пароль)
        if self.config.uuid:
            uid += f"@{self.config.uuid}"
        elif self.config.password:
            uid += f"@{self.config.password}"
            
        # Добавляем транспортные параметры (важно для CDN/WS)
        # Если путь отличается от стандартного "/", добавляем его в ID
        if self.config.path and self.config.path != "/":
            uid += f"{self.config.path}"
            
        # Для gRPC важно имя сервиса
        if self.config.service_name:
            uid += f"?svc={self.config.service_name}"
            
        return uid
