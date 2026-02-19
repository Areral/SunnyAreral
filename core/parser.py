import base64
import json
import urllib.parse
from typing import List
import aiohttp
from core.models import ProxyNode, ProxyConfig
from core.logger import logger
from core.settings import CONFIG

class LinkParser:
    @staticmethod
    def decode_base64(s: str) -> str:
        """Умная декодировка Base64 с исправлением паддинга"""
        s = s.strip().replace('-', '+').replace('_', '/')
        return base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', 'ignore')

    @staticmethod
    def parse_vless(line: str) -> ProxyNode | None:
        try:
            # vless://uuid@host:port?query#name
            u = urllib.parse.urlparse(line)
            q = urllib.parse.parse_qs(u.query)
            
            conf = ProxyConfig(
                server=u.hostname,
                port=u.port,
                uuid=u.username,
                type=q.get('type', ['tcp'])[0],
                security=q.get('security', ['none'])[0],
                path=q.get('path', ['/'])[0],
                host=q.get('host', [''])[0],
                sni=q.get('sni', [''])[0],
                fp=q.get('fp', ['chrome'])[0],
                pbk=q.get('pbk', [''])[0],
                sid=q.get('sid', [''])[0],
                flow=q.get('flow', [''])[0],
                service_name=q.get('serviceName', [''])[0]
            )
            return ProxyNode(protocol="vless", config=conf, raw_uri=line)
        except Exception as e:
            # logger.debug(f"Failed to parse VLESS: {e}") # Debug only
            return None

    @staticmethod
    def parse_vmess(line: str) -> ProxyNode | None:
        try:
            # vmess://base64_json
            b64 = line.replace("vmess://", "")
            data = json.loads(LinkParser.decode_base64(b64))
            
            conf = ProxyConfig(
                server=data['add'],
                port=int(data['port']),
                uuid=data['id'],
                type=data.get('net', 'tcp'),
                security="auto", # VMess usually auto handles security
                tls="tls" if data.get('tls') == "tls" else "none",
                path=data.get('path', '/'),
                host=data.get('host', ''),
                sni=data.get('sni', '')
            )
            # Fix VMess specific mapping
            if conf.tls == "tls": conf.security = "tls"
            
            return ProxyNode(protocol="vmess", config=conf, raw_uri=line)
        except: return None

    @staticmethod
    def parse_trojan(line: str) -> ProxyNode | None:
        try:
            u = urllib.parse.urlparse(line)
            q = urllib.parse.parse_qs(u.query)
            conf = ProxyConfig(
                server=u.hostname,
                port=u.port,
                password=u.username,
                security="tls", # Trojan is always TLS
                sni=q.get('sni', [''])[0] or q.get('peer', [''])[0],
                type=q.get('type', ['tcp'])[0],
                path=q.get('path', ['/'])[0],
                host=q.get('host', [''])[0]
            )
            return ProxyNode(protocol="trojan", config=conf, raw_uri=line)
        except: return None

    @staticmethod
    def parse_ss(line: str) -> ProxyNode | None:
        try:
            # ss://base64(method:pass)@host:port
            if '@' not in line: return None
            part1, part2 = line[5:].split('@', 1)
            user_info = LinkParser.decode_base64(part1).split(':')
            if len(user_info) != 2: return None
            
            host_port = part2.split('#')[0].split(':')
            conf = ProxyConfig(
                server=host_port[0],
                port=int(host_port[1]),
                method=user_info[0],
                password=user_info[1],
                type="tcp"
            )
            return ProxyNode(protocol="ss", config=conf, raw_uri=line)
        except: return None
    
    @staticmethod
    def parse_hysteria2(line: str) -> ProxyNode | None:
        try:
            # hy2://password@host:port?sni=...
            u = urllib.parse.urlparse(line)
            q = urllib.parse.parse_qs(u.query)
            
            conf = ProxyConfig(
                server=u.hostname,
                port=u.port,
                password=u.username,
                security="tls",
                sni=q.get('sni', [''])[0],
                type="udp" # Hysteria is UDP based
            )
            return ProxyNode(protocol="hysteria2", config=conf, raw_uri=line)
        except: return None

    async def fetch_and_parse(self) -> List[ProxyNode]:
        nodes = []
        seen = set()
        
        # 1. Сбор ссылок
        sources = []
        if CONFIG.SUBSCRIPTION_SOURCES:
            sources = [s.strip() for s in CONFIG.SUBSCRIPTION_SOURCES.splitlines() if s.strip()]
        elif os.path.exists("config/sources.txt"):
            with open("config/sources.txt", "r") as f:
                sources = [l.strip() for l in f if l.strip()]

        logger.info(f"📥 Загрузка из {len(sources)} источников...")

        async with aiohttp.ClientSession() as session:
            for url in sources:
                try:
                    async with session.get(url, timeout=10) as resp:
                        content = await resp.text()
                        # Если это base64-подписка
                        if "://" not in content[:50]:
                            content = LinkParser.decode_base64(content)
                        
                        for line in content.splitlines():
                            line = line.strip()
                            if not line: continue
                            
                            node = None
                            if line.startswith("vless://"): node = self.parse_vless(line)
                            elif line.startswith("vmess://"): node = self.parse_vmess(line)
                            elif line.startswith("trojan://"): node = self.parse_trojan(line)
                            elif line.startswith("ss://"): node = self.parse_ss(line)
                            elif line.startswith("hy2://"): node = self.parse_hysteria2(line)
                            
                            if node:
                                if node.unique_id not in seen:
                                    nodes.append(node)
                                    seen.add(node.unique_id)
                except Exception as e:
                    logger.warning(f"Ошибка источника {url}: {e}")
        
        logger.success(f"✅ Успешно распарсено: {len(nodes)} уникальных узлов")
        return nodes
