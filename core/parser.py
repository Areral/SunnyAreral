import base64
import json
import urllib.parse
import ipaddress
import os
import re
import html
from typing import List
import aiohttp
from core.models import ProxyNode, ProxyConfig
from core.logger import logger
from core.settings import CONFIG

class LinkParser:
    @staticmethod
    def decode_base64(s: str) -> str:
        try:
            s = s.strip().replace('-', '+').replace('_', '/')
            s = re.sub(r'\s+', '', s)
            padded = s + '=' * (-len(s) % 4)
            ascii_bytes = padded.encode('ascii', 'ignore')
            return base64.b64decode(ascii_bytes).decode('utf-8', 'ignore')
        except Exception:
            return s

    @staticmethod
    def is_valid_host(host: str) -> bool:
        if host.lower() in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]: 
            return False
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_global
        except ValueError:
            return True 

    @staticmethod
    def parse_vless(line: str) -> ProxyNode | None:
        try:
            line = html.unescape(line)
            line = line.replace("/?", "?")
            u = urllib.parse.urlparse(line)
            q = urllib.parse.parse_qs(u.query)
            
            host = u.hostname
            if not host or not LinkParser.is_valid_host(host): return None
            if not u.port: return None

            conf = ProxyConfig(
                server=host,
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
                service_name=q.get('serviceName', [''])[0],
                spx=q.get('spx', [''])[0]
            )
            return ProxyNode(protocol="vless", config=conf, raw_uri=line)
        except Exception: return None

    @staticmethod
    def parse_vmess(line: str) -> ProxyNode | None:
        try:
            b64 = line.replace("vmess://", "")
            data = json.loads(LinkParser.decode_base64(b64))
            
            host = data.get('add')
            if not host or not LinkParser.is_valid_host(host): return None
            if not data.get('port'): return None
            
            conf = ProxyConfig(
                server=host,
                port=int(data.get('port')),
                uuid=data.get('id'),
                type=data.get('net', 'tcp'),
                security="auto",
                tls="tls" if data.get('tls') == "tls" else "none",
                path=data.get('path', '/'),
                host=data.get('host', ''),
                sni=data.get('sni', '')
            )
            if conf.tls == "tls": conf.security = "tls"
            return ProxyNode(protocol="vmess", config=conf, raw_uri=line)
        except Exception: return None

    @staticmethod
    def parse_trojan(line: str) -> ProxyNode | None:
        try:
            line = html.unescape(line).replace("/?", "?")
            u = urllib.parse.urlparse(line)
            q = urllib.parse.parse_qs(u.query)
            
            host = u.hostname
            if not host or not LinkParser.is_valid_host(host): return None
            if not u.port: return None

            conf = ProxyConfig(
                server=host,
                port=u.port,
                password=u.username,
                security="tls",
                sni=q.get('sni', [''])[0] or q.get('peer', [''])[0],
                type=q.get('type', ['tcp'])[0],
                path=q.get('path', ['/'])[0],
                host=q.get('host', [''])[0]
            )
            return ProxyNode(protocol="trojan", config=conf, raw_uri=line)
        except Exception: return None

    @staticmethod
    def parse_ss(line: str) -> ProxyNode | None:
        try:
            line = html.unescape(line).strip()
            if line.startswith("ss://"):
                line = line[5:]
            
            line = line.split('#')[0]
            
            if '@' in line:
                part1, part2 = line.split('@', 1)
                user_info = LinkParser.decode_base64(part1).split(':', 1)
                host_port = part2.split(':')
            else:
                decoded = LinkParser.decode_base64(line)
                part1, part2 = decoded.split('@', 1)
                user_info = part1.split(':', 1)
                host_port = part2.split(':')

            if len(user_info) != 2 or len(host_port) < 2: return None
            host = host_port[0]
            if not host or not LinkParser.is_valid_host(host): return None

            conf = ProxyConfig(
                server=host,
                port=int(host_port[1]),
                method=user_info[0],
                password=user_info[1],
                type="tcp"
            )
            return ProxyNode(protocol="ss", config=conf, raw_uri=line)
        except Exception: return None

    async def fetch_and_parse(self) -> List[ProxyNode]:
        nodes = []
        seen = set()
        
        sources = []
        if CONFIG.SUBSCRIPTION_SOURCES:
            sources = [s.strip() for s in CONFIG.SUBSCRIPTION_SOURCES.splitlines() if s.strip()]

        logger.info(f"📥 Загрузка из {len(sources)} источников...")

        async with aiohttp.ClientSession() as session:
            for url in sources:
                try:
                    async with session.get(url, timeout=15) as resp:
                        content = await resp.text()
                        
                        if "://" not in content:
                            content = LinkParser.decode_base64(content)
                        
                        for line in content.splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"): continue
                            
                            node = None
                            if line.startswith("vless://"): node = self.parse_vless(line)
                            elif line.startswith("vmess://"): node = self.parse_vmess(line)
                            elif line.startswith("trojan://"): node = self.parse_trojan(line)
                            elif line.startswith("ss://"): node = self.parse_ss(line)
                            
                            if node and node.unique_id not in seen:
                                nodes.append(node)
                                seen.add(node.unique_id)
                except Exception as e:
                    logger.warning(f"Ошибка источника {url}: {e}")
        
        logger.success(f"✅ Успешно распарсено: {len(nodes)} уникальных, валидных узлов")
        return nodes
