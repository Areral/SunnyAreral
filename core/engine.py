import asyncio
import json
import os
import subprocess
import time
import signal
import uuid
import aiohttp
from aiohttp_socks import ProxyConnector
from loguru import logger
from typing import List, Optional

from core.models import ProxyNode
from core.settings import CONFIG

class BatchEngine:
    BASE_PORT = 10000

    GEO_APIS = [
        ("https://ipwho.is/", "country_code"),
        ("http://ip-api.com/json/", "countryCode"),
        ("https://api.country.is/", "country"),
        ("https://ipinfo.io/json", "country") 
    ]

    SUPPORTED_SS_CIPHERS = [
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", 
        "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", 
        "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
    ]

    @staticmethod
    def _is_valid_uuid(val: str) -> bool:
        try:
            uuid.UUID(str(val))
            return True
        except ValueError:
            return False

    @staticmethod
    def _generate_batch_config(nodes: List[ProxyNode]) -> dict:
        inbounds = []
        outbounds = []
        rules = []
        
        for i, node in enumerate(nodes):
            tag = f"proxy-{i}"
            outbound = BatchEngine._node_to_outbound(node, tag)
            if not outbound:
                continue
                
            local_port = BatchEngine.BASE_PORT + i
            
            inbounds.append({
                "type": "socks",
                "tag": f"in-{i}",
                "listen": "127.0.0.1",
                "listen_port": local_port
            })
            
            outbounds.append(outbound)
            rules.append({
                "inbound": [f"in-{i}"],
                "outbound": tag
            })

        outbounds.append({"type": "direct", "tag": "direct"})
        
        return {
            "log": {"level": "error", "output": "discard"},
            "dns": {
                "servers": [{"tag": "remote", "address": "8.8.8.8"}],
                "independent_cache": True
            },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {
                "rules": rules,
                "final": "direct"
            }
        }

    @staticmethod
    def _node_to_outbound(node: ProxyNode, tag: str) -> Optional[dict]:
        c = node.config
        base = {"tag": tag, "server": c.server, "server_port": c.port}
        
        try:
            if node.protocol == "vless":
                if not c.uuid or not BatchEngine._is_valid_uuid(c.uuid): return None
                base.update({"type": "vless", "uuid": c.uuid, "packet_encoding": "xudp"})
                if c.flow: base["flow"] = c.flow.strip()
            elif node.protocol == "vmess":
                if not c.uuid or not BatchEngine._is_valid_uuid(c.uuid): return None
                base.update({"type": "vmess", "uuid": c.uuid, "security": "auto", "packet_encoding": "xudp"})
            elif node.protocol == "trojan":
                if not c.password: return None
                base.update({"type": "trojan", "password": c.password.strip()})
            elif node.protocol == "ss":
                if not c.method or not c.password: return None
                if c.method.lower() not in BatchEngine.SUPPORTED_SS_CIPHERS: return None
                base.update({"type": "shadowsocks", "method": c.method.lower(), "password": c.password.strip()})
            elif node.protocol == "hysteria2":
                if not c.password: return None
                base.update({"type": "hysteria2", "password": c.password.strip()})
                if c.obfs and c.obfs_password:
                    base["obfs"] = {"type": c.obfs.strip(), "password": c.obfs_password.strip()}
                
                # Hysteria2 требует свой блок TLS
                base["tls"] = {
                    "enabled": True,
                    "server_name": c.sni or c.host or c.server,
                    "insecure": c.insecure
                }
                return base # Возвращаем сразу, так как Transport ему не нужен

            # Transport (для всех кроме Hysteria2)
            if c.type == "ws":
                base["transport"] = {"type": "ws", "path": c.path or "/"}
                if c.host: base["transport"]["headers"] = {"Host": c.host.strip()}
            elif c.type == "grpc":
                base["transport"] = {"type": "grpc", "service_name": c.service_name or ""}
            elif c.type in ["xhttp", "httpupgrade"]:
                base["transport"] = {"type": "httpupgrade", "path": c.path or "/"}
                if c.host: base["transport"]["host"] = c.host.strip()
                
            # TLS / Reality (для всех кроме Hysteria2)
            if c.security in ["tls", "reality", "auto"]:
                tls = {
                    "enabled": True, 
                    "server_name": c.sni or c.host or c.server,
                    "utls": {"enabled": True, "fingerprint": c.fp or "chrome"}
                }
                if c.security == "reality":
                    if not c.pbk: return None
                    tls["reality"] = {"enabled": True, "public_key": c.pbk.strip()}
                    if c.sid: tls["reality"]["short_id"] = c.sid.strip()
                    if c.spx and c.spx != "/": tls["reality"]["spider_x"] = c.spx.strip()
                base["tls"] = tls
                
            return base
        except Exception:
            return None

    async def check_batch(self, nodes: List[ProxyNode], is_champion: bool = False) -> List[ProxyNode]:
        if not nodes: return []
        
        alive_nodes = []
        config_path = "data/batch_config.json"
        os.makedirs("data", exist_ok=True)
        
        proc = None
        try:
            config_data = self._generate_batch_config(nodes)
            
            if len(config_data["outbounds"]) <= 1: 
                return []

            with open(config_path, "w") as f:
                json.dump(config_data, f)
            
            proc = subprocess.Popen(
                ["sing-box", "run", "-c", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                text=True
            )
            await asyncio.sleep(2.5)
            
            if proc.poll() is not None:
                _, stderr = proc.communicate()
                error_msg = stderr.strip()
                if len(error_msg) > 500:
                    error_msg = "..." + error_msg[-500:]
                logger.error(f"Sing-box crashed! Reason: {error_msg}")
                return []

            tasks = []
            for i, node in enumerate(nodes):
                if any(ob["tag"] == f"proxy-{i}" for ob in config_data["outbounds"]):
                    port = self.BASE_PORT + i
                    tasks.append(self._http_check(node, port, is_champion))
            
            results = await asyncio.gather(*tasks)
            alive_nodes = [n for n in results if n is not None]
            
        except Exception as e:
            logger.error(f"Batch error: {e}")
        finally:
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=2)
                except:
                    try: proc.kill()
                    except: pass
            if os.path.exists(config_path): os.remove(config_path)
            
        return alive_nodes

    async def _http_check(self, node: ProxyNode, port: int, is_champion: bool) -> Optional[ProxyNode]:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=CONFIG.system.get('http_timeout', 25))
        headers = {"User-Agent": CONFIG.system.get('user_agent', 'Mozilla/5.0')}
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
                t0 = time.perf_counter()
                async with session.get("http://www.gstatic.com/generate_204", allow_redirects=False) as resp:
                    if resp.status != 204: raise Exception(f"Status {resp.status}")
                    node.latency = int((time.perf_counter() - t0) * 1000)

                if is_champion:
                    url = CONFIG.checking.get('champion_test_url', "http://speed.cloudflare.com/__down?bytes=25000000")
                else:
                    url = CONFIG.checking.get('speedtest_url', "http://speed.cloudflare.com/__down?bytes=5000000")
                
                t_start = time.perf_counter()
                async with session.get(url) as resp:
                    if resp.status != 200: raise Exception("Download fail")
                    
                    total = 0
                    async for chunk in resp.content.iter_chunked(65536):
                        total += len(chunk)
                    
                    dur = time.perf_counter() - t_start
                    if dur < 0.2: dur = 0.2
                    
                    speed = (total * 8) / (dur * 1_000_000)
                    if speed > 3000: speed = 0 
                    node.speed = round(speed, 1)

                try:
                    async with session.get("http://cp.cloudflare.com/cdn-cgi/trace", timeout=4) as geo:
                        if geo.status == 200:
                            text = await geo.text()
                            for line in text.splitlines():
                                if line.startswith("loc="):
                                    node.country = line.split("=")[1].upper()
                                    break
                except Exception:
                    try:
                        async with session.get("http://ip-api.com/json/", timeout=4) as geo_fallback:
                            if geo_fallback.status == 200:
                                data = await geo_fallback.json()
                                node.country = data.get("countryCode", "UN").upper()
                    except:
                        pass

                if node.speed >= CONFIG.checking.get('min_speed', 2.0):
                    return node
                    
        except Exception:
            return None
        return None

class Inspector:
    def __init__(self):
        self.batch_engine = BatchEngine()

    async def process_all(self, nodes: List[ProxyNode]) -> List[ProxyNode]:
        alive_total = []
        batch_size = getattr(CONFIG, 'BATCH_SIZE', 50)
        total = len(nodes)
        
        logger.info(f"🚀 Запуск проверки: {total} узлов, размер пакета: {batch_size}")
        
        for i in range(0, total, batch_size):
            batch = nodes[i : i + batch_size]
            logger.info(f"📦 Пакет {i // batch_size + 1}: проверка {len(batch)} узлов...")
            
            results = await self.batch_engine.check_batch(batch)
            alive_total.extend(results)
            
            logger.info(f"   ✨ Живых в пакете: {len(results)}")
            
        return alive_total
    
    async def champion_run(self, node: ProxyNode) -> float:
        results = await self.batch_engine.check_batch([node], is_champion=True)
        if results:
            return results[0].speed
        return 0.0
