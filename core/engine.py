import asyncio
import json
import os
import subprocess
import time
import signal
import threading
from typing import Optional
import aiohttp
from aiohttp_socks import ProxyConnector
from loguru import logger

from core.models import ProxyNode
from core.settings import CONFIG

# Потокобезопасный генератор портов для исключения коллизий при многопоточности
_port_counter = 20000
_port_lock = threading.Lock()

def get_free_port() -> int:
    global _port_counter
    with _port_lock:
        port = _port_counter
        _port_counter += 1
        if _port_counter > 60000:
            _port_counter = 20000
        return port

class SingBoxEngine:
    @staticmethod
    def _generate_config(node: ProxyNode, local_port: int) -> dict:
        c = node.config
        outbound = {"tag": "proxy", "server": c.server, "server_port": c.port}

        if node.protocol == "vless":
            outbound.update({"type": "vless", "uuid": c.uuid, "flow": c.flow or "", "packet_encoding": "xudp"})
        elif node.protocol == "vmess":
            outbound.update({"type": "vmess", "uuid": c.uuid, "security": "auto", "packet_encoding": "xudp"})
        elif node.protocol == "trojan":
            outbound.update({"type": "trojan", "password": c.password})
        elif node.protocol == "ss":
            outbound.update({"type": "shadowsocks", "method": c.method, "password": c.password})

        # Транспорт
        if c.type == "ws":
            outbound["transport"] = {"type": "ws", "path": c.path, "headers": {"Host": c.host}}
        elif c.type == "grpc":
            outbound["transport"] = {"type": "grpc", "service_name": c.service_name}
        elif c.type in ["xhttp", "httpupgrade"]:
            outbound["transport"] = {"type": "httpupgrade", "path": c.path or "/", "host": c.host or ""}

        # TLS / Reality
        if c.security in ["tls", "reality", "auto"]:
            tls_conf = {
                "enabled": True, 
                "server_name": c.sni or c.host or c.server, 
                "utls": {"enabled": True, "fingerprint": c.fp or "chrome"}
            }
            if c.security == "reality":
                tls_conf["reality"] = {"enabled": True, "public_key": c.pbk, "short_id": c.sid or ""}
            outbound["tls"] = tls_conf

        return {
            "log": {"level": "panic", "output": "discard"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8", "detour": "proxy"},
                    {"tag": "cf", "address": "1.1.1.1", "detour": "proxy"}
                ],
                "strategy": "ipv4_only"
            },
            "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": local_port}],
            "outbounds": [outbound]
        }

    async def _run_test(self, node: ProxyNode, test_url: str, check_geo: bool = False) -> bool:
        local_port = get_free_port()
        config_path = f"data/config_{local_port}.json"
        os.makedirs("data", exist_ok=True)
        
        proc = None
        try:
            with open(config_path, "w") as f:
                json.dump(self._generate_config(node, local_port), f)
            
            # Запускаем в новой сессии (os.setsid), чтобы потом убить всё дерево процессов
            proc = subprocess.Popen(
                ["sing-box", "run", "-c", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            await asyncio.sleep(2.0)

            if proc.poll() is not None: return False

            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{local_port}")
            timeout = aiohttp.ClientTimeout(total=25, connect=10, sock_read=15)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                
                # 1. ЖЕСТКАЯ ПРОВЕРКА СОЕДИНЕНИЯ
                t0 = time.perf_counter()
                async with session.get("http://www.gstatic.com/generate_204", allow_redirects=False) as resp:
                    if resp.status != 204: raise Exception("Strict test failed")
                    node.latency = int((time.perf_counter() - t0) * 1000)

                # 2. ТЕСТ СКОРОСТИ
                t_start = time.perf_counter()
                async with session.get(test_url) as resp:
                    if resp.status != 200: raise Exception("Download Failed")
                    
                    total_bytes = 0
                    async for chunk in resp.content.iter_chunked(65536):
                        total_bytes += len(chunk)
                    
                    duration = time.perf_counter() - t_start
                    if duration < 0.3: duration = 0.3 # Защита от деления на около-ноль
                    
                    speed = (total_bytes * 8) / (duration * 1_000_000)
                    if speed > 2500: speed = 999.0 # Защита от багов таймера
                    node.speed = round(speed, 1)

                # 3. ГЕОЛОКАЦИЯ
                if check_geo:
                    try:
                        async with session.get(CONFIG.checking['geo_api'], timeout=4) as geo:
                            data = await geo.json()
                            if data.get('success'): node.country = data.get('country_code', 'UN')
                    except: pass

                return True

        except Exception:
            return False
        finally:
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=1)
                except:
                    try: proc.kill()
                    except: pass
            if os.path.exists(config_path):
                try: os.remove(config_path)
                except: pass

    async def verify_node(self, node: ProxyNode) -> bool:
        return await self._run_test(node, CONFIG.checking['speedtest_url'], check_geo=True)

    async def champion_run(self, node: ProxyNode) -> float:
        logger.info(f"🏆 Тест чемпиона: {node.config.server}")
        success = await self._run_test(node, CONFIG.checking['champion_test_url'], check_geo=False)
        if success:
            logger.info(f"🚀 Скорость чемпиона подтверждена: {node.speed} Mbps")
            return node.speed
        return 0.0

class Inspector:
    def __init__(self):
        self.engine = SingBoxEngine()
        self.sem = asyncio.Semaphore(CONFIG.system['threads'])

    async def check_pipeline(self, node: ProxyNode) -> Optional[ProxyNode]:
        async with self.sem:
            is_alive = await self.engine.verify_node(node)
            if is_alive and node.speed >= CONFIG.checking['min_speed']:
                logger.info(f"✅ Alive: {node.country} | {node.latency}ms | {node.speed} Mbps")
                return node
            return None
