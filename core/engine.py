import asyncio
import json
import os
import random
import subprocess
import time
import signal
from typing import Optional
import aiohttp
from aiohttp_socks import ProxyConnector
from loguru import logger

from core.models import ProxyNode
from core.settings import CONFIG

class SingBoxEngine:
    """
    Enterprise-grade wrapper for Sing-box kernel.
    Handles configuration generation, process lifecycle management, 
    and robust error handling.
    """
    
    @staticmethod
    def _generate_config(node: ProxyNode, local_port: int) -> dict:
        c = node.config
        
        # 1. Base Structure
        outbound = {
            "tag": "proxy",
            "server": c.server,
            "server_port": c.port
        }

        # 2. Protocol Adapters
        if node.protocol == "vless":
            outbound.update({
                "type": "vless",
                "uuid": c.uuid,
                "flow": c.flow or "",
                "packet_encoding": "xudp"
            })
        elif node.protocol == "vmess":
            outbound.update({
                "type": "vmess",
                "uuid": c.uuid,
                "security": "auto",
                "packet_encoding": "xudp"
            })
        elif node.protocol == "trojan":
            outbound.update({
                "type": "trojan",
                "password": c.password
            })
        elif node.protocol == "ss":
            outbound.update({
                "type": "shadowsocks",
                "method": c.method,
                "password": c.password
            })
        elif node.protocol == "hysteria2":
            outbound.update({
                "type": "hysteria2",
                "password": c.password,
                "up_mbps": 50,
                "down_mbps": 100,
                "obfs": {"type": "salamander", "password": "password"}
            })

        # 3. Transport Layer
        if c.type == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": c.path,
                "headers": {"Host": c.host}
            }
        elif c.type == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": c.service_name
            }

        # 4. Security (TLS/Reality)
        if c.security in ["tls", "reality", "auto"]:
            tls_conf = {
                "enabled": True,
                "server_name": c.sni or c.host or c.server,
                "utls": {"enabled": True, "fingerprint": c.fp}
            }
            if c.security == "reality":
                tls_conf["reality"] = {
                    "enabled": True,
                    "public_key": c.pbk,
                    "short_id": c.sid or ""
                }
            outbound["tls"] = tls_conf

        # 5. Final Assembly with Hardcoded Robust DNS
        return {
            "log": {"level": "panic", "output": "discard"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8", "detour": "proxy"},
                    {"tag": "cf", "address": "1.1.1.1", "detour": "proxy"}
                ],
                "strategy": "ipv4_only"
            },
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": local_port
            }],
            "outbounds": [outbound]
        }

    async def _run_test(self, node: ProxyNode, test_url: str, check_geo: bool = False) -> bool:
        """
        Internal method to run the Sing-box process and perform HTTP tests.
        """
        local_port = random.randint(20000, 60000)
        config_path = f"data/config_{local_port}.json"
        os.makedirs("data", exist_ok=True)
        
        proc = None
        try:
            # A. Config Dump
            with open(config_path, "w") as f:
                json.dump(self._generate_config(node, local_port), f)
            
            # B. Process Start
            proc = subprocess.Popen(
                ["sing-box", "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid # Создаем группу процессов для надежного убийства
            )
            await asyncio.sleep(2.0) # Warm-up

            if proc.poll() is not None:
                return False

            # C. HTTP Client Setup
            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{local_port}")
            timeout = aiohttp.ClientTimeout(total=25, connect=10, sock_read=15)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                
                # 1. LATENCY CHECK (Real Request)
                # Используем gstatic (204) - это тест "есть ли реальный интернет"
                t0 = time.perf_counter()
                async with session.get("http://www.gstatic.com/generate_204", allow_redirects=False) as resp:
                    if resp.status != 204: raise Exception("No Internet")
                    node.latency = int((time.perf_counter() - t0) * 1000)

                # 2. SPEED TEST (Download)
                t_start = time.perf_counter()
                async with session.get(test_url) as resp:
                    if resp.status != 200: raise Exception("Download Failed")
                    
                    total_bytes = 0
                    async for chunk in resp.content.iter_chunked(65536):
                        total_bytes += len(chunk)
                    
                    duration = time.perf_counter() - t_start
                    
                    # Фильтр "Фейковой" скорости (если скачалось мгновенно - это кэш)
                    if duration < 0.3: duration = 0.3
                    
                    speed = (total_bytes * 8) / (duration * 1_000_000)
                    
                    # Отсекаем нереалистичные значения (баги таймера)
                    if speed > 5000: speed = 0.0
                    
                    node.speed = round(speed, 1)

                # 3. GEO CHECK (Only if requested and node is alive)
                if check_geo:
                    try:
                        async with session.get(CONFIG.checking['geo_api'], timeout=4) as geo:
                            data = await geo.json()
                            if data.get('success'):
                                node.country = data.get('country_code', 'UN')
                    except: pass

                return True

        except Exception:
            return False
        finally:
            # D. Paranoid Cleanup
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM) # Убиваем всю группу процессов
                    proc.wait(timeout=1)
                except:
                    try: proc.kill()
                    except: pass
            if os.path.exists(config_path):
                os.remove(config_path)

    async def verify_node(self, node: ProxyNode) -> bool:
        """Standard verification pipeline (5MB test)"""
        return await self._run_test(node, CONFIG.checking['speedtest_url'], check_geo=True)

    async def champion_run(self, node: ProxyNode) -> float:
        """Champion verification pipeline (25MB test) - No Geo needed"""
        logger.info(f"🏆 Запуск теста чемпиона для: {node.config.server}")
        # Используем большой файл для точного замера
        success = await self._run_test(node, "http://speed.cloudflare.com/__down?bytes=25000000", check_geo=False)
        if success:
            logger.info(f"🚀 Реальная скорость чемпиона: {node.speed} Mbps")
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
