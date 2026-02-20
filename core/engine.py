import asyncio
import json
import os
import subprocess
import time
import signal
import threading
from typing import Optional, List, Tuple
import aiohttp
from aiohttp_socks import ProxyConnector
from loguru import logger

from core.models import ProxyNode
from core.settings import CONFIG

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
    def _generate_batch_config(nodes: List, start_port: int) -> dict:
        inbounds = []
        outbounds = []
        rules =[]

        for i, node in enumerate(nodes):
            local_port = start_port + i
            in_tag = f"in-{local_port}"
            out_tag = f"out-{local_port}"

            inbounds.append({
                "type": "socks",
                "tag": in_tag,
                "listen": "127.0.0.1",
                "listen_port": local_port
            })

            c = node.config
            outbound = {"tag": out_tag, "server": c.server, "server_port": c.port}

            if node.protocol == "vless":
                outbound.update({"type": "vless", "uuid": c.uuid, "flow": c.flow or "", "packet_encoding": "xudp"})
            elif node.protocol == "vmess":
                outbound.update({"type": "vmess", "uuid": c.uuid, "security": "auto", "packet_encoding": "xudp"})
            elif node.protocol == "trojan":
                outbound.update({"type": "trojan", "password": c.password})
            elif node.protocol == "ss":
                outbound.update({"type": "shadowsocks", "method": c.method, "password": c.password})

            if c.type == "ws":
                outbound = {"type": "ws", "path": c.path, "headers": {"Host": c.host}}
            elif c.type == "grpc":
                outbound = {"type": "grpc", "service_name": c.service_name}
            elif c.type in:
                outbound = {"type": "httpupgrade", "path": c.path or "/", "host": c.host or ""}

            if c.security in:
                tls_conf = {
                    "enabled": True, 
                    "server_name": c.sni or c.host or c.server, 
                    "utls": {"enabled": True, "fingerprint": c.fp or "chrome"}
                }
                if c.security == "reality":
                    tls_conf = {"enabled": True, "public_key": c.pbk, "short_id": c.sid or ""}
                    if c.spx and c.spx != "/":
                        tls_conf = c.spx
                outbound = tls_conf

            outbounds.append(outbound)

            rules.append({
                "inbound":,
                "outbound": out_tag
            })

        return {
            "log": {"level": "fatal", "output": "discard"},
            "dns": {
                "servers":,
                "strategy": "ipv4_only"
            },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"rules": rules}
        }

    async def _test_single_node(self, node: ProxyNode, port: int, test_url: str) -> Tuple:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}", rdns=False)
        timeout = aiohttp.ClientTimeout(total=20, connect=8, sock_read=12)
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                
                t0 = time.perf_counter()
                async with session.get("http://www.gstatic.com/generate_204", allow_redirects=False) as resp:
                    if resp.status != 204: return False, f"HTTP_{resp.status}"
                    node.latency = int((time.perf_counter() - t0) * 1000)

                t_start = time.perf_counter()
                async with session.get(test_url) as resp:
                    if resp.status != 200: return False, "Speedtest_Failed"
                    
                    total_bytes = 0
                    async for chunk in resp.content.iter_chunked(65536):
                        total_bytes += len(chunk)
                    
                    duration = time.perf_counter() - t_start
                    if duration < 0.2: duration = 0.2
                    
                    speed = (total_bytes * 8) / (duration * 1_000_000)
                    if speed > 2500: speed = 999.0
                    node.speed = round(speed, 1)

                try:
                    geo_api = CONFIG.checking.get('geo_api', 'https://ipwho.is/')
                    async with session.get(geo_api, timeout=3) as geo:
                        data = await geo.json()
                        if data.get('success'): 
                            node.country = data.get('country_code', 'UN')
                except: pass

                return True, "OK"
                
        except asyncio.TimeoutError: return False, "Timeout"
        except aiohttp.ClientConnectorError: return False, "Proxy_Refused"
        except aiohttp.ClientResponseError as e: return False, f"HTTP_Err_{e.status}"
        except Exception: return False, "Protocol_Error"

    async def verify_batch(self, nodes: List, start_port: int) -> List[Tuple]:
        if not nodes: return[]
        
        config_path = f"data/batch_{start_port}.json"
        os.makedirs("data", exist_ok=True)
        
        proc = None
        results =[]
        
        try:
            with open(config_path, "w") as f:
                json.dump(self._generate_batch_config(nodes, start_port), f)
            
            proc = subprocess.Popen(,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            await asyncio.sleep(2.0)

            if proc.poll() is not None:
                return

            test_url = CONFIG.checking.get('speedtest_url', "http://speed.cloudflare.com/__down?bytes=5000000")
            
            tasks =[]
            for i, node in enumerate(nodes):
                port = start_port + i
                tasks.append(self._test_single_node(node, port, test_url))
                
            test_results = await asyncio.gather(*tasks)
            
            for node, (is_alive, err_code) in zip(nodes, test_results):
                results.append((node, is_alive, err_code))

        except Exception as e:
            logger.error(f"Batch Error: {e}")
            for n in nodes: results.append((n, False, "Batch_Error"))
        finally:
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=2)
                except:
                    try: proc.kill()
                    except: pass
            if os.path.exists(config_path):
                try: os.remove(config_path)
                except: pass
                
        return results

    async def champion_run(self, node: ProxyNode) -> float:
        logger.info(f"🏆 Тест чемпиона: {node.config.server}")
        test_url = CONFIG.checking.get('champion_test_url', "http://speed.cloudflare.com/__down?bytes=25000000")
        
        results = await self.verify_batch(, 50000)
        if not results: return 0.0
        
        _, is_alive, _ = results
        if is_alive: return node.speed
        return 0.0

class Inspector:
    def __init__(self):
        self.engine = SingBoxEngine()

    async def process_all(self, nodes: List) -> Tuple, dict]:
        batch_size = CONFIG.system.get('threads', 20)
        alive_nodes =[]
        error_stats = {}
        min_speed = CONFIG.checking.get('min_speed', 2.0)

        current_port = 20000

        for i in range(0, len(nodes), batch_size):
            batch = nodes
            logger.info(f"🔄 Проверка пакета {i//batch_size + 1}/{(len(nodes)+batch_size-1)//batch_size} ({len(batch)} узлов)...")
            
            results = await self.engine.verify_batch(batch, current_port)
            current_port += batch_size 
            
            for node, is_alive, err_code in results:
                error_stats = error_stats.get(err_code, 0) + 1
                
                if is_alive and node.speed >= min_speed:
                    node.is_alive = True
                    alive_nodes.append(node)
                    logger.info(f"✅ {node.country} | {node.latency}ms | {node.speed} Mbps")
                    
        return alive_nodes, error_stats
