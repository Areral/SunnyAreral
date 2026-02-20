import asyncio
import json
import os
import subprocess
import time
import signal
from typing import Optional, List, Tuple
import aiohttp
from aiohttp_socks import ProxyConnector
from loguru import logger

from core.models import ProxyNode
from core.settings import CONFIG

class SingBoxEngine:
    @staticmethod
    def _generate_batch_config(nodes: List[ProxyNode], start_port: int) -> dict:
        """Генерирует умный конфиг для ПАКЕТНОЙ проверки с жесткой изоляцией"""
        inbounds = []
        outbounds = []
        rules = []

        for i, node in enumerate(nodes):
            local_port = start_port + i
            in_tag = f"in-{local_port}"
            out_tag = f"out-{local_port}"

            # 1. ВХОД (Локальный порт)
            inbounds.append({
                "type": "socks",
                "tag": in_tag,
                "listen": "127.0.0.1",
                "listen_port": local_port
            })

            # 2. ВЫХОД (Прокси)
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
                outbound["transport"] = {"type": "ws", "path": c.path, "headers": {"Host": c.host}}
            elif c.type == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": c.service_name}
            elif c.type in ["xhttp", "httpupgrade"]:
                outbound["transport"] = {"type": "httpupgrade", "path": c.path or "/", "host": c.host or ""}

            if c.security in ["tls", "reality", "auto"]:
                tls_conf = {"enabled": True, "server_name": c.sni or c.host or c.server, "utls": {"enabled": True, "fingerprint": c.fp or "chrome"}}
                if c.security == "reality":
                    tls_conf["reality"] = {"enabled": True, "public_key": c.pbk, "short_id": c.sid or ""}
                    if c.spx and c.spx != "/": tls_conf["reality"]["spider_x"] = c.spx
                outbound["tls"] = tls_conf

            outbounds.append(outbound)

            # 3. ЖЕСТКОЕ ПРАВИЛО (Порт X идет ТОЛЬКО в Прокси X)
            rules.append({
                "inbound": [in_tag],
                "outbound": out_tag
            })

        # Общий конфиг
        return {
            "log": {"level": "panic", "output": "discard"},
            "dns": {
                # РЕШЕНИЕ ПРОБЛЕМЫ 3: Локальный быстрый DNS без detour: proxy
                "servers": [{"tag": "local", "address": "1.1.1.1", "detour": "direct"}],
                "strategy": "ipv4_only"
            },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"rules": rules}
        }

    async def _test_single_node(self, node: ProxyNode, port: int, test_url: str) -> Tuple[bool, str]:
        """Тестирует один узел внутри батча. Возвращает (Успех, Код ошибки)"""
        # РЕШЕНИЕ ПРОБЛЕМЫ 3 (DNS Trap): rdns=False. Python резолвит домен САМ!
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}", rdns=False)
        timeout = aiohttp.ClientTimeout(total=20, connect=8, sock_read=12)
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # 1. ПРОВЕРКА СОЕДИНЕНИЯ (Latency)
                t0 = time.perf_counter()
                async with session.get("http://www.gstatic.com/generate_204", allow_redirects=False) as resp:
                    if resp.status != 204: return False, f"HTTP_{resp.status}"
                    node.latency = int((time.perf_counter() - t0) * 1000)

                # 2. ТЕСТ СКОРОСТИ
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

                # 3. ГЕОЛОКАЦИЯ
                try:
                    # Для API гео используем короткий таймаут
                    async with session.get(CONFIG.checking.get('geo_api', 'https://ipwho.is/'), timeout=3) as geo:
                        data = await geo.json()
                        if data.get('success'): node.country = data.get('country_code', 'UN')
                except: pass

                return True, "OK"
                
        # РЕШЕНИЕ ПРОБЛЕМЫ 4: Телеметрия ошибок (Blind Exceptions)
        except asyncio.TimeoutError:
            return False, "Timeout"
        except aiohttp.ClientConnectorError:
            return False, "Proxy_Refused"
        except aiohttp.ClientResponseError as e:
            return False, f"HTTP_Err_{e.status}"
        except Exception as e:
            return False, "Protocol_Error"

    async def verify_batch(self, nodes: List[ProxyNode]) -> List[Tuple[ProxyNode, bool, str]]:
        """Запускает ядро для пакета из N прокси и тестирует их параллельно"""
        if not nodes: return []
        
        start_port = 30000
        config_path = f"data/batch_{start_port}.json"
        os.makedirs("data", exist_ok=True)
        
        proc = None
        results = []
        
        try:
            with open(config_path, "w") as f:
                json.dump(self._generate_batch_config(nodes, start_port), f)
            
            proc = subprocess.Popen(
                ["sing-box", "run", "-c", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            await asyncio.sleep(2.0) # Ждем старта ядра

            if proc.poll() is not None:
                # Ядро упало из-за кривого конфига (скорее всего 1 битый прокси сломал всё)
                return [(n, False, "Kernel_Crash") for n in nodes]

            # Запускаем HTTP тесты для всех портов ОДНОВРЕМЕННО
            test_url = CONFIG.checking.get('speedtest_url', "http://speed.cloudflare.com/__down?bytes=5000000")
            
            tasks = []
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
        """Одиночный тест для абсолютного победителя (25MB)"""
        logger.info(f"🏆 Тест чемпиона: {node.config.server}")
        test_url = CONFIG.checking.get('champion_test_url', "http://speed.cloudflare.com/__down?bytes=25000000")
        
        # Для чемпиона запускаем микро-батч из 1 элемента
        results = await self.verify_batch([node])
        _, is_alive, _ = results[0]
        
        if is_alive: return node.speed
        return 0.0

class Inspector:
    def __init__(self):
        self.engine = SingBoxEngine()

    async def process_all(self, nodes: List[ProxyNode]) -> Tuple[List[ProxyNode], dict]:
        """Управляет разбивкой на батчи и собирает статистику ошибок"""
        batch_size = CONFIG.system.get('threads', 30) # 30 прокси в 1 процессе - идеально
        alive_nodes = []
        error_stats = {}
        min_speed = CONFIG.checking.get('min_speed', 2.0)

        # Разбиваем список на чанки (батчи)
        for i in range(0, len(nodes), batch_size):
            batch = nodes[i:i + batch_size]
            logger.info(f"🔄 Проверка пакета {i//batch_size + 1}/{(len(nodes)+batch_size-1)//batch_size} ({len(batch)} узлов)...")
            
            results = await self.engine.verify_batch(batch)
            
            for node, is_alive, err_code in results:
                # Телеметрия
                error_stats[err_code] = error_stats.get(err_code, 0) + 1
                
                if is_alive and node.speed >= min_speed:
                    node.is_alive = True
                    alive_nodes.append(node)
                    logger.info(f"✅ {node.country} | {node.latency}ms | {node.speed} Mbps")
                    
        return alive_nodes, error_stats
