import aiohttp
import ipaddress
import asyncio
from loguru import logger
from core.settings import CONFIG
from core.models import ProxyNode

class RKNValidator:
    domains_wl = set()
    ips_wl = set()
    networks_wl =[]
    _is_loaded = False

    @classmethod
    async def _fetch_list(cls, session: aiohttp.ClientSession, url: str) -> str:
        if not url: 
            return ""
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception:
            pass
        return ""

    @classmethod
    async def load_lists(cls):
        cls.domains_wl.clear()
        cls.ips_wl.clear()
        cls.networks_wl.clear()
        cls._is_loaded = False
        
        dom_urls = CONFIG.whitelist.get("domains_urls",[])
        if not dom_urls and CONFIG.whitelist.get("domains_url"):
            dom_urls = [CONFIG.whitelist.get("domains_url")]
            
        ip_urls = CONFIG.whitelist.get("ips_urls",[])
        if not ip_urls and CONFIG.whitelist.get("ips_url"):
            ip_urls =[CONFIG.whitelist.get("ips_url")]
        
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks =[]
            for url in dom_urls: tasks.append(cls._fetch_list(session, url))
            for url in ip_urls: tasks.append(cls._fetch_list(session, url))
            
            results = await asyncio.gather(*tasks)
            
        dom_results = results[:len(dom_urls)]
        ip_results = results[len(dom_urls):]

        for text in dom_results:
            if text:
                cls.domains_wl.update({
                    line.strip().lower() 
                    for line in text.splitlines() 
                    if line.strip() and not line.startswith('#')
                })
                
        if cls.domains_wl:
            logger.info(f"⛨ Загружено {len(cls.domains_wl)} уникальных доменов БС.")

        all_ip_lines = set()
        for text in ip_results:
            if text:
                all_ip_lines.update({
                    line.strip().lower() 
                    for line in text.splitlines() 
                    if line.strip() and not line.startswith('#')
                })
                
        unique_nets = set()
        for item in all_ip_lines:
            if '/' in item:
                try:
                    unique_nets.add(ipaddress.ip_network(item, strict=False))
                except ValueError:
                    pass
            else:
                cls.ips_wl.add(item)
                
        cls.networks_wl = list(unique_nets)

        if cls.ips_wl or cls.networks_wl:
            logger.info(f"⛨ Загружено {len(cls.ips_wl)} IP-адресов и {len(cls.networks_wl)} уникальных подсетей БС.")

        if cls.domains_wl or cls.ips_wl or cls.networks_wl:
            cls._is_loaded = True
        else:
            logger.warning("⚠ Базы РКН пусты или недоступны. Режим БС отключен (защита от False Positive).")

    @classmethod
    def check_bs(cls, node: ProxyNode) -> bool:
        if node.config.security != "reality":
            return False
            
        if not cls._is_loaded:
            return False
            
        target = node.config.sni or node.config.host or node.config.server
        if not target: 
            return False
            
        target = target.lower()
        
        if target in cls.domains_wl or target in cls.ips_wl:
            return True
            
        parts = target.split('.')
        for i in range(len(parts) - 1):
            base_domain = '.'.join(parts[i:])
            if base_domain in cls.domains_wl:
                return True

        try:
            ip_obj = ipaddress.ip_address(target)
            for net in cls.networks_wl:
                if ip_obj in net:
                    return True
        except ValueError:
            pass
            
        return False
