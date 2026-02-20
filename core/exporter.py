import base64
import urllib.parse
import os
import datetime
from typing import List
import aiohttp
from loguru import logger

from core.models import ProxyNode
from core.settings import CONFIG

class Exporter:
    @staticmethod
    def _flag(code: str) -> str:
        if not code or code == "UN": return "🏳️"
        try: return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
        except: return "🏳️"

    @staticmethod
    def generate_subscription(nodes: List[ProxyNode]) -> str:
        links = []
        nodes.sort(key=lambda x: x.speed, reverse=True)
        
        for i, node in enumerate(nodes, 1):
            flag = Exporter._flag(node.country)
            cc = node.country
            sni = node.config.sni or node.config.host or node.config.server
            proto = node.protocol.upper()
            name = f"{i:02d} {flag} {cc} | {sni} | {proto} | @SunnyAreral"
            
            parsed = urllib.parse.urlparse(node.raw_uri)
            encoded_name = urllib.parse.quote(name, safe='/')
            new_url = parsed._replace(fragment=encoded_name).geturl()
            links.append(new_url)
            
        full_text = "\n".join(links)
        return base64.b64encode(full_text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def save_files(nodes: List[ProxyNode]):
        content_b64 = Exporter.generate_subscription(nodes)
        
        with open("subscription.txt", "w") as f:
            f.write(content_b64)
            
        template_path = CONFIG.app.get('template_path', 'config/template.html')
        if os.path.exists(template_path):
            try:
                with open(template_path, "r", encoding="utf-8") as f:
                    tpl = f.read()
                
                # ИСПРАВЛЕНО: Аргументы для max
                top_speed = max([n.speed for n in nodes]) if nodes else 0.0
                count = len(nodes)
                now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
                public_url = CONFIG.app.get('public_url', '')
                
                html = tpl.replace("{{UPDATE_TIME}}", now.strftime('%d.%m %H:%M')) \
                          .replace("{{PROXY_COUNT}}", str(count)) \
                          .replace("{{MAX_SPEED}}", str(int(top_speed))) \
                          .replace("{{SUB_LINK}}", f"{public_url}/sub") \
                          .replace("<title>SunnyAreral Config</title>", "<title>SunnyAreral | SUB</title>")
                          
                with open("index.html", "w", encoding="utf-8") as f:
                    f.write(html)
                logger.success("📁 Файлы сохранены")
            except Exception as e:
                logger.error(f"HTML Error: {e}")

    @staticmethod
    async def send_telegram_report(total_parsed: int, alive_nodes: List[ProxyNode], duration: float):
        if not CONFIG.TG_BOT_TOKEN or not CONFIG.TG_CHAT_ID: return

        # ИСПРАВЛЕНО: Аргументы для max и sum
        top_speed = max([n.speed for n in alive_nodes]) if alive_nodes else 0.0
        avg_speed = (sum([n.speed for n in alive_nodes]) / len(alive_nodes)) if alive_nodes else 0.0
        public_url = CONFIG.app.get('public_url', '')
        
        msg = (
            f"📊 <b>System Report:</b>\n\n"
            f"🔍 Parsed: {total_parsed}\n"
            f"✅ Alive: {len(alive_nodes)}\n"
            f"⚡️ Top Speed: {top_speed:.1f} Mbps\n"
            f"📈 Avg Speed: {avg_speed:.1f} Mbps\n"
            f"⏱️ Duration: {duration:.1f}s\n\n"
            f"🔗 <a href='{public_url}'>Status Page</a>"
        )
        
        url = f"https://api.telegram.org/bot{CONFIG.TG_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": CONFIG.TG_CHAT_ID,
            "text": msg,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if CONFIG.TG_TOPIC_ID: payload["message_thread_id"] = CONFIG.TG_TOPIC_ID
            
        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload)
            except: pass
