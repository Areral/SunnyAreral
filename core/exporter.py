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
        try:
            return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
        except:
            return "🏳️"

    @staticmethod
    def generate_subscription(nodes: List[ProxyNode]) -> str:
        """Generates Base64 subscription string with custom naming"""
        links = []
        # Sort by speed descending
        nodes.sort(key=lambda x: x.speed, reverse=True)
        
        for i, node in enumerate(nodes, 1):
            # 1. Flag & Country
            flag = Exporter._flag(node.country)
            cc = node.country
            
            # 2. Smart SNI Detection
            # Users trust SNI (e.g., google.com) more than random IPs
            sni = node.config.sni or node.config.host or node.config.server
            
            # 3. Protocol
            proto = node.protocol.upper()
            
            # 4. Brand
            brand = "@SunnyAreral"
            
            # Format: 01 🇩🇪 DE | sni.google.com | VLESS | @SunnyAreral
            name = f"{i:02d} {flag} {cc} | {sni} | {proto} | {brand}"
            
            # 5. Encode Fragment
            parsed = urllib.parse.urlparse(node.raw_uri)
            # safe='/' ensures slashes aren't encoded, but spaces are
            encoded_name = urllib.parse.quote(name, safe='/')
            new_url = parsed._replace(fragment=encoded_name).geturl()
            links.append(new_url)
            
        return base64.b64encode("\n".join(links).encode()).decode()

    @staticmethod
    def save_files(nodes: List[ProxyNode]):
        """Saves subscription.txt and index.html"""
        try:
            # 1. Save TXT
            content_b64 = Exporter.generate_subscription(nodes)
            with open("subscription.txt", "w") as f:
                f.write(content_b64)
            
            # 2. Save HTML
            template_path = CONFIG.app.get('template_path', 'config/template.html')
            if os.path.exists(template_path):
                with open(template_path, "r", encoding="utf-8") as f:
                    tpl = f.read()
                
                # Metrics
                top_speed = max([n.speed for n in nodes]) if nodes else 0
                count = len(nodes)
                now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
                
                # Replacements
                html = tpl.replace("{{UPDATE_TIME}}", now.strftime('%d.%m %H:%M')) \
                          .replace("{{PROXY_COUNT}}", str(count)) \
                          .replace("{{MAX_SPEED}}", str(int(top_speed))) \
                          .replace("{{SUB_LINK}}", f"{CONFIG.app['public_url']}/sub") \
                          .replace("<title>SunnyAreral Config</title>", "<title>SunnyAreral | SUB</title>")
                          
                with open("index.html", "w", encoding="utf-8") as f:
                    f.write(html)
                logger.success("📁 Files (txt, html) saved successfully")
            else:
                logger.warning(f"⚠️ Template not found at {template_path}")
                
        except Exception as e:
            logger.error(f"Save error: {e}")

    @staticmethod
    async def send_telegram_report(total_parsed: int, alive_nodes: List[ProxyNode], duration: float):
        """Sends a professional report to Telegram"""
        if not CONFIG.TG_BOT_TOKEN or not CONFIG.TG_CHAT_ID:
            logger.warning("⚠️ Telegram credentials missing")
            return

        top_speed = max([n.speed for n in alive_nodes]) if alive_nodes else 0
        avg_speed = sum([n.speed for n in alive_nodes]) / len(alive_nodes) if alive_nodes else 0
        
        # Professional Report Format
        msg = (
            f"📊 <b>System Report:</b>\n\n"
            f"🔍 Parsed: {total_parsed}\n"
            f"✅ Alive: {len(alive_nodes)}\n"
            f"⚡️ Top Speed: {top_speed:.1f} Mbps\n"
            f"📈 Avg Speed: {avg_speed:.1f} Mbps\n"
            f"⏱️ Duration: {duration:.1f}s\n\n"
            f"🔗 <a href='{CONFIG.app['public_url']}'>Status Page</a>"
        )
        
        url = f"https://api.telegram.org/bot{CONFIG.TG_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": CONFIG.TG_CHAT_ID,
            "text": msg,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if CONFIG.TG_TOPIC_ID:
            payload["message_thread_id"] = CONFIG.TG_TOPIC_ID
            
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(url, json=payload)
                logger.info("📢 Report sent to Telegram")
            except Exception as e:
                logger.error(f"Telegram error: {e}")
