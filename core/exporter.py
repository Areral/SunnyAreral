import urllib.parse
import os
import datetime
import base64
import json
import hashlib
import ipaddress
from typing import List, Dict, Any, Optional
import aiohttp
from loguru import logger

from core.models import ProxyNode
from core.settings import CONFIG


class Exporter:
    @staticmethod
    def _flag(code: str) -> str:
        if not code or code == "UN": return "❓"
        try: return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
        except Exception: return "❓"

    @staticmethod
    def _safe_b64encode(b: bytes) -> str:
        try:
            return base64.b64encode(b).decode("utf-8").rstrip("=")
        except Exception:
            return ""

    @staticmethod
    def _is_ip(address: str) -> bool:
        if not address: return False
        try:
            ipaddress.ip_address(address.strip("[]"))
            return True
        except ValueError:
            return False

    @staticmethod
    def _format_host(address: str) -> str:
        if not address: return address
        clean = address.strip().strip("[]")
        try:
            ip = ipaddress.ip_address(clean)
            return f"[{clean}]" if ip.version == 6 else clean
        except ValueError:
            return clean

    @staticmethod
    def _resolve_export_sni(c, is_ip_server: bool) -> Optional[str]:
        if c.sni: return c.sni
        if c.type not in ("ws", "httpupgrade", "xhttp", "http", "h2"):
            if c.host: return c.host
        if not is_ip_server: return c.server
        return None

    @staticmethod
    def _xray_encode_value(key: str, value: str) -> str:
        k = key.lower()
        if k in ("pbk", "sid", "flow", "fp", "type", "security", "encryption", "net", "tls", "protocol"):
            return value
        if k == "alpn": return urllib.parse.quote(value, safe=",/")
        if k == "path": return urllib.parse.quote(value, safe="")
        if k in ("host", "sni", "peer", "add", "server"): return urllib.parse.quote(value, safe=".-_[]:")
        if k == "servicename": return urllib.parse.quote(value, safe=".-_/")
        return urllib.parse.quote(value, safe="")

    @staticmethod
    def _urlencode(query_dict: Dict[str, Any]) -> str:
        if not query_dict: return ""
        parts =[]
        for k, raw_v in query_dict.items():
            if raw_v is None: continue
            v = "1" if isinstance(raw_v, bool) and raw_v else ("0" if isinstance(raw_v, bool) else str(raw_v))
            
            if v == "" and k.lower() not in ("sid", "pbk", "path", "spx"): 
                continue
                
            parts.append(f"{k}={Exporter._xray_encode_value(k, v)}")
        return "&".join(parts)

    @staticmethod
    def _build_url(node: ProxyNode, name: str) -> str:
        c = node.config
        encoded_name = urllib.parse.quote(name, safe="")
        host_for_uri = Exporter._format_host(c.server or "")
        port = c.port

        try:
            if node.protocol == "vless":
                q = dict(c.raw_meta or {})
                q["type"] = c.type
                q["security"] = c.security
                q["encryption"] = "none"

                if c.path is not None: q["path"] = c.path
                if c.host: q["host"] = c.host
                if c.sni: q["sni"] = c.sni
                if c.fp: q["fp"] = c.fp
                if c.alpn: q["alpn"] = c.alpn
                if c.pbk is not None: q["pbk"] = c.pbk
                if c.sid is not None: q["sid"] = c.sid
                if c.spx is not None: q["spx"] = c.spx
                if c.flow: q["flow"] = c.flow
                if c.service_name: q["serviceName"] = c.service_name

                return f"vless://{c.uuid}@{host_for_uri}:{port}?{Exporter._urlencode(q)}#{encoded_name}"

            elif node.protocol == "vmess":
                data = {
                    "v": "2", "ps": name, "add": c.server, "port": str(c.port),
                    "id": str(c.uuid), "aid": str(c.alter_id), "net": c.type,
                    "type": "none", "tls": "tls" if c.security in ("tls", "reality") else "",
                }
                
                if c.host: data["host"] = c.host
                if c.path: data["path"] = c.path
                if c.type == "grpc" and c.service_name: data["path"] = c.service_name

                if data["tls"]:
                    if c.sni: data["sni"] = c.sni
                    if c.fp: data["fp"] = c.fp
                    if c.alpn: data["alpn"] = c.alpn
                    
                for k, v in c.raw_meta.items():
                    if k not in data:
                        data[k] = v

                j_str = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
                return f"vmess://{Exporter._safe_b64encode(j_str.encode('utf-8'))}"

            elif node.protocol == "trojan":
                q = dict(c.raw_meta or {})
                q["type"] = c.type
                q["security"] = c.security

                if c.path is not None: q["path"] = c.path
                if c.host: q["host"] = c.host
                if c.sni: q["sni"] = c.sni
                if c.fp: q["fp"] = c.fp
                if c.alpn: q["alpn"] = c.alpn
                if c.service_name: q["serviceName"] = c.service_name
                if c.flow: q["flow"] = c.flow

                return f"trojan://{c.password}@{host_for_uri}:{port}?{Exporter._urlencode(q)}#{encoded_name}"

            elif node.protocol == "ss":
                b64_up = Exporter._safe_b64encode(f"{c.method}:{c.password}".encode("utf-8"))
                q = dict(c.raw_meta or {})
                q_str = Exporter._urlencode(q)
                suffix = f"/?{q_str}" if q_str else ""
                return f"ss://{b64_up}@{host_for_uri}:{port}{suffix}#{encoded_name}"

            elif node.protocol == "hysteria2":
                q = dict(c.raw_meta or {})
                if c.sni: q["sni"] = c.sni
                if c.obfs: q["obfs"] = c.obfs
                if c.obfs_password: q["obfs-password"] = c.obfs_password

                return f"hysteria2://{c.password}@{host_for_uri}:{port}?{Exporter._urlencode(q)}#{encoded_name}"

        except Exception as e:
            logger.debug(f"URL Build Error[{node.protocol}] {node.config.server}: {e}")

        try:
            parsed = urllib.parse.urlparse(node.raw_uri)
            return parsed._replace(fragment=encoded_name).geturl()
        except Exception:
            return node.raw_uri or ""

    @staticmethod
    def generate_subscription(nodes: List[ProxyNode], title: str) -> str:
        channel_tag = CONFIG.app.get("channel_tag", "@SunnyAreral")
        lines =[f"#profile-title: {title}", "#profile-update-interval: 6"]
        for node in sorted(nodes, key=lambda x: x.speed, reverse=True):
            flag = Exporter._flag(node.country)
            sni = node.config.sni or node.config.host or node.config.server
            proto = node.protocol.upper()
            short_hash = hashlib.md5(node.strict_id.encode("utf-8")).hexdigest()[:4].upper()
            name = f"{flag} {node.country} | {sni} | {proto}[{short_hash}] | {channel_tag}"
            lines.append(Exporter._build_url(node, name))
        return "\n".join(lines)

    @staticmethod
    def save_files(nodes: List[ProxyNode]):
        if not nodes:
            logger.warning("⚠ Пустой список нод — файлы подписок НЕ перезаписываются")
            return

        nodes_bs =[n for n in nodes if n.is_bs]
        nodes_chs =[n for n in nodes if not n.is_bs]

        for filename, node_list, title in[
            ("sub_all.txt", nodes, "SunnyAreral | MIX База"),
            ("sub_bs.txt", nodes_bs, "SunnyAreral | Обход БС"),
            ("sub_chs.txt", nodes_chs, "SunnyAreral | Обход ЧС"),
        ]:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(Exporter.generate_subscription(node_list, title))
            except Exception as e:
                logger.error(f"Ошибка сохранения {filename}: {e}")

        try:
            with open("config/web/template.html", "r", encoding="utf-8") as f:
                tpl = f.read()
            with open("config/web/style.css", "r", encoding="utf-8") as f:
                css = f.read()
            with open("config/web/main.js", "r", encoding="utf-8") as f:
                js = f.read()

            top_speed = max((n.speed for n in nodes), default=0.0)
            now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
            public_url = CONFIG.app.get("public_url", "")

            html_out = (
                tpl.replace("{{INJECT_CSS}}", css)
                   .replace("{{INJECT_JS}}", js)
                   .replace("{{UPDATE_TIME}}", now.strftime("%d.%m %H:%M"))
                   .replace("{{PROXY_COUNT}}", str(len(nodes)))
                   .replace("{{MAX_SPEED}}", str(int(top_speed)))
                   .replace("{{SUB_LINK}}", f"{public_url}/sub")
            )
            with open("index.html", "w", encoding="utf-8") as f:
                f.write(html_out)
        except Exception as e:
            logger.error(f"HTML build error: {e}")

    @staticmethod
    async def send_telegram_report(total_parsed: int, alive_nodes: List[ProxyNode], duration: float, dead_sources: List[str]):
        if not CONFIG.TG_BOT_TOKEN or not CONFIG.TG_CHAT_ID: 
            return
            
        top_speed = max((n.speed for n in alive_nodes), default=0.0)
        bs_count = sum(1 for n in alive_nodes if n.is_bs)
        public_url = CONFIG.app.get("public_url", "")
        
        dead_text = ""
        if dead_sources:
            dead_text = f"\n\n🗑️ <b>Dead Sources:</b> {len(dead_sources)}"

        msg = (
            f"💠 <b>System Core Report:</b>\n\n"
            f"📡 Parsed: {total_parsed}\n"
            f"🔋 Alive Total: {len(alive_nodes)}\n"
            f"🛡️ Verified Route: {bs_count}\n"
            f"☄️ Unfiltered Route: {len(alive_nodes) - bs_count}\n\n"
            f"⚡ Peak Bandwidth: {top_speed:.1f} Mbps\n"
            f"⏱️ Cycle Time: {duration:.1f}s{dead_text}\n\n"
            f"🌐 <a href='{public_url}'>Nexus Status</a>"
        )

        payload = {"chat_id": CONFIG.TG_CHAT_ID, "text": msg, "parse_mode": "HTML", "disable_web_page_preview": True}
        if CONFIG.TG_TOPIC_ID: payload["message_thread_id"] = CONFIG.TG_TOPIC_ID
        url = f"https://api.telegram.org/bot{CONFIG.TG_BOT_TOKEN}/sendMessage"
        
        async with aiohttp.ClientSession() as session:
            try: 
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    resp.raise_for_status()
            except Exception as e:
                logger.error(f"Telegram report failed: {e}")
