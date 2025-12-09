import aiohttp
import asyncio
import logging
import json
import os
import re
import pytz
import random
import feedparser
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from datetime import datetime, timedelta, date
from deep_translator import GoogleTranslator
import urllib.parse
import ssl
import certifi
import warnings
import google.generativeai as genai

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# ----- SSL FIX -----
try:
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
except:
    ssl_context = ssl._create_unverified_context()

logger = logging.getLogger("SecurityBot")

class IntelThread:
    def __init__(self):
        # Telegram
        self.tg_token = os.getenv("TELEGRAM_TOKEN")
        self.tg_chat_id = os.getenv("TELEGRAM_CHAT_ID")

        # Gemini AI
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        self.model = None
        if self.gemini_api_key:
            genai.configure(api_key=self.gemini_api_key)
            models = ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"]
            for m in models:
                try:
                    self.model = genai.GenerativeModel(m)
                    break
                except:
                    pass

        if not self.model:
            logger.warning("⚠️ Gemini pasif çalışıyor (AI fallback TR).")

        self.translator = GoogleTranslator(source="auto", target="tr")

        # Sayaçlar
        self.last_parsed_counts = {}
        self.failed_sources = {}

        # Dosyalar
        self.memory_file = "known_ids.json"
        self.notified_ids_file = "notified_ids.json"

        self.known_ids = self.load_json(self.memory_file, default={})
        notified_list = self.load_json(self.notified_ids_file, default=[])
        self.notified_ids = set(notified_list)

        # Kaynaklar
        self.sources = [
            {"name": "Tenable Plugins (New)", "url": "https://www.tenable.com/plugins/feeds?sort=newest", "type": "tenable"},
            {"name": "Tenable Plugins (Upd)", "url": "https://www.tenable.com/plugins/feeds?sort=updated", "type": "tenable"},
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
        ]

        self.news_sources = [
            "Google News Hunter",
            "BleepingComputer",
            "The Hacker News",
            "Dark Reading"
        ]

        # Headers
        self.headers = {
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (X11; Linux x86_64)"
            ])
        }

        # Günlük / aylık raporlama kayıtları
        self.news_buffer_file = "daily_news_buffer.json"
        self.daily_stats_file = "daily_stats.json"

        self.news_buffer = self.load_json(self.news_buffer_file, default=[])
        self.daily_stats = self.load_json(self.daily_stats_file, default={
            "date": str(date.today()), "total": 0, "critical": 0
        })

        self.last_news_report_date = None
        self.last_monthly_report_date = None
        self.last_heartbeat_date = None

    # ---------- JSON UTILITY ----------
    def load_json(self, path, default):
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r") as f:
                return json.load(f)
        except:
            return default

    def save_json(self, path, data):
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=4)
        except:
            pass

    # ---------- STRING UTIL ----------
    def normalize_id(self, raw):
        raw = raw.upper()
        m = re.search(r"CVE-\d{4}-\d+", raw)
        if m:
            return m.group(0)
        return raw[:40]

    def extract_severity_from_text(self, text):
        t = text.lower()
        if "critical" in t:
            return 9.8
        if "high" in t:
            return 8.0
        if "medium" in t:
            return 6.0
        return 0.0

    # Gemini veya fallback
    async def ai_summary(self, title, desc):
        text = f"{title}\n{desc}"
        if not self.model:
            try:
                return self.translator.translate(text)[:600]
            except:
                return text[:600]

        prompt = f"""
You are a cybersecurity analyst. Summarize the following vulnerability in English: 
Title: {title}
Details: {desc}

Then STOP. Do NOT explain more.
"""

        try:
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, self.model.generate_content, prompt)
            en = resp.text.strip()
            try:
                tr = self.translator.translate(en)
            except:
                tr = en
            return tr
        except:
            return text[:500]
    # ---------- TENABLE PLUGIN PAGE → CVSS SCORE ÇEK ----------
    async def fetch_tenable_cvss(self, session, plugin_url):
        """
        Tenable plugin sayfasına gider → Risk Information → CVSS3 / CVSS2 değerlerini çekmeye çalışır.
        Bir şey bulunamazsa 0 döner.
        """
        try:
            async with session.get(plugin_url, headers=self.headers, ssl=ssl_context, timeout=15) as r:
                if r.status != 200:
                    return 0.0
                html = await r.text()

            # CVSS3
            m = re.search(r"CVSSv3.*?(\d\.\d)", html, re.IGNORECASE | re.DOTALL)
            if m:
                return float(m.group(1))

            # CVSS2 fallback
            m2 = re.search(r"CVSSv2.*?(\d\.\d)", html, re.IGNORECASE | re.DOTALL)
            if m2:
                return float(m2.group(1))

            # Eğer sayfada direkt “Critical / High / Medium” geçiyorsa tahmini severity
            if "critical" in html.lower():
                return 9.8
            if "high" in html.lower():
                return 8.0
            if "medium" in html.lower():
                return 6.0

            return 0.0
        except:
            return 0.0

    # ---------- TENABLE RSS PARSER (NEW + UPDATED) ----------
    async def parse_tenable(self, session, source):
        """
        Tenable plugin feed sayfalarını parse eder.
        Her plugin için:
            - ID
            - Title
            - Description
            - Link
            - Publish Date
            - CVSS Score (RSS + Plugin Page)
        """
        items = []
        try:
            async with session.get(source["url"], headers=self.headers, ssl=ssl_context, timeout=20) as r:
                if r.status != 200:
                    self.failed_sources[source["name"]] = r.status
                    return []
                html = await r.text()

            soup = BeautifulSoup(html, "lxml")
            rows = soup.find_all("tr")

            for row in rows:
                link_tag = row.find("a")
                if not link_tag:
                    continue

                title = link_tag.text.strip()
                link = "https://www.tenable.com" + link_tag["href"]
                raw_id = link.split("/")[-1]

                desc = "Tenable Plugin"
                pub_ts = None

                # Publish date tespiti
                tds = row.find_all("td")
                if len(tds) >= 3:
                    pub_ts = tds[-1].text.strip()

                # Severity tahmini (title veya tablodan)
                severity_score = self.extract_severity_from_text(title)

                items.append({
                    "raw_id": raw_id,
                    "id": self.normalize_id(raw_id),
                    "title": title,
                    "desc": desc,
                    "link": link,
                    "score": severity_score,
                    "pub_ts": pub_ts,
                    "source": source["name"]
                })

            self.last_parsed_counts[source["name"]] = len(items)
            return items

        except Exception as e:
            self.failed_sources[source["name"]] = str(e)
            return []

    # ---------- GENEL RSS / FEED PARSER ----------
    async def parse_feed(self, session, source):
        try:
            async with session.get(source["url"], headers=self.headers, ssl=ssl_context, timeout=20) as r:
                if r.status != 200:
                    self.failed_sources[source["name"]] = r.status
                    return []
                data = await r.read()

            feed = feedparser.parse(data)
            items = []

            for entry in feed.entries[:10]:
                items.append({
                    "raw_id": entry.link,
                    "id": self.normalize_id(entry.link),
                    "title": entry.title,
                    "desc": entry.get("summary", ""),
                    "link": entry.link,
                    "score": self.extract_severity_from_text(entry.title),
                    "pub_ts": entry.get("published", None),
                    "source": source["name"]
                })

            self.last_parsed_counts[source["name"]] = len(items)
            return items

        except Exception as e:
            self.failed_sources[source["name"]] = str(e)
            return []

    # ---------- KAYNAK TİPİNE GÖRE PARSE ----------
    async def parse_source(self, session, source):
        if source["type"] == "tenable":
            return await self.parse_tenable(session, source)
        if source["type"] == "feed":
            return await self.parse_feed(session, source)
        return []

    # ---------- TÜM KAYNAKLARI ÇEK ----------
    async def fetch_all_sources(self):
        all_items = []
        async with aiohttp.ClientSession() as session:
            tasks = [self.parse_source(session, src) for src in self.sources]
            results = await asyncio.gather(*tasks)

            for res in results:
                all_items.extend(res)

        return all_items
    # ---------- TELEGRAM ----------
    async def send_telegram(self, text):
        if not self.tg_token:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {
            "chat_id": self.tg_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        try:
            async with aiohttp.ClientSession() as s:
                await s.post(url, json=payload)
        except:
            pass

    async def send_telegram_card(self, text, link=None):
        if not self.tg_token:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {
            "chat_id": self.tg_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": False
        }

        if link:
            payload["reply_markup"] = {
                "inline_keyboard": [[{"text": "🔗 Kaynak", "url": link}]]
            }

        try:
            async with aiohttp.ClientSession() as s:
                await s.post(url, json=payload)
        except:
            pass

    async def send_telegram_file(self, path):
        url = f"https://api.telegram.org/bot{self.tg_token}/sendDocument"
        data = aiohttp.FormData()
        data.add_field("chat_id", self.tg_chat_id)
        data.add_field("document", open(path, "rb"), filename=path)

        try:
            async with aiohttp.ClientSession() as s:
                await s.post(url, data=data)
        except:
            pass

    # ---------- DAILY RESET ----------
    def daily_reset_check(self):
        today = str(date.today())
        if self.daily_stats["date"] != today:
            self.daily_stats = {"date": today, "total": 0, "critical": 0}
            self.save_json(self.daily_stats_file, self.daily_stats)

    def update_daily_stats(self, item):
        self.daily_reset_check()
        self.daily_stats["total"] += 1
        if item.get("score", 0) >= 9.0:
            self.daily_stats["critical"] += 1
        self.save_json(self.daily_stats_file, self.daily_stats)

    # ---------- FORMAT ----------
    async def format_alert(self, item, upgraded=False):
        title = item["title"]
        link = item["link"]
        score = item["score"]
        plugin_id = item["id"]
        source = item["source"]

        ai_txt = await self.ai_summary(title, item["desc"])

        icon = "🛑" if score >= 9 else "⚠️" if score >= 7 else "🟠"

        header = "📈 SEVİYE YÜKSELDİ" if upgraded else "⚡ ACİL GÜVENLİK UYARISI"

        return f"""
<b>{icon} {header}</b>
<b>Kaynak:</b> {source}
<b>ID:</b> {plugin_id}
<b>CVSS:</b> {score}
<b>Başlık:</b> {title}

<b>AI Analiz (TR):</b>
{ai_txt}

🔗 {link}
"""

    # ---------- DAILY NEWS DIGEST ----------
    async def send_daily_news_digest(self):
        today = str(date.today())
        if self.last_news_report_date == today:
            return
        if not self.news_buffer:
            return

        report = "🗞️ <b>Günlük Siber Güvenlik Özeti</b>\n\n"

        for x in self.news_buffer:
            report += f"🔹 <b>{x['title']}</b>\n{x['ai_summary']}\n\n"

        await self.send_telegram(report)

        self.news_buffer = []
        self.save_json(self.news_buffer_file, [])
        self.last_news_report_date = today

    # ---------- MONTHLY EXECUTIVE REPORT ----------
    async def send_monthly_report(self):
        today = str(date.today())
        if self.last_monthly_report_date == today:
            return

        month_str = datetime.now().strftime("%m-%Y.json")
        if not os.path.exists(month_str):
            await self.send_telegram("⚠️ Aylık rapor bulunamadı.")
            return

        await self.send_telegram("📊 Aylık Rapor Hazırlanıyor...")

        try:
            with open(month_str, "r") as f:
                data = json.load(f)
        except:
            await self.send_telegram("⚠️ Rapor okunamadı.")
            return

        crit = len([x for x in data if x.get("score", 0) >= 9])
        high = len([x for x in data if 7 <= x.get("score", 0) < 9])
        med = len([x for x in data if 6 <= x.get("score", 0) < 7])

        chart_config = {
            "type": "pie",
            "data": {
                "labels": ["Critical", "High", "Medium"],
                "datasets": [{
                    "data": [crit, high, med],
                    "backgroundColor": ["#e74c3c", "#e67e22", "#f1c40f"]
                }]
            }
        }

        chart_url = f"https://quickchart.io/chart?c={urllib.parse.quote(json.dumps(chart_config))}"
        await self.send_telegram_card(
            f"📊 <b>Aylık Güvenlik Raporu</b>\nCritical: {crit}\nHigh: {high}\nMedium: {med}",
            link=chart_url
        )

        self.last_monthly_report_date = today
    # ---------- KOMUTLAR ----------
    async def check_commands(self):
        if not self.tg_token:
            return

        url = f"https://api.telegram.org/bot{self.tg_token}/getUpdates"
        params = {"timeout": 1}

        async with aiohttp.ClientSession() as s:
            try:
                resp = await s.get(url, params=params)
                data = await resp.json()

                for upd in data.get("result", []):
                    if "message" not in upd:
                        continue

                    msg = upd["message"]
                    chat_id = str(msg["chat"]["id"])
                    if chat_id != str(self.tg_chat_id):
                        continue

                    text = msg.get("text", "").strip().lower()

                    if text == "/durum":
                        await self.cmd_status()
                    elif text == "/debug":
                        await self.cmd_debug()
                    elif text == "/aylik":
                        await self.send_monthly_report()
                    elif text == "/tara":
                        await self.send_telegram("🚀 Manuel tarama başlatıldı!")
                        await self.process_intelligence()
                    elif text == "/indir":
                        await self.cmd_download()

            except:
                pass

    async def cmd_status(self):
        m_name = getattr(self.model, "model_name", "Pasif")
        msg = f"""
🤖 <b>SİSTEM DURUMU</b>

📌 AI: {m_name}
📌 Bilinen ID: {len(self.known_ids)}
📌 Bildirim Gönderilen ID: {len(self.notified_ids)}

📅 Bugün:
Toplam: {self.daily_stats.get("total",0)}
Kritik: {self.daily_stats.get("critical",0)}

⏱️ Son Tarama: {datetime.now().strftime("%H:%M:%S")}
"""
        await self.send_telegram(msg)

    async def cmd_debug(self):
        msg = "<b>🔧 DEBUG RAPORU</b>\n\n"

        if not self.failed_sources:
            msg += "🟢 Hiç hata yok.\n\n"
        else:
            msg += "🔴 Hatalı Kaynaklar:\n"
            for k, v in self.failed_sources.items():
                msg += f"• {k}: {v}\n"
            msg += "\n"

        msg += "📡 Kaynaklardan Gelen Kayıt Sayıları:\n"
        for src, cnt in self.last_parsed_counts.items():
            msg += f"• {src}: {cnt} kayıt\n"

        await self.send_telegram(msg)

    async def cmd_download(self):
        fname = datetime.now().strftime("%m-%Y.json")
        if not os.path.exists(fname):
            await self.send_telegram("⚠️ Bu aya ait rapor bulunamadı.")
        else:
            await self.send_telegram_file(fname)

    # ---------- ANA ZEKA: PROCESS INTELLIGENCE ----------
    async def process_intelligence(self):
        await self.check_commands()   # hızlı kontrol

        tr = pytz.timezone("Europe/Istanbul")
        now_tr = datetime.now(tr)
        self.daily_reset_check()

        # Günlük haber özeti
        if now_tr.hour == 18:
            await self.send_daily_news_digest()

        # Aylık rapor
        if now_tr.day == 1 and now_tr.hour == 9:
            await self.send_monthly_report()

        logger.info("🔎 Tehdit istihbarat taraması başlıyor...")

        # --- TÜM VERİ KAYNAKLARI ---
        all_items = await self.fetch_all_sources()
        now_utc = datetime.utcnow()

        for item in all_items:
            vid = item["id"]
            score = item.get("score", 0)
            source = item["source"]

            prev_score = self.known_ids.get(vid)

            # ——— Tenable publish time (24h kontrol) ———
            is_tenable = "Tenable" in source
            is_recent_24h = False

            if is_tenable and item.get("pub_ts"):
                try:
                    pub = item["pub_ts"]
                    if len(pub) > 10:
                        try:
                            pub_dt = datetime.strptime(pub, "%Y-%m-%d")
                        except:
                            pub_dt = datetime.utcnow()
                    else:
                        pub_dt = datetime.utcnow()

                    if (now_utc - pub_dt) <= timedelta(hours=24):
                        is_recent_24h = True
                except:
                    is_recent_24h = True

            # ---------- YENİ KAYIT ----------
            if prev_score is None:
                self.known_ids[vid] = score
                self.update_daily_stats(item)

                notify = False

                # Tenable için özel mantık → Son 24 saat + Medium+
                if is_tenable and score >= 6.0 and is_recent_24h:
                    notify = True

                # ZDI her zaman bildir
                if source == "ZeroDayInitiative":
                    notify = True

                if notify:
                    if vid not in self.notified_ids:
                        await self.handle_notification(item)
                        self.notified_ids.add(vid)

            # ---------- SEVİYE YÜKSELMESİ ----------
            elif score >= 8.5 and prev_score < 8.5:
                await self.handle_notification(item, upgraded=True)
                self.known_ids[vid] = score
                self.notified_ids.add(vid)

        self.save_json(self.memory_file, self.known_ids)
        self.save_json(self.notified_ids_file, list(self.notified_ids))

        logger.info("✅ Tarama tamamlandı.")

    # ---------- BİLDİRİM GÖNDERME ----------
    async def handle_notification(self, item, upgraded=False):
        formatted = await self.format_alert(item, upgraded)
        await self.send_telegram_card(formatted, link=item["link"])
