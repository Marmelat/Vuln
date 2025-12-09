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
import google.generativeai as genai
from datetime import datetime, timedelta, date
from dotenv import load_dotenv
from deep_translator import GoogleTranslator
import urllib.parse
import ssl
import certifi
import warnings

# XML ve SSL Uyarılarını Sustur
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# .env yükle
load_dotenv()

logger = logging.getLogger("SecurityBot")

# --- GLOBAL SSL FIX ---
try:
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
except Exception:
    ssl_context = ssl._create_unverified_context()


class IntelThread:
    def __init__(self):
        # --- 1. AYARLAR ---
        self.tg_token = os.getenv("TELEGRAM_TOKEN")
        self.tg_chat_id = os.getenv("TELEGRAM_CHAT_ID")

        # Gemini AI
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        self.model = None
        if self.gemini_api_key:
            genai.configure(api_key=self.gemini_api_key)
            models_to_try = [
                "gemini-1.5-flash",
                "gemini-1.5-flash-latest",
                "gemini-1.5-pro",
                "gemini-pro",
            ]
            for m in models_to_try:
                try:
                    genai.GenerativeModel(m)
                    self.model = genai.GenerativeModel(m)
                    break
                except Exception:
                    pass

        if not self.model:
            logger.warning("⚠️ AI Pasif")

        self.last_update_id = 0
        self.last_scan_timestamp = "Henüz Başlamadı"
        self.failed_sources = {}

        # Backend EN, sunum TR: translator sadece Telegram çıktısında kullanılacak
        self.translator = GoogleTranslator(source="auto", target="tr")

        # --- LİSTELER ---
        self.news_sources_list = [
            "Google News Hunter",
            "BleepingComputer",
            "The Hacker News",
            "Dark Reading",
        ]
        self.my_assets = [
            "wordpress",
            "fortinet",
            "cisco",
            "ubuntu",
            "nginx",
            "exchange server",
            "palo alto",
            "sql server",
        ]

        # --- 2. KAYNAKLAR ---
        self.sources = [
            # TENABLE (RSS feed gibi davranıyoruz)
            {
                "name": "Tenable Plugins (New)",
                "url": "https://www.tenable.com/plugins/feeds?sort=newest",
                "type": "tenable_rss",
            },
            {
                "name": "Tenable Plugins (Upd)",
                "url": "https://www.tenable.com/plugins/feeds?sort=updated",
                "type": "tenable_rss",
            },

            # TEKNİK API
            {
                "name": "GitHub Advisory",
                "url": "https://api.github.com/advisories?per_page=10&sort=published",
                "type": "api_github",
            },
            {
                "name": "CVE.org",
                "url": "https://cveawg.mitre.org/api/cve-id?cveState=PUBLISHED",
                "type": "api_json",
            },
            {
                "name": "NIST NVD",
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10",
                "type": "api_json",
            },

            # JSON FEED
            {
                "name": "CISA KEV",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "type": "json_simple",
            },

            # RSS FEED
            {
                "name": "Google News Hunter",
                "url": "https://news.google.com/rss/search?q=cyber+security+vulnerability+exploit+OR+zero-day+when:1d&hl=en-US&gl=US&ceid=US:en",
                "type": "feed",
            },
            {
                "name": "BleepingComputer",
                "url": "https://www.bleepingcomputer.com/feed/",
                "type": "feed",
            },
            {
                "name": "The Hacker News",
                "url": "https://feeds.feedburner.com/TheHackersNews",
                "type": "feed",
            },
            {
                "name": "Dark Reading",
                "url": "https://www.darkreading.com/rss.xml",
                "type": "feed",
            },
            {
                "name": "MSRC",
                "url": "https://api.msrc.microsoft.com/update-guide/rss",
                "type": "feed",
            },
            {
                "name": "CERT-EU",
                "url": "https://www.cert.europa.eu/feed/",
                "type": "feed",
            },
            {
                "name": "Tenable Research",
                "url": "https://www.tenable.com/blog/feed",
                "type": "feed",
            },
            {
                "name": "Wordfence (WP)",
                "url": "https://www.wordfence.com/feed/",
                "type": "feed",
            },
            {
                "name": "Cisco PSIRT",
                "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
                "type": "feed",
            },
            {
                "name": "Fortinet",
                "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
                "type": "feed",
            },
            {
                "name": "Palo Alto",
                "url": "https://security.paloaltonetworks.com/rss.xml",
                "type": "feed",
            },
            {
                "name": "Snyk Vuln",
                "url": "https://snyk.io/blog/feed.xml",
                "type": "feed",
            },
            {
                "name": "ZeroDayInitiative",
                "url": "https://www.zerodayinitiative.com/rss/published/",
                "type": "feed",
            },
            {
                "name": "PacketStorm",
                "url": "https://rss.packetstormsecurity.com/files/tags/exploit/",
                "type": "feed",
            },
            {
                "name": "Vulners",
                "url": "https://vulners.com/rss.xml",
                "type": "feed",
            },
        ]

        # Dosya Yönetimi
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        self.news_buffer_file = "daily_news_buffer.json"
        self.notified_ids_file = "notified_ids.json"

        self.known_ids = self.load_json_safe(self.memory_file)
        self.daily_stats = self.load_json_safe(self.daily_stats_file)
        self.news_buffer = self.load_json_safe(self.news_buffer_file, is_list=True)
        self.notified_ids = set(self.load_json_safe(self.notified_ids_file, is_list=True))

        if not isinstance(self.daily_stats, dict) or "date" not in self.daily_stats:
            self.daily_stats = {
                "date": str(date.today()),
                "total": 0,
                "critical": 0,
                "items": [],
            }

        self.check_daily_reset(force_check=True)
        self.last_flush_time = datetime.now()
        self.last_heartbeat_date = None
        self.last_news_report_date = None
        self.last_monthly_report_date = None

        # --- DİNAMİK USER-AGENT ---
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        ]

        self.headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    # --- 3. GEMINI AI (backend EN, sonra TR'ye çeviriyoruz) ---
    async def ask_gemini(self, title, description, source_name, is_news=False):
        # Model yoksa: ham İngilizce string dön (backend EN kalsın)
        if not self.model:
            return f"{title}\n{description}"

        try:
            if is_news:
                prompt = (
                    "You are a cyber security analyst. Summarize the following news in ONE short English sentence.\n"
                    f"Source: {source_name}\n"
                    f"Title: {title}\n"
                    f"Description: {description[:1500]}"
                )
            else:
                prompt = (
                    "You are a senior SOC analyst. Analyze the following vulnerability.\n\n"
                    f"Source: {source_name}\n"
                    f"Title: {title}\n"
                    f"Details: {description[:2000]}\n\n"
                    "Respond in **English** with the following structure (no code blocks):\n"
                    "📦 **Class:** [Operating System | Web App | Network | Mobile | Database]\n"
                    "🎯 **Target:** (Affected product and versions)\n"
                    "💀 **Risk:** (RCE, DoS, SQLi etc. - short summary)\n"
                    "🛡️ **Action:** (What should be done? - imperative form)\n"
                )
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, self.model.generate_content, prompt
            )
            return response.text.strip()
        except Exception:
            # Hata olursa da backend EN kalsın
            return f"{title}\n{description}"

    # --- 4. CHATOPS ---
    async def check_commands(self):
        if not self.tg_token:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/getUpdates"
        params = {"offset": self.last_update_id + 1, "timeout": 1}
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_context)
        ) as session:
            try:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        for update in data.get("result", []):
                            self.last_update_id = update["update_id"]
                            if "message" in update and "text" in update["message"]:
                                if str(update["message"]["chat"]["id"]) == str(
                                    self.tg_chat_id
                                ):
                                    await self.handle_command(
                                        update["message"]["text"]
                                    )
            except Exception:
                pass

    async def handle_command(self, command):
        cmd_parts = command.strip().split()
        cmd = cmd_parts[0].lower()
        if cmd in ["/durum", "/status"]:
            stats = self.daily_stats
            try:
                m_name = self.model.model_name
            except Exception:
                m_name = "Gemini"
            ai_status = f"✅ Aktif ({m_name})" if self.model else "⚠️ Pasif"
            if self.failed_sources:
                health_msg = f"⚠️ <b>{len(self.failed_sources)} Kaynak Hatalı</b>"
            else:
                health_msg = "✅ Sağlıklı"
            msg = (
                f"🤖 <b>SİSTEM DURUMU</b>\n"
                f"🕒 <b>Son Tarama:</b> {self.last_scan_timestamp}\n"
                f"📡 <b>Kaynaklar:</b> {health_msg}\n"
                f"🧠 <b>AI:</b> {ai_status}\n"
                f"📊 <b>Bugün:</b> {stats.get('total', 0)} veri, "
                f"{stats.get('critical', 0)} kritik."
            )
            await self.send_telegram_card(msg)

        elif cmd == "/debug":
            # Daha detaylı debug: başarısız kaynaklar + toplam known id sayısı
            if not self.failed_sources:
                msg = (
                    "✅ <b>Hata Yok</b>\n"
                    f"📚 Bilinen ID sayısı: {len(self.known_ids)}\n"
                    f"📨 Bildirim Gönderilen ID sayısı: {len(self.notified_ids)}"
                )
                await self.send_telegram_card(msg)
            else:
                errs = "\n".join(
                    [f"• {k}: {v}" for k, v in self.failed_sources.items()]
                )
                msg = (
                    "🔧 <b>HATA RAPORU</b>\n"
                    f"{errs}\n\n"
                    f"📚 Bilinen ID sayısı: {len(self.known_ids)}\n"
                    f"📨 Bildirim Gönderilen ID sayısı: {len(self.notified_ids)}"
                )
                await self.send_telegram_card(msg)

        elif cmd in ["/indir", "/rapor"]:
            tr = pytz.timezone("Europe/Istanbul")
            dosya = datetime.now(tr).strftime("%m-%Y.json")
            if os.path.exists(dosya):
                await self.send_telegram_card(f"📂 <b>{dosya}</b> yükleniyor...")
                await self.send_telegram_file(dosya)
            else:
                await self.send_telegram_card(f"⚠️ Dosya yok: {dosya}")

        elif cmd == "/tara":
            await self.send_telegram_card("🚀 Tarama başladı (bir sonraki periyodik döngüde çalışacak).")

        elif cmd == "/aylik":
            await self.send_telegram_card("📊 Aylık yönetici raporu hazırlanıyor...")
            await self.send_monthly_executive_report(force=True)

    # --- 5. LOGGING ---
    def log_to_monthly_json(self, item, old_score=None):
        try:
            tr = pytz.timezone("Europe/Istanbul")
            simdi = datetime.now(tr)
            dosya_ismi = (simdi + timedelta(minutes=10)).strftime("%m-%Y.json")
            entry = item.copy()
            entry["log_time"] = simdi.strftime("%Y-%m-%d %H:%M:%S")
            if old_score is not None:
                entry["update_log"] = f"🔺 {old_score} -> {item.get('score')}"
                entry["status"] = "ESCALATED"
            else:
                entry["status"] = "NEW"
            mevcut = []
            if os.path.exists(dosya_ismi):
                try:
                    with open(dosya_ismi, "r", encoding="utf-8") as f:
                        mevcut = json.load(f)
                except Exception:
                    mevcut = []
            mevcut.append(entry)
            with open(dosya_ismi, "w", encoding="utf-8") as f:
                json.dump(mevcut, f, ensure_ascii=False, indent=4)
        except Exception:
            pass

    # --- 6. RAPORLAMA ---
    async def generate_custom_report(self, start_date: datetime, end_date: datetime):
        target_files = set()
        curr = start_date
        while curr <= end_date:
            fname = curr.strftime("%m-%Y.json")
            target_files.add(fname)
            if curr.month == 12:
                curr = curr.replace(year=curr.year + 1, month=1, day=1)
            else:
                curr = curr.replace(month=curr.month + 1, day=1)

        filtered_data = []
        for f_name in target_files:
            if os.path.exists(f_name):
                try:
                    with open(f_name, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for item in data:
                            try:
                                log_time = datetime.strptime(
                                    item.get("log_time", ""), "%Y-%m-%d %H:%M:%S"
                                )
                                if start_date <= log_time <= end_date:
                                    filtered_data.append(item)
                            except Exception:
                                pass
                except Exception:
                    pass

        if not filtered_data:
            await self.send_telegram_card("⚠️ <b>Veri Dosyası Yok!</b>")
            return

        crit = sum(1 for i in filtered_data if i.get("score", 0) >= 8.5)
        high = sum(
            1 for i in filtered_data if 7.0 <= i.get("score", 0) < 8.5
        )
        escalated = sum(1 for i in filtered_data if i.get("status") == "ESCALATED")

        ai_comment = "Veri analizi yapılamadı."
        if self.model:
            top_risks = sorted(
                filtered_data, key=lambda x: x.get("score", 0), reverse=True
            )[:10]
            summary_text = "\n".join(
                [f"- {i.get('title')} ({i.get('score')})" for i in top_risks]
            )
            prompt = (
                "Write an executive summary in English for a monthly security report.\n"
                f"Date Range: {start_date.date()} - {end_date.date()}\n"
                f"Critical: {crit}, High: {high}\n"
                f"Top Items:\n{summary_text}\n"
            )
            try:
                resp = await asyncio.get_event_loop().run_in_executor(
                    None, self.model.generate_content, prompt
                )
                ai_comment = self.translate_text(resp.text.strip())
            except Exception:
                pass

        chart_config = {
            "type": "doughnut",
            "data": {
                "labels": ["KRITIK", "YUKSEK", "YUKSELEN"],
                "datasets": [
                    {
                        "data": [crit, high, escalated],
                        "backgroundColor": ["#E74C3C", "#E67E22", "#8E44AD"],
                    }
                ],
            },
            "options": {
                "title": {"display": True, "text": "AYLIK RAPOR", "fontColor": "#fff"},
                "legend": {"labels": {"fontColor": "#fff"}},
            },
        }
        chart_json = json.dumps(chart_config)
        chart_url = (
            "https://quickchart.io/chart?c="
            f"{urllib.parse.quote(chart_json)}&bkg=black&w=500&h=300"
        )
        caption = (
            "📊 <b>Aylık Yönetici Özeti</b>\n"
            f"🛑 Kritik: {crit}\n"
            f"⚠️ Yüksek: {high}\n"
            f"📈 Eskalasyon: {escalated}\n"
            f"📝 {ai_comment}"
        )

        await self.download_and_send_photo(chart_url, caption)

    async def send_monthly_executive_report(self, force: bool = False):
        tr = pytz.timezone("Europe/Istanbul")
        now = datetime.now(tr)
        today_str = str(now.date())
        if self.last_monthly_report_date == today_str and not force:
            return

        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_date = now
        await self.generate_custom_report(start_date, end_date)
        self.last_monthly_report_date = today_str

    async def send_daily_summary_report(self):
        stats = self.daily_stats
        msg = (
            "📅 <b>Gün Sonu Özeti</b>\n"
            f"📊 Toplam olay: {stats.get('total', 0)}\n"
            f"🛑 Kritik: {stats.get('critical', 0)}"
        )
        await self.send_telegram_card(msg)

    # --- 7. TELEGRAM ---
    async def download_and_send_photo(self, image_url, caption):
        if not self.tg_token:
            return
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=ssl_context)
            ) as session:
                async with session.get(image_url) as resp:
                    if resp.status == 200:
                        img_data = await resp.read()
                        url = f"https://api.telegram.org/bot{self.tg_token}/sendPhoto"
                        data = aiohttp.FormData()
                        data.add_field("chat_id", self.tg_chat_id)
                        data.add_field(
                            "photo", img_data, filename="chart.png"
                        )
                        data.add_field("caption", caption)
                        data.add_field("parse_mode", "HTML")
                        await session.post(url, data=data)
        except Exception:
            await self.send_telegram_card(f"{caption}\n(Grafik Yüklenemedi)")

    async def send_telegram_card(
        self, message, link=None, search_query=None, extra_ref=None
    ):
        if not self.tg_token:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {
            "chat_id": self.tg_chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        keyboard = []
        if link:
            keyboard.append({"text": "🔗 Kaynak", "url": link})
        if extra_ref:
            keyboard.append({"text": "🛡️ Resmi Çözüm", "url": extra_ref})
        elif search_query:
            q = search_query[:50].replace(" ", "+")
            keyboard.append(
                {
                    "text": "🛡️ Çözüm Ara",
                    "url": f"https://www.google.com/search?q={q}+patch",
                }
            )
        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": [keyboard]}

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=ssl_context)
            ) as s:
                await s.post(url, json=payload, headers=self.headers)
        except Exception:
            pass

    async def send_telegram_file(self, filepath):
        if not self.tg_token:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendDocument"
        data = aiohttp.FormData()
        data.add_field("chat_id", self.tg_chat_id)
        data.add_field(
            "document",
            open(filepath, "rb"),
            filename=os.path.basename(filepath),
        )
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=ssl_context)
            ) as s:
                await s.post(url, data=data)
        except Exception:
            pass

    async def send_telegram_photo(self, photo_url, caption):
        if not self.tg_token:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendPhoto"
        payload = {
            "chat_id": self.tg_chat_id,
            "photo": photo_url,
            "caption": caption,
            "parse_mode": "HTML",
        }
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=ssl_context)
            ) as s:
                await s.post(url, json=payload, headers=self.headers)
        except Exception:
            pass

    # --- 8. HABER BÜLTENİ ---
    async def send_daily_news_digest(self, force=False):
        today = str(date.today())
        if self.last_news_report_date == today and not force:
            return
        if not self.news_buffer:
            return
        report = (
            "🗞️ <b>SİBER GÜVENLİKTEN HAVADİSLER</b>\n"
            f"📅 <i>{today} | Gün Sonu</i>\n"
            "⎯⎯⎯⎯⎯⎯⎯\n\n"
        )
        for news in self.news_buffer:
            summary_tr = self.translate_text(news["ai_summary"])
            entry = (
                f"🔹 <a href='{news['link']}'>{news['title']}</a>\n"
                f"└ <i>{summary_tr}</i>\n\n"
            )
            if len(report) + len(entry) > 4000:
                await self.send_telegram_card(report)
                report = ""
            report += entry
        if report:
            await self.send_telegram_card(report)
        self.news_buffer = []
        self.save_json(self.news_buffer_file, [])
        self.last_news_report_date = today

    # --- 9. YARDIMCI ---
    def load_json_safe(self, filepath, is_list=False):
        default = [] if is_list else {}
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if is_list:
                        return data if isinstance(data, list) else default
                    else:
                        return {k: 0 for k in data} if isinstance(data, list) else data
            except Exception:
                return default
        return default

    def save_json(self, filepath, data):
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
        except Exception:
            pass

    def extract_official_solution_link(self, text):
        if not text:
            return None
        urls = re.findall(
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]"
            r"|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            text,
        )
        domains = [
            "microsoft.com",
            "cisco.com",
            "fortiguard.com",
            "tenable.com",
            "github.com",
            "oracle.com",
        ]
        for u in urls:
            if any(d in u for d in domains):
                return u
        return None

    def normalize_id(self, r, l="", t=""):
        txt = f"{r} {l} {t}".upper()
        if m := re.search(r"CVE-\d{4}-\d{4,7}", txt):
            return m.group(0)
        if "http" in r:
            return r.rstrip("/").split("/")[-1][:40]
        return r[:40]

    def extract_score(self, item):
        """
        Başlık + açıklama içinden skor çıkar.
        1) CVSS/score sayısı varsa onu kullan
        2) Yoksa 'Critical Severity / High Severity / Medium Severity' gibi
           Tenable / RSS kelimelerinden yaklaşık skor üret
        """
        txt = (item.get("title", "") + " " + item.get("desc", "")).lower()

        # 1) Sayısal CVSS / score var mı?
        m = re.search(r"(?:cvss|score)[\s:]*([0-9]{1,2}\.?[0-9]?)", txt)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass

        # 2) Severity kelimelerinden tahmini skor üret (özellikle Tenable RSS için)
        if "critical severity" in txt or "severity: critical" in txt:
            return 9.8
        if "high severity" in txt or "severity: high" in txt:
            return 8.0
        if "medium severity" in txt or "severity: medium" in txt:
            return 6.0
        if "low severity" in txt or "severity: low" in txt:
            return 3.0

        return 0.0

    async def enrich_with_epss(self, cve):
        if not cve.startswith("CVE"):
            return "N/A"
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=ssl_context)
            ) as s:
                async with s.get(
                    f"https://api.first.org/data/v1/epss?cve={cve}",
                    timeout=5,
                    headers=self.headers,
                ) as r:
                    d = await r.json()
                    return f"%{float(d['data'][0].get('epss', 0)) * 100:.2f}"
        except Exception:
            return "N/A"

    # 🔥 TENABLE CVSS PARSER
    def parse_tenable_cvss(self, html: str):
        """
        Tenable Nessus plugin sayfasındaki 'Risk Information' / CVSS v3/v2 skorunu çeker.
        Bulursa float döner, bulamazsa None döner.
        """
        try:
            soup = BeautifulSoup(html, "lxml")

            risk_block = (
                soup.find(id="risk-information")
                or soup.find("section", id="riskInformation")
                or soup
            )

            text = risk_block.get_text(" ", strip=True)

            m = re.search(
                r"CVSS\s*v?3[\.\d]*\s*(?:Base Score)?\s*([0-9]\.\d)",
                text,
                re.IGNORECASE,
            )
            if m:
                return float(m.group(1))

            m2 = re.search(
                r"CVSS\s*2[\.\d]*\s*(?:Base Score)?\s*([0-9]\.\d)",
                text,
                re.IGNORECASE,
            )
            if m2:
                return float(m2.group(1))

            if "Critical" in text:
                return 9.8
            if "High" in text:
                return 8.0

            return None
        except Exception as e:
            logger.error(f"Tenable CVSS parse hatası: {e}")
            return None

    async def enrich_score_from_web(self, url, current_score, session):
        """
        CVSS skoru yoksa, vendor sayfasına gidip çekmeye çalışır.
        Tenable plugin URL'leri için özel parser kullanır.
        """
        if current_score and current_score > 0.0:
            return current_score

        try:
            async with session.get(
                url, headers=self.headers, timeout=10
            ) as response:
                if response.status != 200:
                    logger.warning(
                        f"Skor için GET {url} status={response.status}"
                    )
                    return current_score or 0.0

                html = await response.text()

                if "tenable.com/plugins/nessus" in url:
                    tenable_score = self.parse_tenable_cvss(html)
                    if tenable_score is not None:
                        return tenable_score

                match = re.search(
                    r"(?:CVSS[^0-9]{0,20}|Base Score[^0-9]{0,20})(\d{1,2}\.\d)",
                    html,
                    re.IGNORECASE,
                )
                if match:
                    return float(match.group(1))

                if "Critical" in html:
                    return 9.8
                if "High" in html:
                    return 8.0

                return current_score or 0.0

        except Exception as e:
            logger.error(f"Skor enrich hatası {url}: {e}")
            return current_score or 0.0

    def check_daily_reset(self, force_check=False):
        today = str(date.today())
        if not isinstance(self.daily_stats, dict):
            self.daily_stats = {
                "date": today,
                "total": 0,
                "critical": 0,
                "items": [],
            }
        if self.daily_stats.get("date") != today:
            if not force_check:
                asyncio.create_task(self.send_daily_summary_report())
            self.daily_stats = {
                "date": today,
                "total": 0,
                "critical": 0,
                "items": [],
            }
            self.save_json(self.daily_stats_file, self.daily_stats)

    def update_daily_stats(self, item):
        self.check_daily_reset()
        self.daily_stats["total"] += 1
        if item.get("score", 0) >= 9.0:
            self.daily_stats["critical"] += 1
        self.save_json(self.daily_stats_file, self.daily_stats)

    def detect_os_and_tags(self, text):
        t = text.lower()
        sys = "Genel"
        tags = ["#CyberIntel"]
        maps = {
            "windows": "#Windows",
            "linux": "#Linux",
            "wordpress": "#WordPress",
            "ransomware": "#Ransomware",
            "cisco": "#Cisco",
        }
        for k, v in maps.items():
            if k in t:
                tags.append(v)
        return sys, " ".join(list(set(tags)))

    def translate_text(self, t):
        try:
            return self.translator.translate(t[:450])
        except Exception:
            return t

    async def check_heartbeat(self):
        now = datetime.now()
        today = str(date.today())
        if self.last_heartbeat_date != today and 9 <= now.hour < 10:
            await self.send_telegram_card(
                "🤖 <b>GÜNLÜK KONTROL</b>\n✅ Sistem Aktif"
            )
            self.last_heartbeat_date = today

    # --- FORMATLAMA ---
    async def format_alert_technical(self, item, header_title="ACİL UYARI"):
        score = item.get("score", 0)
        source_name = item.get("source", "")

        # AI analizi EN
        ai_output_en = await self.ask_gemini(
            item.get("title", ""),
            item.get("desc", ""),
            source_name,
            is_news=False,
        )
        if not ai_output_en:
            ai_output_en = "Analysis not available."

        # Telegram için TR çeviri
        ai_output_tr = self.translate_text(ai_output_en)

        epss_str = await self.enrich_with_epss(item["id"])
        icon = "🛑" if score >= 9 else "🟠"

        meta_info = (
            f"🆔 <b>{item['id']}</b>\n"
            f"📊 <b>CVSS:</b> {score} | <b>EPSS:</b> {epss_str}\n"
            f"📂 <b>Kaynak:</b> {source_name}"
        )

        return (
            f"<b>{icon} {header_title}</b>\n"
            "⎯⎯⎯⎯⎯⎯\n"
            f"{meta_info}\n\n"
            f"{ai_output_tr}\n"
        )

    # --- ANA DÖNGÜ ---
    async def fetch_all(self):
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_context)
        ) as s:
            tasks = [self.parse_generic(s, src, src["type"]) for src in self.sources]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

    async def parse_generic(self, session, source, mode):
        try:
            await asyncio.sleep(random.uniform(30.0, 60.0))
            timeout = aiohttp.ClientTimeout(total=40)
            items = []

            # --- TENABLE RSS ---
            if mode == "tenable_rss":
                async with session.get(
                    source["url"], timeout=timeout, headers=self.headers
                ) as r:
                    if r.status != 200:
                        self.failed_sources[source["name"]] = r.status
                        return []
                    content = await r.read()
                    f = feedparser.parse(content)
                    for e in f.entries[:20]:
                        link = e.link
                        raw_id = link.split("/")[-1]
                        pub_ts = None
                        if hasattr(e, "published_parsed") and e.published_parsed:
                            pub_dt = datetime(*e.published_parsed[:6])
                            pub_ts = pub_dt.isoformat()
                        items.append(
                            {
                                "raw_id": raw_id,
                                "title": e.title,
                                "desc": getattr(e, "summary", ""),
                                "link": link,
                                "score": 0.0,
                                "pub_ts": pub_ts,
                            }
                        )

            # --- GITHUB ADVISORY API ---
            elif mode == "api_github":
                async with session.get(
                    source["url"], timeout=timeout, headers=self.headers
                ) as r:
                    if r.status != 200:
                        self.failed_sources[source["name"]] = r.status
                        return []
                    d = await r.json()
                    for adv in d[:10]:
                        items.append(
                            {
                                "raw_id": adv.get("ghsa_id") or adv.get("id"),
                                "title": adv.get("summary")
                                or adv.get("ghsa_id")
                                or "GitHub Advisory",
                                "desc": adv.get("description", ""),
                                "link": adv.get("html_url")
                                or adv.get("url", ""),
                                "score": 0.0,
                            }
                        )

            # --- GENEL JSON API (NVD / CVE.ORG) ---
            elif mode == "api_json":
                async with session.get(
                    source["url"], timeout=timeout, headers=self.headers
                ) as r:
                    if r.status != 200:
                        self.failed_sources[source["name"]] = r.status
                        return []
                    d = await r.json()

                    if "NVD" in source["name"] or "NIST" in source["name"]:
                        for v in d.get("vulnerabilities", [])[:10]:
                            cve = v.get("cve", {})
                            cid = cve.get("id")
                            if not cid:
                                continue
                            items.append(
                                {
                                    "raw_id": cid,
                                    "title": f"NIST: {cid}",
                                    "desc": "NIST record.",
                                    "link": f"https://nvd.nist.gov/vuln/detail/{cid}",
                                    "score": 0.0,
                                }
                            )
                    else:
                        for cv in d.get("cve_ids", [])[:10]:
                            cid = cv.get("cve_id")
                            if not cid:
                                continue
                            items.append(
                                {
                                    "raw_id": cid,
                                    "title": f"New CVE: {cid}",
                                    "desc": "Newly published vulnerability.",
                                    "link": f"https://www.cve.org/CVERecord?id={cid}",
                                    "score": 0.0,
                                }
                            )

            # --- CISA KEV JSON ---
            elif mode == "json_simple":
                async with session.get(
                    source["url"], timeout=timeout, headers=self.headers
                ) as r:
                    if r.status != 200:
                        self.failed_sources[source["name"]] = r.status
                        return []
                    d = await r.json()
                    for i in d.get("vulnerabilities", [])[:20]:
                        cid = i.get("cveID")
                        if not cid:
                            continue
                        items.append(
                            {
                                "raw_id": cid,
                                "title": i.get("vulnerabilityName", cid),
                                "desc": i.get("shortDescription", ""),
                                "link": f"https://www.cve.org/CVERecord?id={cid}",
                                "score": 10.0,
                            }
                        )

            # --- RSS / FEED GENEL ---
            elif mode == "feed":
                async with session.get(
                    source["url"], timeout=timeout, headers=self.headers
                ) as r:
                    if r.status != 200:
                        self.failed_sources[source["name"]] = r.status
                        return []
                    content = await r.read()
                    f = feedparser.parse(content)
                    for e in f.entries[:5]:
                        items.append(
                            {
                                "raw_id": getattr(e, "guid", e.link),
                                "title": e.title,
                                "desc": getattr(e, "summary", ""),
                                "link": e.link,
                                "score": 0.0,
                            }
                        )

            final = []
            for i in items:
                i["score"] = self.extract_score(i)

                if (
                    i["score"] == 0.0
                    and i.get("link")
                    and source["name"] not in self.news_sources_list
                ):
                    i["score"] = await self.enrich_score_from_web(
                        i["link"], i["score"], session
                    )

                i["id"] = self.normalize_id(
                    i.get("raw_id", ""), i.get("link", ""), i.get("title", "")
                )
                i["source"] = source["name"]
                final.append(i)

            logger.info(f"[{source['name']}] parsed items: {len(final)}")
            return final

        except Exception as e:
            logger.error(f"Kaynak {source['name']} genel hata: {e}")
            self.failed_sources[source["name"]] = "EXC"
            return []

    async def process_intelligence(self):
        await self.check_commands()

        tr = pytz.timezone("Europe/Istanbul")
        simdi = datetime.now(tr)
        self.last_scan_timestamp = simdi.strftime("%H:%M:%S")

        if simdi.hour == 18 and self.last_news_report_date != str(date.today()):
            await self.send_daily_news_digest()

        if (
            simdi.weekday() == 0
            and simdi.hour == 9
            and self.last_monthly_report_date != str(date.today())
        ):
            await self.send_monthly_executive_report()

        logger.info("🔎 Tarama Sürüyor (Tenable-RSS + CVSS)...")
        self.check_daily_reset()
        await self.check_heartbeat()

        all_threats = await self.fetch_all()
        now_utc = datetime.utcnow()

        for threat in all_threats:
            tid = threat["id"]
            curr = threat.get("score", 0)
            prev = self.known_ids.get(tid)
            src = threat.get("source", "")
            is_news = src in self.news_sources_list
            notify = False
            is_upd = False

            # 24 SAAT İÇİNDE GÜNCELLENEN TENABLE CRITICAL'LERİ ZORLA KONTROL ET
            if "Tenable" in src and curr >= 8.5 and tid not in self.notified_ids:
                pub_ts = threat.get("pub_ts")
                if pub_ts:
                    try:
                        pub_dt = datetime.fromisoformat(pub_ts)
                        if (now_utc - pub_dt) <= timedelta(hours=24):
                            notify = True
                    except Exception:
                        pass

            # YENİ KAYIT
            if prev is None:
                self.known_ids[tid] = curr
                self.update_daily_stats(threat)
                self.log_to_monthly_json(threat)

                if is_news:
                    ai_summary_en = await self.ask_gemini(
                        threat.get("title", ""),
                        threat.get("desc", ""),
                        src,
                        True,
                    )
                    self.news_buffer.append(
                        {
                            "title": threat["title"],
                            "link": threat["link"],
                            "ai_summary": ai_summary_en,
                        }
                    )
                    self.save_json(self.news_buffer_file, self.news_buffer)
                else:
                    if curr >= 8.5:
                        notify = True or notify  # zaten True ise bozulmasın
                    elif threat["source"] == "CISA KEV":
                        notify = True or notify
                    elif threat["source"] == "ZeroDayInitiative":
                        notify = True or notify
                    elif "Tenable" in threat["source"] and curr >= 7.0:
                        notify = True or notify

                    if any(
                        a in (threat["title"] + threat["desc"]).lower()
                        for a in self.my_assets
                    ):
                        notify = True or notify

            # VAR OLAN KAYIT (NEWS DEĞİL)
            elif not is_news:
                if curr >= 8.5 and prev < 8.5:
                    is_upd = True
                    notify = True or notify
                    self.known_ids[tid] = curr
                    self.log_to_monthly_json(threat, old_score=prev)

            if notify and not is_news:
                header = (
                    "📈 SEVİYE YÜKSELDİ"
                    if is_upd
                    else "ACİL GÜVENLİK UYARISI"
                )
                msg = await self.format_alert_technical(threat, header)
                ref = self.extract_official_solution_link(
                    threat.get("desc", "")
                )
                search = threat["title"] if "http" in tid else tid
                await self.send_telegram_card(
                    msg, link=threat["link"], search_query=search, extra_ref=ref
                )

                self.notified_ids.add(tid)
                self.save_json(self.notified_ids_file, list(self.notified_ids))
                self.save_json(self.memory_file, self.known_ids)

        self.save_json(self.memory_file, self.known_ids)
        self.save_json(self.notified_ids_file, list(self.notified_ids))
