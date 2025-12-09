import aiohttp
import asyncio
import logging
import json
import os
import re
import pytz
import random
import feedparser
from bs4 import BeautifulSoup
import google.generativeai as genai
from datetime import datetime, timedelta, date
from dotenv import load_dotenv
from deep_translator import GoogleTranslator
import urllib.parse
import ssl 
import certifi 
import warnings

# Gereksiz uyarıları sustur
warnings.filterwarnings("ignore")

# .env yükle
load_dotenv()

logger = logging.getLogger("SecurityBot")

# --- GLOBAL SSL FIX ---
try:
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
except:
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
            models_to_try = ['gemini-1.5-flash', 'gemini-1.5-flash-latest', 'gemini-1.5-pro', 'gemini-pro']
            for m in models_to_try:
                try:
                    genai.GenerativeModel(m) 
                    self.model = genai.GenerativeModel(m)
                    break
                except: pass
        
        if not self.model: logger.warning("⚠️ AI Pasif")

        self.last_update_id = 0
        self.last_scan_timestamp = "Henüz Başlamadı"
        self.failed_sources = {} 
        self.translator = GoogleTranslator(source='auto', target='tr')
        
        # --- LİSTELER ---
        self.news_sources_list = ["Google News Hunter", "BleepingComputer", "The Hacker News", "Dark Reading"]
        self.my_assets = ["wordpress", "fortinet", "cisco", "ubuntu", "nginx", "exchange server", "palo alto", "sql server"]
        
        # --- DİNAMİK USER-AGENT HAVUZU (HER İSTEKTE KİMLİK DEĞİŞİR) ---
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        ]

        # --- 2. KAYNAKLAR (TENABLE HTML & TEKNİK) ---
        self.sources = [
            # TENABLE (Özel İlgi - HTML)
            {"name": "Tenable Plugins (New)", "url": "https://www.tenable.com/plugins/feeds?sort=newest", "type": "html_tenable"},
            {"name": "Tenable Plugins (Upd)", "url": "https://www.tenable.com/plugins/feeds?sort=updated", "type": "html_tenable"},

            # DEVLET & OTORİTE
            {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_cisa"},
            {"name": "NIST NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&pubStartDate=", "type": "json_nist"},
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?cveState=PUBLISHED&time_modified_gt=", "type": "json_cveorg"},
            {"name": "CERT-EU", "url": "https://www.cert.europa.eu/feed/", "type": "feed"},

            # VENDOR
            {"name": "MSRC", "url": "https://api.msrc.microsoft.com/update-guide/rss", "type": "feed"},
            {"name": "GitHub Advisory", "url": "https://github.com/advisories.atom", "type": "feed"}, 
            {"name": "Cisco PSIRT", "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "type": "feed"},
            {"name": "Fortinet", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "feed"},
            {"name": "Palo Alto", "url": "https://security.paloaltonetworks.com/rss.xml", "type": "feed"},
            {"name": "Snyk Vuln", "url": "https://snyk.io/blog/feed.xml", "type": "feed"}, 
            
            # EXPLOIT & ZERO-DAY
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/files/tags/exploit/", "type": "feed"},
            {"name": "Vulners", "url": "https://vulners.com/rss.xml", "type": "feed"},
        ]
        
        # Dosya Yönetimi
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        
        self.known_ids = self.load_json_safe(self.memory_file)
        self.daily_stats = self.load_json_safe(self.daily_stats_file)
        
        if not isinstance(self.daily_stats, dict) or "date" not in self.daily_stats:
            self.daily_stats = {"date": str(date.today()), "total": 0, "critical": 0, "items": []}
            
        self.check_daily_reset(force_check=True)
        self.last_flush_time = datetime.now()
        self.last_heartbeat_date = None
        self.last_monthly_report_date = None

    # --- YENİ: PROFESYONEL İSTEK MOTORU (SMART FETCHER) ---
    async def fetch_content_robust(self, url, session):
        """
        Bu fonksiyon, isteği atar, hata alırsa bekleyip tekrar dener (Retry Logic).
        Her denemede farklı bir User-Agent kullanır (Identity Rotation).
        """
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Rastgele bir kimlik seç
                current_ua = random.choice(self.user_agents)
                headers = {
                    "User-Agent": current_ua,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive"
                }
                
                # İsteği at (SSL Fix ile)
                async with session.get(url, headers=headers, timeout=30, ssl=ssl_context) as response:
                    if response.status == 200:
                        return await response.read()
                    elif response.status in [429, 503]:
                        # Sunucu "Çok hızlı geliyorsun" dediyse bekle (Exponential Backoff)
                        await asyncio.sleep(2 ** (attempt + 1)) 
                    else:
                        # 404 gibi kalıcı hatalarda bekleme, çık
                        return None
            except Exception as e:
                await asyncio.sleep(2)
        return None

    # --- 3. GEMINI AI ---
    async def ask_gemini(self, title, description, source_name):
        if not self.model: return self.translate_text(f"{title}\n{description}")
        try:
            prompt = (
                f"Sen kıdemli bir güvenlik uzmanısın. Analiz et.\n"
                f"Kaynak: {source_name}\nBaşlık: {title}\nDetay: {description[:2000]}\n\n"
                f"Çıktı Formatı (Markdown, kod bloğu yok):\n"
                f"📦 **Sınıf:** [İşletim Sistemi | Web App | Network | Lib | Diğer]\n"
                f"🎯 **Hedef:** (Etkilenen ürün)\n"
                f"⚡ **Özet:** Zafiyetin nedeni?\n"
                f"💀 **Risk:** (RCE, DoS, SQLi vb.)\n"
                f"🛡️ **Aksiyon:** (Sürüm ver, emir kipi kullan)"
            )
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self.model.generate_content, prompt)
            return response.text.strip()
        except: return self.translate_text(f"{title}\n{description}")[:300]

    # --- 4. CHATOPS ---
    async def check_commands(self):
        if not self.tg_token: return
        url = f"https://api.telegram.org/bot{self.tg_token}/getUpdates"
        params = {"offset": self.last_update_id + 1, "timeout": 1}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        for update in data.get("result", []):
                            self.last_update_id = update["update_id"]
                            if "message" in update and "text" in update["message"]:
                                if str(update["message"]["chat"]["id"]) == str(self.tg_chat_id):
                                    await self.handle_command(update["message"]["text"])
            except: pass

    async def handle_command(self, command):
        cmd_parts = command.strip().split()
        cmd = cmd_parts[0].lower()
        if cmd in ["/durum", "/status"]:
            stats = self.daily_stats
            try: m_name = self.model.model_name
            except: m_name = "Gemini"
            ai_status = f"✅ Aktif ({m_name})" if self.model else "⚠️ Pasif"
            health_msg = f"⚠️ {len(self.failed_sources)} Hatalı" if self.failed_sources else "✅ Sağlıklı"
            msg = (
                f"🤖 <b>SİSTEM DURUMU</b>\n🕒 <b>Son Tarama:</b> {self.last_scan_timestamp}\n"
                f"📡 <b>Kaynaklar:</b> {health_msg}\n🧠 <b>AI:</b> {ai_status}\n"
                f"📊 <b>Bugün:</b> {stats.get('total', 0)} veri."
            )
            await self.send_telegram_card(msg)
        elif cmd == "/debug":
            if not self.failed_sources: await self.send_telegram_card("✅ Harika! Hata yok.")
            else:
                errs = "\n".join([f"• {k}: {v}" for k,v in self.failed_sources.items()])
                await self.send_telegram_card(f"🔧 <b>HATA DETAYI</b>\n{errs}")
        elif cmd in ["/indir", "/rapor"]:
            tr = pytz.timezone('Europe/Istanbul')
            dosya = datetime.now(tr).strftime("%m-%Y.json")
            if os.path.exists(dosya):
                await self.send_telegram_card(f"📂 <b>{dosya}</b> yükleniyor...")
                await self.send_telegram_file(dosya)
            else: await self.send_telegram_card(f"⚠️ Dosya yok: {dosya}")
        elif cmd == "/tara": await self.send_telegram_card("🚀 Tarama başladı.")
        elif cmd == "/aylik": await self.send_monthly_executive_report(force=True)

    # --- 5. LOGGING ---
    def log_to_monthly_json(self, item, old_score=None):
        try:
            tr = pytz.timezone('Europe/Istanbul')
            simdi = datetime.now(tr)
            dosya_ismi = (simdi + timedelta(minutes=10)).strftime("%m-%Y.json")
            entry = item.copy()
            entry['log_time'] = simdi.strftime("%Y-%m-%d %H:%M:%S")
            if old_score is not None:
                entry['update_log'] = f"🔺 {old_score} -> {item.get('score')}"
                entry['status'] = "ESCALATED"
            else: entry['status'] = "NEW"
            mevcut = []
            if os.path.exists(dosya_ismi):
                try:
                    with open(dosya_ismi, 'r', encoding='utf-8') as f: mevcut = json.load(f)
                except: mevcut = []
            mevcut.append(entry)
            with open(dosya_ismi, 'w', encoding='utf-8') as f: json.dump(mevcut, f, ensure_ascii=False, indent=4)
        except: pass

    # --- 6. RAPORLAMA ---
    async def generate_custom_report(self, start_date, end_date):
        target_files = set()
        curr = start_date
        while curr <= end_date:
            fname = curr.strftime("%m-%Y.json")
            target_files.add(fname)
            if curr.month == 12: curr = curr.replace(year=curr.year+1, month=1, day=1)
            else: curr = curr.replace(month=curr.month+1, day=1)
        
        filtered_data = []
        for f_name in target_files:
            if os.path.exists(f_name):
                try:
                    with open(f_name, 'r') as f:
                        data = json.load(f)
                        for item in data:
                            try:
                                log_time = datetime.strptime(item.get('log_time', ''), "%Y-%m-%d %H:%M:%S")
                                if start_date <= log_time <= end_date: filtered_data.append(item)
                            except: pass
                except: pass

        if not filtered_data:
            await self.send_telegram_card("⚠️ <b>Kayıt Bulunamadı!</b>")
            return

        await self.send_telegram_card("⏳ <b>Rapor hazırlanıyor...</b>")

        crit = sum(1 for i in filtered_data if i.get('score', 0) >= 8.5)
        high = sum(1 for i in filtered_data if 7.0 <= i.get('score', 0) < 8.5)
        escalated = sum(1 for i in filtered_data if i.get('status') == "ESCALATED")
        
        ai_comment = "Veri analizi yapılamadı."
        if self.model:
            top_risks = sorted(filtered_data, key=lambda x: x.get('score', 0), reverse=True)[:10]
            summary_text = "\n".join([f"- {i.get('title')} ({i.get('score')})" for i in top_risks])
            prompt = f"Rapor Özeti Yaz.\nTarih: {start_date.date()}-{end_date.date()}\nKritik: {crit}, Yüksek: {high}\nEn Önemli:\n{summary_text}\nYönetici özeti yaz."
            try:
                resp = await asyncio.get_event_loop().run_in_executor(None, self.model.generate_content, prompt)
                ai_comment = resp.text.strip()
            except: pass

        chart_config = {
            "type": "doughnut",
            "data": {
                "labels": ["KRITIK", "YUKSEK", "YUKSELEN"],
                "datasets": [{"data": [crit, high, escalated], "backgroundColor": ["#E74C3C", "#E67E22", "#8E44AD"]}]
            },
            "options": {"title": {"display": True, "text": "RAPOR", "fontColor": "#fff"}, "legend": {"labels": {"fontColor": "#fff"}}}
        }
        chart_json = json.dumps(chart_config)
        chart_url = f"https://quickchart.io/chart?c={urllib.parse.quote(chart_json)}&bkg=black&w=500&h=300"
        caption = f"📊 <b>ÖZEL RAPOR</b>\n🛑 Kritik: {crit}\n📈 Eskalasyon: {escalated}\n📝 {ai_comment}"
        
        await self.download_and_send_photo(chart_url, caption)

    # --- 7. TELEGRAM ---
    async def download_and_send_photo(self, image_url, caption):
        if not self.tg_token: return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(image_url) as resp:
                    if resp.status == 200:
                        img_data = await resp.read()
                        url = f"https://api.telegram.org/bot{self.tg_token}/sendPhoto"
                        data = aiohttp.FormData()
                        data.add_field('chat_id', self.tg_chat_id)
                        data.add_field('photo', img_data, filename='chart.png')
                        data.add_field('caption', caption)
                        data.add_field('parse_mode', 'HTML')
                        await session.post(url, data=data)
        except Exception as e:
            await self.send_telegram_card(f"{caption}\n(Grafik Yüklenemedi)")

    async def send_telegram_card(self, message, link=None, search_query=None, extra_ref=None):
        if not self.tg_token: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {"chat_id": self.tg_chat_id, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True}
        keyboard = []
        if link: keyboard.append({"text": "🔗 Kaynak", "url": link})
        if extra_ref: keyboard.append({"text": "🛡️ Resmi Çözüm", "url": extra_ref})
        elif search_query:
            q = search_query[:50].replace(" ", "+")
            keyboard.append({"text": "🛡️ Çözüm Ara", "url": f"https://www.google.com/search?q={q}+patch"})
        if keyboard: payload["reply_markup"] = {"inline_keyboard": [keyboard]}
        
        try:
            async with aiohttp.ClientSession() as s:
                await s.post(url, json=payload, headers=self.headers)
        except: pass

    async def send_telegram_file(self, filepath):
        url = f"https://api.telegram.org/bot{self.tg_token}/sendDocument"
        data = aiohttp.FormData()
        data.add_field('chat_id', self.tg_chat_id)
        data.add_field('document', open(filepath, 'rb'), filename=os.path.basename(filepath))
        try:
            async with aiohttp.ClientSession() as s:
                await s.post(url, data=data)
        except: pass

    async def send_telegram_photo(self, photo_url, caption):
        url = f"https://api.telegram.org/bot{self.tg_token}/sendPhoto"
        payload = {"chat_id": self.tg_chat_id, "photo": photo_url, "caption": caption, "parse_mode": "HTML"}
        try:
            async with aiohttp.ClientSession() as s:
                await s.post(url, json=payload, headers=self.headers)
        except: pass

    # --- 9. YARDIMCI ---
    def load_json_safe(self, filepath, is_list=False):
        default = [] if is_list else {}
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    if is_list: return data if isinstance(data, list) else default
                    else: return {k: 0 for k in data} if isinstance(data, list) else data
            except: return default
        return default
    
    def save_json(self, filepath, data):
        try: with open(filepath, 'w') as f: json.dump(data, f)
        except: pass
    
    def extract_official_solution_link(self, text):
        if not text: return None
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        domains = ["microsoft.com", "cisco.com", "fortiguard.com", "paloaltonetworks.com", "tenable.com", "github.com"]
        for u in urls:
            if any(d in u for d in domains): return u
        return None
    
    def normalize_id(self, r, l="", t=""):
        txt = f"{r} {l} {t}".upper()
        if m := re.search(r"CVE-\d{4}-\d{4,7}", txt): return m.group(0)
        if "http" in r: return r.rstrip('/').split('/')[-1][:40]
        return r[:40]
    
    def extract_score(self, item):
        txt = (item.get('title','') + item.get('desc','')).lower()
        if m := re.search(r"(?:cvss|score)[\s:]*([0-9]{1,2}\.?[0-9]?)", txt): return float(m.group(1))
        return 0.0
    
    async def enrich_with_epss(self, cve):
        if not cve.startswith("CVE"): return "N/A"
        try:
            # EPSS için de robust fetch kullan
            content = await self.fetch_content_robust(f"https://api.first.org/data/v1/epss?cve={cve}", aiohttp.ClientSession())
            if content:
                d = json.loads(content)
                return f"%{float(d['data'][0].get('epss',0))*100:.2f}"
        except: return "N/A"

    async def enrich_score_from_web(self, url, current_score):
        if current_score > 0.0: return current_score
        try:
            # DEEP SCOUT da artık robust fetch kullanıyor (Anti-Ban)
            async with aiohttp.ClientSession() as session:
                html_bytes = await self.fetch_content_robust(url, session)
                if html_bytes:
                    html = html_bytes.decode('utf-8', errors='ignore')
                    match = re.search(r"(?:CVSS|Base Score|Score).*?(\d{1,2}\.\d)", html, re.IGNORECASE)
                    if match: return float(match.group(1))
                    if "Critical" in html or "High" in html: return 9.0 
            return 0.0
        except: return 0.0
    
    def check_daily_reset(self, force_check=False):
        today = str(date.today())
        if not isinstance(self.daily_stats, dict): self.daily_stats = {"date": today, "total": 0, "critical": 0, "items": []}
        if self.daily_stats.get("date") != today:
            if not force_check: asyncio.create_task(self.send_daily_summary_report())
            self.daily_stats = {"date": today, "total": 0, "critical": 0, "items": []}
            self.save_json(self.daily_stats_file, self.daily_stats)

    def update_daily_stats(self, item):
        self.check_daily_reset()
        self.daily_stats["total"] += 1
        if item.get('score', 0) >= 9.0: self.daily_stats["critical"] += 1
        self.save_json(self.daily_stats_file, self.daily_stats)

    def detect_os_and_tags(self, text):
        t = text.lower()
        sys = "Genel"
        tags = ["#CyberIntel"]
        maps = {"windows": "#Windows", "linux": "#Linux", "wordpress": "#WordPress", "ransomware": "#Ransomware", "cisco": "#Cisco"}
        for k, v in maps.items(): 
            if k in t: tags.append(v)
        return sys, " ".join(list(set(tags)))

    def translate_text(self, t):
        try: return self.translator.translate(t[:450])
        except: return t

    async def check_heartbeat(self):
        now = datetime.now()
        today = str(date.today())
        if self.last_heartbeat_date != today and 9 <= now.hour < 10:
            await self.send_telegram_card("🤖 <b>GÜNLÜK KONTROL</b>\n✅ Sistem Aktif")
            self.last_heartbeat_date = today

    async def send_monthly_executive_report(self, force=False):
        today = date.today()
        next_monday = today + timedelta(days=7)
        is_last_monday = (today.weekday() == 0 and next_monday.month != today.month)
        if not force:
            if not is_last_monday: return
            if str(today) == self.last_monthly_report_date: return
        tr = pytz.timezone('Europe/Istanbul')
        start = datetime(today.year, today.month, 1, tzinfo=tr).replace(tzinfo=None)
        end = (start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        await self.generate_custom_report(start, end)
        self.last_monthly_report_date = str(today)

    # --- FORMATLAMA ---
    async def format_alert_technical(self, item, header_title="ACİL UYARI"):
        score = item.get('score', 0)
        source_name = item.get('source', '')
        
        ai_analiz_raw = await self.ask_gemini(item.get('title', ''), item.get('desc', ''), source_name, is_news=False)
        
        if "Model" in ai_analiz_raw or "Pasif" in ai_analiz_raw:
             ai_output = f"📦 **Sınıf:** Genel Zafiyet (AI Pasif)\n"
             ai_output += f"🎯 **Hedef Sistem:** Analiz Edilemedi\n\n"
             ai_output += ai_analiz_raw
        else:
             ai_output = ai_analiz_raw
        
        epss_str = await self.enrich_with_epss(item['id'])
        icon = "🛑" if score >= 9 else "🟠"
        meta_info = f"🆔 <b>{item['id']}</b>\n📊 <b>CVSS:</b> {score} | <b>EPSS:</b> {epss_str}\n📂 <b>Kaynak:</b> {source_name}"

        return (
            f"<b>{icon} {header_title}</b>\n"
            f"⎯⎯⎯⎯⎯⎯\n"
            f"{meta_info}\n\n"
            f"{ai_output}\n"
        )

    # --- ANA DÖNGÜ (SEMAPHORE İLE TRAFİK KONTROLÜ) ---
    async def fetch_all(self):
        # YENİ: Aynı anda sadece 2 istek at (Trafik polisi)
        sem = asyncio.Semaphore(2) 
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for src in self.sources:
                task = self.parse_generic_with_semaphore(sem, session, src, src["type"])
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

    async def parse_generic_with_semaphore(self, sem, session, source, mode):
        async with sem: # Sadece 2 işçi aynı anda çalışabilir
            return await self.parse_generic(session, source, mode)

    async def parse_generic(self, session, source, mode):
        try:
            # Jitter
            await asyncio.sleep(random.uniform(2.0, 5.0))
            items = []
            
            if mode == "html_tenable":
                content = await self.fetch_content_robust(source["url"], session)
                if not content:
                    self.failed_sources[source['name']] = "FetchErr"
                    return []
                if source['name'] in self.failed_sources: del self.failed_sources[source['name']]
                
                html = content.decode('utf-8', errors='ignore')
                soup = BeautifulSoup(html, 'lxml')
                rows = soup.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        link_tag = row.find('a')
                        if link_tag:
                            title = link_tag.text.strip()
                            link = "https://www.tenable.com" + link_tag['href']
                            raw_id = link.split('/')[-1]
                            items.append({"raw_id": raw_id, "title": title, "desc": "Tenable Plugin Update", "link": link, "score": 0.0})

            elif "json" in mode:
                content = await self.fetch_content_robust(source["url"], session)
                if not content:
                    self.failed_sources[source['name']] = "FetchErr"
                    return []
                if source['name'] in self.failed_sources: del self.failed_sources[source['name']]
                
                d = json.loads(content)
                if mode == "json_cisa":
                        items = [{"raw_id": i.get("cveID"), "title": i.get("vulnerabilityName"), "desc": i.get("shortDescription"), "link": f"https://www.cve.org/CVERecord?id={i.get('cveID')}", "score": 10.0} for i in d.get("vulnerabilities", [])[:5]]
                elif mode == "json_nist":
                        for i in d.get("vulnerabilities", [])[:5]:
                            cve = i.get("cve", {})
                            items.append({"raw_id": cve.get("id"), "title": f"NIST: {cve.get('id')}", "desc": "NIST Kaydı", "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}", "score": 7.5}) 
                elif mode == "json_cveorg":
                        items = [{"raw_id": i.get("cve_id"), "title": f"Yeni CVE: {i.get('cve_id')}", "desc": "Yeni zafiyet.", "link": f"https://www.cve.org/CVERecord?id={i.get('cve_id')}", "score": 0} for i in d.get("cve_ids", [])[:10]]
            
            elif mode == "feed":
                content = await self.fetch_content_robust(source["url"], session)
                if not content:
                    self.failed_sources[source['name']] = "FetchErr"
                    return []
                if source['name'] in self.failed_sources: del self.failed_sources[source['name']]
                
                content_str = content.decode('utf-8', errors='ignore')
                f = feedparser.parse(content_str)
                for e in f.entries[:5]:
                    items.append({"raw_id": e.link, "title": e.title, "desc": e.get('summary',''), "link": e.link, "score": 0})
            
            final = []
            for i in items:
                i['score'] = self.extract_score(i)
                # DEEP SCOUT
                if i['score'] == 0.0 and i.get('link'):
                    i['score'] = await self.enrich_score_from_web(i['link'], i['score'])
                
                i['id'] = self.normalize_id(i["raw_id"], i["link"], i["title"])
                i['source'] = source['name']
                final.append(i)
            return final
        except Exception as e:
            self.failed_sources[source['name']] = "EXC"
            return []

    async def process_intelligence(self):
        await self.check_commands()
        
        tr = pytz.timezone('Europe/Istanbul')
        simdi = datetime.now(tr)
        self.last_scan_timestamp = simdi.strftime("%H:%M:%S")
        
        if simdi.hour == 18 and self.last_news_report_date != str(date.today()):
            await self.send_daily_news_digest()
            
        if simdi.weekday() == 0 and simdi.hour == 9 and self.last_monthly_report_date != str(date.today()):
            await self.send_monthly_executive_report()

        logger.info("🔎 Tarama Sürüyor (v23.0 Stealth Mode)...")
        self.check_daily_reset()
        await self.check_heartbeat()

        all_threats = await self.fetch_all()
        for threat in all_threats:
            tid = threat["id"]
            curr = threat.get('score', 0)
            prev = self.known_ids.get(tid)
            src = threat.get('source', '')
            
            notify = False
            is_upd = False
            
            if prev is None:
                self.known_ids[tid] = curr
                self.update_daily_stats(threat)
                self.log_to_monthly_json(threat) 
                
                # FİLTRE: 8.5+ veya Özel Kaynaklar
                if curr >= 8.5: notify = True
                elif threat['source']=="CISA KEV": notify = True
                elif threat['source']=="ZeroDayInitiative": notify = True
                
                if any(a in (threat['title']+threat['desc']).lower() for a in self.my_assets): notify = True

            else:
                if curr > prev and curr >= 8.5:
                    is_upd = True
                    notify = True
                    self.known_ids[tid] = curr
                    self.log_to_monthly_json(threat, old_score=prev)
            
            if notify:
                header = "📈 SEVİYE YÜKSELDİ" if is_upd else "ACİL GÜVENLİK UYARISI"
                msg = await self.format_alert_technical(threat, header)
                ref = self.extract_official_solution_link(threat.get('desc', ''))
                search = threat['title'] if "http" in tid else tid
                await self.send_telegram_card(msg, link=threat['link'], search_query=search, extra_ref=ref)
                self.save_json(self.memory_file, self.known_ids)

        self.save_json(self.memory_file, self.known_ids)
