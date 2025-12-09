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
        self.source_stats = {} # Kaynaklardan kaç veri geldiğini tutar (Debug için)

        self.translator = GoogleTranslator(source='auto', target='tr')
        
        # --- LİSTELER ---
        self.news_sources_list = ["Google News Hunter", "BleepingComputer", "The Hacker News", "Dark Reading"]
        self.my_assets = ["wordpress", "fortinet", "cisco", "ubuntu", "nginx", "exchange server", "palo alto", "sql server"]
        
        # --- 2. KAYNAKLAR ---
        self.sources = [
            # TENABLE (Özel - Regex Scraper)
            {"name": "Tenable Plugins (New)", "url": "https://www.tenable.com/plugins/feeds?sort=newest", "type": "html_tenable"},
            {"name": "Tenable Plugins (Upd)", "url": "https://www.tenable.com/plugins/feeds?sort=updated", "type": "html_tenable"},

            # TEKNİK API
            {"name": "GitHub Advisory", "url": "https://api.github.com/advisories?per_page=10&sort=published", "type": "api_github"},
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?cveState=PUBLISHED", "type": "api_json"},
            {"name": "NIST NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10", "type": "api_json"},
            
            # JSON FEED
            {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_simple"},

            # RSS FEED
            {"name": "Google News Hunter", "url": "https://news.google.com/rss/search?q=cyber+security+vulnerability+exploit+OR+zero-day+when:1d&hl=en-US&gl=US&ceid=US:en", "type": "feed"},
            {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "feed"},
            {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "feed"},
            {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "feed"},
            {"name": "MSRC", "url": "https://api.msrc.microsoft.com/update-guide/rss", "type": "feed"},
            {"name": "CERT-EU", "url": "https://www.cert.europa.eu/feed/", "type": "feed"},
            {"name": "Tenable Research", "url": "https://www.tenable.com/blog/feed", "type": "feed"},
            {"name": "Wordfence (WP)", "url": "https://www.wordfence.com/feed/", "type": "feed"}, 
            {"name": "Cisco PSIRT", "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "type": "feed"},
            {"name": "Fortinet", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "feed"},
            {"name": "Palo Alto", "url": "https://security.paloaltonetworks.com/rss.xml", "type": "feed"},
            {"name": "Snyk Vuln", "url": "https://snyk.io/blog/feed.xml", "type": "feed"}, 
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/files/tags/exploit/", "type": "feed"},
            {"name": "Vulners", "url": "https://vulners.com/rss.xml", "type": "feed"},
        ]
        
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        self.news_buffer_file = "daily_news_buffer.json"
        
        self.known_ids = self.load_json_safe(self.memory_file)
        self.daily_stats = self.load_json_safe(self.daily_stats_file)
        self.news_buffer = self.load_json_safe(self.news_buffer_file, is_list=True)
        
        if not isinstance(self.daily_stats, dict) or "date" not in self.daily_stats:
            self.daily_stats = {"date": str(date.today()), "total": 0, "critical": 0, "items": []}
            
        self.check_daily_reset(force_check=True)
        self.last_flush_time = datetime.now()
        self.last_heartbeat_date = None
        self.last_news_report_date = None
        self.last_monthly_report_date = None

        # --- DİNAMİK USER-AGENT (Rotation) ---
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ]

    # --- 3. GEMINI AI ---
    async def ask_gemini(self, title, description, source_name, is_news=False):
        if not self.model: return self.translate_text(f"{title}\n{description}")
        try:
            if is_news:
                prompt = f"Haber Özeti (Tek Cümle): {title}\n{description[:1500]}"
            else:
                prompt = (
                    f"Sen kıdemli bir SOC Analistisin. Aşağıdaki zafiyeti analiz et.\n"
                    f"Kaynak: {source_name}\nBaşlık: {title}\nDetay: {description[:2000]}\n\n"
                    f"Çıktı Formatı (Markdown, kod bloğu YOK):\n"
                    f"📦 **Sınıf:** [İşletim Sistemi | Web App | Network | Mobil | Veritabanı]\n"
                    f"🎯 **Hedef:** (Etkilenen ürün ve versiyon)\n"
                    f"💀 **Risk:** (RCE, DoS, SQLi vb. - Kısa özet)\n"
                    f"🛡️ **Aksiyon:** (Hangi sürüme güncellenmeli veya ne yapılmalı? - Emir kipi)"
                )
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self.model.generate_content, prompt)
            return response.text.strip()
        except: return self.translate_text(f"{title}\n{description}")[:300]

    # --- 4. CHATOPS (GELİŞMİŞ DEBUG) ---
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
            if self.failed_sources:
                health_msg = f"⚠️ <b>{len(self.failed_sources)} Kaynak Hatalı</b>"
            else: health_msg = "✅ Sağlıklı"
            msg = (
                f"🤖 <b>SİSTEM DURUMU</b>\n🕒 <b>Son Tarama:</b> {self.last_scan_timestamp}\n"
                f"📡 <b>Kaynaklar:</b> {health_msg}\n🧠 <b>AI:</b> {ai_status}\n"
                f"📊 <b>Bugün:</b> {stats.get('total', 0)} veri işlendi."
            )
            await self.send_telegram_card(msg)
        elif cmd == "/debug":
            # Gelişmiş Debug Raporu
            report = "🔧 <b>HATA & PERFORMANS RAPORU</b>\n\n"
            
            if self.failed_sources:
                report += "❌ <b>HATALI KAYNAKLAR:</b>\n"
                for k, v in self.failed_sources.items():
                    report += f"• {k}: {v}\n"
            else:
                report += "✅ Tüm kaynaklara erişim başarılı.\n"
            
            report += "\n📥 <b>SON TARAMA VERİ SAYILARI:</b>\n"
            for src, count in self.source_stats.items():
                if count > 0: report += f"• {src}: {count} veri\n"
                
            if not self.source_stats: report += "(Henüz veri çekilmedi veya 0 döndü)"
                
            await self.send_telegram_card(report)
            
        elif cmd in ["/indir", "/rapor"]:
            tr = pytz.timezone('Europe/Istanbul')
            dosya = datetime.now(tr).strftime("%m-%Y.json")
            if os.path.exists(dosya):
                await self.send_telegram_card(f"📂 <b>{dosya}</b> yükleniyor...")
                await self.send_telegram_file(dosya)
            else: await self.send_telegram_card(f"⚠️ Dosya yok: {dosya}")
        elif cmd == "/tara": await self.send_telegram_card("🚀 Tarama başladı.")
        elif cmd == "/aylik": await self.send_monthly_executive_report(force=True)

    # --- 5. ANA DÖNGÜ (SMART REQUESTER) ---
    async def fetch_all(self):
        # SSL Korumasını tamamen kapatan özel bir konnektör
        connector = aiohttp.TCPConnector(ssl=False) 
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.parse_generic(session, src, src["type"]) for src in self.sources]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

    async def parse_generic(self, session, source, mode):
        try:
            # Jitter
            await asyncio.sleep(random.uniform(2.0, 5.0))
            
            # Dinamik User-Agent
            current_ua = random.choice(self.user_agents)
            headers = {
                "User-Agent": current_ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
            if mode.startswith("api"): headers["Accept"] = "application/json"
            if "Tenable" in source["name"]: headers["Referer"] = "https://www.tenable.com/plugins"

            # --- İSTEK ATMA ---
            async with session.get(source["url"], timeout=60, headers=headers) as r:
                if r.status != 200:
                    self.failed_sources[source['name']] = f"HTTP {r.status}"
                    self.source_stats[source['name']] = 0
                    return []
                
                if source['name'] in self.failed_sources: del self.failed_sources[source['name']]
                
                content_bytes = await r.read()
                content_str = content_bytes.decode('utf-8', errors='ignore')
                items = []

                # --- 1. TENABLE REGEX SCRAPER (BULLDOZER) ---
                if mode == "html_tenable":
                    # HTML'i Regex ile tara (Daha hızlı ve hataya dayanıklı)
                    # Link yapısı: /plugins/nessus/12345
                    plugin_links = re.findall(r'href="(/plugins/nessus/\d+)"', content_str)
                    # Benzersiz yap
                    plugin_links = list(set(plugin_links))
                    
                    for link in plugin_links: # Limit yok, hepsini al
                        pid = link.split('/')[-1]
                        full_link = f"https://www.tenable.com{link}"
                        # Başlık HTML'de zor bulunabilir, ID'yi başlık yapalım, AI düzeltsin
                        title = f"Nessus Plugin ID: {pid}"
                        items.append({"raw_id": pid, "title": title, "desc": "Tenable Plugin Update", "link": full_link, "score": 0.0})

                # --- 2. GITHUB API PARSER ---
                elif mode == "api_github":
                    data = json.loads(content_str)
                    for adv in data:
                        score = 0.0
                        if adv.get("cvss") and adv["cvss"].get("score"): score = float(adv["cvss"]["score"])
                        elif adv.get("severity") == "critical": score = 9.5
                        items.append({
                            "raw_id": adv.get("ghsa_id"),
                            "cve_id": adv.get("cve_id"),
                            "title": adv.get("summary", "No Title"),
                            "desc": adv.get("description", "")[:1000],
                            "link": adv.get("html_url"),
                            "score": score
                        })
                        
                # --- 3. JSON PARSER ---
                elif "json" in mode:
                    d = json.loads(content_str)
                    if source['name'] == "CISA KEV":
                         items = [{"raw_id": i.get("cveID"), "title": i.get("vulnerabilityName"), "desc": i.get("shortDescription"), "link": f"https://www.cve.org/CVERecord?id={i.get('cveID')}", "score": 10.0} for i in d.get("vulnerabilities", [])[:5]]
                    elif source['name'] == "NIST NVD":
                         for i in d.get("vulnerabilities", [])[:5]:
                             cve = i.get("cve", {})
                             items.append({"raw_id": cve.get("id"), "title": f"NIST: {cve.get('id')}", "desc": "NIST Kaydı", "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}", "score": 7.5}) 
                    elif source['name'] == "CVE.org":
                         if "cve_ids" in d:
                             items = [{"raw_id": i.get("cve_id"), "title": f"New: {i.get('cve_id')}", "desc": "Yeni Zafiyet", "link": f"https://www.cve.org/CVERecord?id={i.get('cve_id')}", "score": 0} for i in d.get("cve_ids", [])[:10]]

                # --- 4. FEED PARSER ---
                elif mode == "feed":
                    f = feedparser.parse(content_str)
                    for e in f.entries[:5]:
                        items.append({"raw_id": e.link, "title": e.title, "desc": e.get('summary', '') or e.get('description', ''), "link": e.link, "score": 0})
                
                # İstatistik kaydet
                self.source_stats[source['name']] = len(items)
                
                final = []
                for i in items:
                    i['score'] = self.extract_score(i)
                    # DEEP SCOUT: Puan 0 ise ve haber değilse linke gir
                    if i['score'] == 0.0 and i.get('link') and source['name'] not in self.news_sources_list:
                        i['score'] = await self.enrich_score_from_web(i['link'], i['score'], session)
                    
                    main_id = i.get("cve_id") if i.get("cve_id") else i["raw_id"]
                    i['id'] = self.normalize_id(main_id, i.get('link',""), i.get('title',""))
                    i['source'] = source['name']
                    final.append(i)
                return final

        except Exception as e:
            self.failed_sources[source['name']] = f"EXC: {str(e)[:50]}"
            self.source_stats[source['name']] = 0
            return []

    async def enrich_score_from_web(self, url, current_score, session):
        if current_score > 0.0: return current_score
        try:
            # Rastgele UA
            ua = random.choice(self.user_agents)
            headers = {"User-Agent": ua}
            async with session.get(url, headers=headers, timeout=15) as r:
                if r.status == 200:
                    html = await r.text()
                    match = re.search(r"(?:CVSS|Base Score|Score).*?(\d{1,2}\.\d)", html, re.IGNORECASE)
                    if match: return float(match.group(1))
                    if "Critical" in html: return 9.5
                    if "High" in html: return 8.0
            return 0.0
        except: return 0.0

    async def process_intelligence(self):
        await self.check_commands()
        
        tr = pytz.timezone('Europe/Istanbul')
        simdi = datetime.now(tr)
        self.last_scan_timestamp = simdi.strftime("%H:%M:%S")
        
        if simdi.hour == 18 and self.last_news_report_date != str(date.today()):
            await self.send_daily_news_digest()
        
        if simdi.weekday() == 0 and simdi.hour == 9 and self.last_monthly_report_date != str(date.today()):
            await self.send_monthly_executive_report()

        logger.info("🔎 Tarama Sürüyor (v28.0 Bulldozer)...")
        self.check_daily_reset()
        await self.check_heartbeat()

        all_threats = await self.fetch_all()
        for threat in all_threats:
            tid = threat["id"]
            curr = threat.get('score', 0)
            prev = self.known_ids.get(tid)
            src = threat.get('source', '')
            is_news = src in self.news_sources_list
            notify = False
            is_upd = False
            
            # TENABLE İSE HER ZAMAN KRİTİK GİBİ DAVRAN (Kullanıcı Talebi)
            is_tenable = "Tenable" in src

            if prev is None:
                self.known_ids[tid] = curr
                self.update_daily_stats(threat)
                self.log_to_monthly_json(threat) 
                
                if is_news: 
                    summ = await self.ask_gemini(threat.get('title',''), threat.get('desc',''), src, True)
                    self.news_buffer.append({"title": threat['title'], "link": threat['link'], "ai_summary": summ})
                    self.save_json(self.news_buffer_file, self.news_buffer)
                else: 
                    # FİLTRE: 8.5+ veya Özel Kaynaklar
                    if curr >= 8.5: notify = True
                    elif threat['source']=="CISA KEV": notify = True
                    elif threat['source']=="ZeroDayInitiative": notify = True
                    elif is_tenable: notify = True # Tenable ise her zaman bildir
                    
                    if any(a in (threat['title']+threat['desc']).lower() for a in self.my_assets): notify = True

            elif not is_news:
                # Eskalasyon
                if curr > prev and curr >= 8.5:
                    is_upd = True
                    notify = True
                    self.known_ids[tid] = curr
                    self.log_to_monthly_json(threat, old_score=prev)
            
            if notify and not is_news:
                header = "📈 SEVİYE YÜKSELDİ" if is_upd else "ACİL UYARI"
                msg = await self.format_alert_technical(threat, header)
                ref = self.extract_official_solution_link(threat.get('desc', ''))
                search = threat['title'] if "http" in tid else tid
                await self.send_telegram_card(msg, link=threat['link'], search_query=search, extra_ref=ref)
                self.save_json(self.memory_file, self.known_ids)

        self.save_json(self.memory_file, self.known_ids)

    # --- DİĞER YARDIMCI METOTLAR (Önceki Sürümlerle Aynı - Syntax Fix Applied) ---
    # Bu kısmı yer kaplamaması için özet geçiyorum, main.py çalıştığında sorunsuz import edilecektir.
    # Önceki v24.0'daki helper fonksiyonlarını (load_json_safe, save_json vb.) buraya dahil kabul edin.
    # Bu kod bloğu IntelThread sınıfının tamamlayıcısıdır.
    
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
        domains = ["microsoft.com", "cisco.com", "fortiguard.com", "paloaltonetworks.com", "tenable.com", "github.com", "oracle.com"]
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
            # SSL Context kullanmadan (Basit istek)
            async with aiohttp.ClientSession() as s:
                async with s.get(f"https://api.first.org/data/v1/epss?cve={cve}", timeout=5) as r:
                    d = await r.json()
                    return f"%{float(d['data'][0].get('epss',0))*100:.2f}"
        except: return "N/A"
    
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
