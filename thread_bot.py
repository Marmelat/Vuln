import aiohttp
import asyncio
import logging
import json
import os
import re
import pytz
import feedparser
import google.generativeai as genai
from datetime import datetime, timedelta, date
from dotenv import load_dotenv
from deep_translator import GoogleTranslator

# .env yükle
load_dotenv()

logger = logging.getLogger("SecurityBot")

class IntelThread:
    def __init__(self):
        # --- 1. AYARLAR ---
        self.tg_token = os.getenv("TELEGRAM_TOKEN")
        self.tg_chat_id = os.getenv("TELEGRAM_CHAT_ID")
        
        # Gemini AI
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        if self.gemini_api_key:
            genai.configure(api_key=self.gemini_api_key)
            try: self.model = genai.GenerativeModel('gemini-1.5-flash')
            except: 
                try: self.model = genai.GenerativeModel('gemini-1.5-pro')
                except: self.model = genai.GenerativeModel('gemini-pro')
        else:
            logger.warning("⚠️ GEMINI_API_KEY eksik! Standart çeviri modu aktif.")
            self.model = None

        self.last_update_id = 0
        self.last_scan_timestamp = "Henüz Başlamadı"
        self.failed_sources = []
        
        # User-Agent
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        
        self.translator = GoogleTranslator(source='auto', target='tr')
        
        # --- AYIRT EDİCİ LİSTELER ---
        self.news_sources_list = [
            "Google News Hunter", 
            "BleepingComputer", 
            "The Hacker News", 
            "Dark Reading"
        ]

        # Envanter (Şimdilik boş olsa bile kod yapısı hazır dursun)
        self.my_assets = [] 
        
        # --- 2. KAYNAKLAR ---
        self.sources = [
            # HABER (Bülten Modu)
            {"name": "Google News Hunter", "url": "https://news.google.com/rss/search?q=cyber+security+vulnerability+exploit+OR+zero-day+when:1d&hl=en-US&gl=US&ceid=US:en", "type": "feed"},
            {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "feed"},
            {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "feed"},

            # TEKNİK (Anlık Mod)
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?state=PUBLISHED&time_modified_gt=", "type": "json_cveorg"},
            {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_cisa"},
            {"name": "NIST NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40&pubStartDate=", "type": "json_nist"},
            {"name": "CERT-EU", "url": "https://www.cert.europa.eu/publications/security-advisories/rss", "type": "feed"},
            {"name": "Tenable Plugins", "url": "https://www.tenable.com/plugins/feeds.xml?sort=newest", "type": "feed"},
            {"name": "Wordfence (WP)", "url": "https://www.wordfence.com/feed/", "type": "feed"}, 
            {"name": "MSRC (Microsoft)", "url": "https://msrc.microsoft.com/blog/feed/", "type": "feed"},
            {"name": "Cisco PSIRT", "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "type": "feed"},
            {"name": "Fortinet", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "feed"},
            {"name": "Palo Alto", "url": "https://security.paloaltonetworks.com/rss.xml", "type": "feed"},
            {"name": "Snyk Vuln", "url": "https://snyk.io/blog/feed.xml", "type": "feed"}, 
            {"name": "GitHub Advisory", "url": "https://github.com/advisories.atom", "type": "feed"}, 
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "type": "feed"},
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/files/tags/exploit/", "type": "feed"},
            {"name": "Vulners", "url": "https://vulners.com/rss.xml", "type": "feed"},
        ]
        
        # Dosya Yolları
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        self.news_buffer_file = "daily_news_buffer.json" 
        
        # Yüklemeler
        self.known_ids = self.load_json(self.memory_file)
        self.daily_stats = self.load_json(self.daily_stats_file)
        self.news_buffer = self.load_json(self.news_buffer_file)
        if not isinstance(self.news_buffer, list): self.news_buffer = []

        if not isinstance(self.daily_stats, dict) or "date" not in self.daily_stats:
            self.daily_stats = {"date": str(date.today()), "total": 0, "critical": 0, "items": []}
            
        self.check_daily_reset(force_check=True)
        self.last_flush_time = datetime.now()
        self.last_heartbeat_date = None
        self.last_news_report_date = None

    # --- 3. GEMINI AI (SINIFLANDIRMA EKLENDİ) ---
    async def ask_gemini(self, title, description, source_name, is_news=False):
        if not self.model: return self.translate_text(f"{title}\n{description}")

        try:
            if is_news:
                # BÜLTEN İÇİN KISA ÖZET
                prompt = (
                    f"Aşağıdaki siber güvenlik haberini analiz et.\n"
                    f"Başlık: {title}\n"
                    f"İçerik: {description}\n\n"
                    f"Lütfen çıktıyı Türkçe olarak TEK BİR CÜMLE ile özetle. Haber neyden bahsediyor? (Markdown kullanma)."
                )
            else:
                # TEKNİK ZAFİYET ANALİZİ (SINIFLANDIRMA + AKSIYON)
                prompt = (
                    f"Sen kıdemli bir güvenlik uzmanısın. Aşağıdaki zafiyeti analiz et ve sınıflandır.\n"
                    f"Kaynak: {source_name}\n"
                    f"Başlık: {title}\n"
                    f"Detay: {description}\n\n"
                    f"Lütfen çıktıyı Türkçe, Markdown formatında (kod bloğu olmadan) şu başlıklarla ver:\n"
                    f"⚠️ **KAYNAK DEĞİŞİKLİĞİ:** (Sadece metinde 'moved', 'deprecated' uyarısı varsa buraya yaz, yoksa bu satırı sil)\n"
                    f"📦 **Sınıf:** [İşletim Sistemi | Web Uygulaması | Ağ/Güvenlik Cihazı | Yazılım Kütüphanesi | Diğer]\n"
                    f"🎯 **Hedef Sistem:** (Etkilenen ürün nedir? Örn: Windows Server, WordPress, FortiGate)\n"
                    f"⚡ **Teknik Özet:** Zafiyetin kök nedeni nedir?\n"
                    f"💀 **Risk:** Saldırgan ne yapabilir?\n"
                    f"🛡️ **Aksiyon:** Hangi sürüme güncellenmeli? (Emir kipi kullan)\n"
                )

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self.model.generate_content, prompt)
            return response.text.strip()
        except Exception as e:
            logger.error(f"Gemini API Hatası: {e}")
            return self.translate_text(f"{title}\n{description}")[:200] + "..."

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
            except Exception: pass

    async def handle_command(self, command):
        cmd = command.lower().strip()
        if cmd in ["/durum", "/status"]:
            stats = self.daily_stats
            try: model_name = self.model.model_name
            except: model_name = "Gemini"
            ai_status = f"✅ Aktif ({model_name})" if self.model else "⚠️ Pasif"
            if self.failed_sources:
                health_msg = f"⚠️ <b>{len(self.failed_sources)} Kaynak Hatalı:</b>\n" + ", ".join(self.failed_sources[:3])
            else: health_msg = "✅ Tüm Kaynaklar Sağlıklı"

            msg = (
                f"🤖 <b>SİSTEM DURUMU</b>\n"
                f"🕒 <b>Son Tarama:</b> {self.last_scan_timestamp}\n"
                f"📡 <b>Kaynaklar:</b> {health_msg}\n"
                f"🧠 <b>AI Modu:</b> {ai_status}\n"
                f"📰 <b>Haber Kumbarası:</b> {len(self.news_buffer)} adet birikti\n"
                f"📊 <b>Bugün:</b> {stats.get('total', 0)} veri işlendi."
            )
            await self.send_telegram_card(msg)
        elif cmd in ["/indir", "/rapor"]:
            tr = pytz.timezone('Europe/Istanbul')
            dosya = datetime.now(tr).strftime("%m-%Y.json")
            if os.path.exists(dosya):
                await self.send_telegram_card(f"📂 <b>{dosya}</b> gönderiliyor...")
                await self.send_telegram_file(dosya)
            else:
                await self.send_telegram_card(f"⚠️ <b>{dosya}</b> bulunamadı.")
        elif cmd == "/tara":
            await self.send_telegram_card("🚀 Tarama başlatılıyor...")
        elif cmd == "/bulten": 
            await self.send_daily_news_digest(force=True)

    async def send_telegram_file(self, filepath):
        url = f"https://api.telegram.org/bot{self.tg_token}/sendDocument"
        data = aiohttp.FormData()
        data.add_field('chat_id', self.tg_chat_id)
        data.add_field('document', open(filepath, 'rb'), filename=os.path.basename(filepath))
        async with aiohttp.ClientSession() as session:
            try: await session.post(url, data=data)
            except Exception: pass

    # --- 5. AYLIK LOGLAMA ---
    def log_to_monthly_json(self, item):
        try:
            tr_timezone = pytz.timezone('Europe/Istanbul')
            simdi = datetime.now(tr_timezone)
            sanal_zaman = simdi + timedelta(minutes=10)
            dosya_ismi = sanal_zaman.strftime("%m-%Y.json")
            item['log_zamani'] = simdi.strftime("%Y-%m-%d %H:%M:%S")
            mevcut = []
            if os.path.exists(dosya_ismi):
                try:
                    with open(dosya_ismi, 'r', encoding='utf-8') as f:
                        mevcut = json.load(f)
                except: mevcut = []
            mevcut.append(item)
            with open(dosya_ismi, 'w', encoding='utf-8') as f:
                json.dump(mevcut, f, ensure_ascii=False, indent=4)
        except: pass

    # --- 6. FORMATLAMA (TEKNİK ZAFİYET) ---
    async def format_alert_technical(self, item, header_title="ACİL UYARI"):
        score = item.get('score', 0)
        source_name = item.get('source', '')
        
        # Teknik modda analiz iste
        ai_analiz_raw = await self.ask_gemini(item.get('title', ''), item.get('desc', ''), source_name, is_news=False)
        ai_output = f"{ai_analiz_raw}\n"
        
        # Hashtag (Yedek)
        _, hashtags = self.detect_os_and_tags(item['title'] + " " + item['desc'])
        
        epss_str = await self.enrich_with_epss(item['id'])
        icon = "🛑" if score >= 9 else "🟠"
        meta_info = f"🆔 <b>{item['id']}</b>\n📊 <b>CVSS:</b> {score} | <b>EPSS:</b> {epss_str}\n📂 {source_name}"

        return (
            f"<b>{icon} {header_title}</b>\n"
            f"⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n"
            f"{meta_info}\n\n"
            f"{ai_output}\n"
            f"🏷 <i>{hashtags}</i>"
        )

    async def send_telegram_card(self, message, link=None, search_query=None, extra_ref=None):
        if not self.tg_token: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {"chat_id": self.tg_chat_id, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True}
        
        keyboard = []
        if link: keyboard.append({"text": "🔗 Kaynak", "url": link})
        
        if search_query and "CVE" in search_query: 
             if extra_ref:
                keyboard.append({"text": "🛡️ Resmi Çözüm", "url": extra_ref})
             else:
                safe_q = search_query.replace(" ", "+")
                search_url = f"https://www.google.com/search?q={safe_q}+solution+patch+security+advisory"
                keyboard.append({"text": "🛡️ Çözüm Ara", "url": search_url})
        
        if keyboard: payload["reply_markup"] = {"inline_keyboard": [keyboard]}

        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload, headers=self.headers)
            except: pass

    # --- 7. HABER BÜLTENİ FONKSİYONU (18:00) ---
    async def send_daily_news_digest(self, force=False):
        today_str = str(date.today())
        
        if self.last_news_report_date == today_str and not force:
            return

        if not self.news_buffer:
            return 

        report_msg = f"🗞️ <b>SİBER GÜVENLİKTEN HAVADİSLER</b>\n"
        report_msg += f"📅 <i>{today_str} | Gün Sonu Raporu</i>\n"
        report_msg += f"⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n\n"

        for idx, news in enumerate(self.news_buffer):
            entry = f"🔹 <a href='{news['link']}'>{news['title']}</a>\n"
            entry += f"└ <i>{news['ai_summary']}</i>\n\n"
            
            if len(report_msg) + len(entry) > 4000:
                await self.send_telegram_card(report_msg)
                report_msg = ""
            
            report_msg += entry

        if report_msg:
            await self.send_telegram_card(report_msg)

        self.news_buffer = []
        self.save_json(self.news_buffer_file, [])
        self.last_news_report_date = today_str
        logger.info("✅ Günlük haber bülteni gönderildi.")

    # --- 8. YARDIMCI VE CORE ---
    def load_json(self, filepath):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f: return json.load(f)
            except: pass
        return {} 

    def save_json(self, filepath, data):
        try:
            with open(filepath, 'w') as f: json.dump(data, f)
        except: pass

    def normalize_id(self, raw_id, link="", title=""):
        text = f"{raw_id} {link} {title}".upper()
        if m := re.search(r"CVE-\d{4}-\d{4,7}", text): return m.group(0)
        if m := re.search(r"GHSA-[a-zA-Z0-9-]{10,}", text): return m.group(0)
        if m := re.search(r"ZDI-\d{2}-\d{3,}", text): return m.group(0)
        if "http" in raw_id:
            slug = raw_id.rstrip('/').split('/')[-1]
            return slug[:40] if slug else raw_id[:40]
        return raw_id[:40]

    def extract_score(self, item):
        if item.get('score', 0) > 0: return float(item['score'])
        text = (item.get('title', '') + " " + item.get('desc', '')).lower()
        if m := re.search(r"(?:cvss|score)[\s:]*([0-9]{1,2}\.?[0-9]?)", text): return float(m.group(1))
        return 0.0

    async def enrich_with_epss(self, cve_id):
        if not cve_id.startswith("CVE-"): return "N/A"
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, timeout=5, headers=self.headers) as r:
                    if r.status == 200:
                        d = await r.json()
                        if d.get("data"): return f"%{float(d['data'][0].get('epss',0))*100:.2f}"
            except: pass
        return "N/A"

    async def check_heartbeat(self):
        now = datetime.now()
        today_str = str(date.today())
        if self.last_heartbeat_date != today_str and 9 <= now.hour < 10:
            await self.send_telegram_card(f"🤖 <b>GÜNLÜK KONTROL</b>\n✅ Sistem: Aktif")
            self.last_heartbeat_date = today_str

    def check_daily_reset(self, force_check=False):
        today_str = str(date.today())
        if not isinstance(self.daily_stats, dict):
            self.daily_stats = {"date": today_str, "total": 0, "critical": 0, "items": []}
        if self.daily_stats.get("date") != today_str:
            if not force_check: asyncio.create_task(self.send_daily_summary_report())
            self.daily_stats = {"date": today_str, "total": 0, "critical": 0, "items": []}
            self.save_json(self.daily_stats_file, self.daily_stats)

    def extract_official_solution_link(self, text):
        if not text: return None
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        priority_domains = ["microsoft.com", "cisco.com", "fortiguard.com", "paloaltonetworks.com", "mozilla.org", "adobe.com", "vmware.com", "citrix.com", "wordpress.org", "tenable.com"]
        for url in urls:
            for domain in priority_domains:
                if domain in url: return url
        return None

    def update_daily_stats(self, item):
        self.check_daily_reset()
        self.daily_stats["total"] += 1
        if item.get('score', 0) >= 9.0: self.daily_stats["critical"] += 1
        self.save_json(self.daily_stats_file, self.daily_stats)

    def detect_os_and_tags(self, text):
        text = text.lower()
        system = "Genel"
        tags = ["#CyberIntel"]
        mapping = {"windows": "#Windows", "linux": "#Linux", "wordpress": "#WordPress", "ransomware": "#Ransomware"}
        for k, v in mapping.items():
            if k in text: tags.append(v)
        return system, " ".join(list(set(tags)))

    def translate_text(self, text):
        if not text or len(text) < 3: return text
        try: return self.translator.translate(text[:450])
        except: return text

    async def send_telegram_photo(self, photo_url, caption):
        if not self.tg_token: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendPhoto"
        payload = {"chat_id": self.tg_chat_id, "photo": photo_url, "caption": caption, "parse_mode": "HTML"}
        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload, headers=self.headers)
            except: pass

    async def send_daily_summary_report(self):
        stats = self.daily_stats
        if stats["total"] == 0: return
        await self.send_telegram_card(f"📊 <b>GÜNLÜK RAPOR</b>\nTespit: {stats['total']}")

    def check_is_critical(self, item):
        if item['source'] == "CISA KEV": return True
        if item.get('score', 0) >= 9.0: return True
        text = (str(item.get('desc', '')) + " " + str(item.get('title', ''))).lower()
        if any(x in text for x in ["critical", "rce", "zero-day", "active exploitation", "ransomware", "breach"]): return True
        return False

    async def parse_generic(self, session, source, mode):
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            items = []
            
            if "json" in mode:
                async with session.get(source["url"], timeout=timeout, headers=self.headers) as response:
                    if response.status != 200:
                        if source['name'] not in self.failed_sources: self.failed_sources.append(source['name'])
                        return []
                    if source['name'] in self.failed_sources: self.failed_sources.remove(source['name'])
                    data = await response.json()
                    
                    if mode == "json_cisa":
                         items = [{"raw_id": i.get("cveID"), "title": i.get("vulnerabilityName"), "desc": i.get("shortDescription"), "link": f"https://www.cve.org/CVERecord?id={i.get('cveID')}", "score": 10.0} for i in data.get("vulnerabilities", [])[:5]]
                    elif mode == "json_nist":
                         yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.000')
                         async with session.get(f"{source['url']}{yesterday}", timeout=timeout, headers=self.headers) as r:
                            if r.status == 200:
                                d = await r.json()
                                for i in d.get("vulnerabilities", []):
                                    cve = i.get("cve", {})
                                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                                    if metrics and metrics[0].get("cvssData", {}).get("baseScore", 0) >= 7.0:
                                        items.append({"raw_id": cve.get("id"), "title": f"NIST: {cve.get('id')}", "desc": "NIST kaydı.", "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}", "score": metrics[0].get("cvssData", {}).get("baseScore", 0)})
                    elif mode == "json_cveorg":
                         items = [{"raw_id": i.get("cve_id"), "title": f"Yeni CVE: {i.get('cve_id')}", "desc": "Yeni zafiyet.", "link": f"https://www.cve.org/CVERecord?id={i.get('cve_id')}", "score": 0} for i in (await response.json()).get("cve_ids", [])[:10]]

            elif mode == "feed":
                async with session.get(source["url"], timeout=timeout, headers=self.headers) as response:
                    if response.status != 200:
                        if source['name'] not in self.failed_sources: self.failed_sources.append(source['name'])
                        return []
                    if source['name'] in self.failed_sources: self.failed_sources.remove(source['name'])
                    content = await response.read()
                    feed = feedparser.parse(content)
                    for entry in feed.entries[:5]:
                        items.append({"raw_id": entry.get('link', ''), "title": entry.get('title', 'Başlık Yok'), "desc": (entry.get('summary') or entry.get('description') or "")[:500], "link": entry.get('link', ''), "score": 0})
            
            final_items = []
            for i in items:
                i['id'] = self.normalize_id(i["raw_id"], i["link"], i["title"])
                i['source'] = source['name']
                if i['score'] == 0: i['score'] = self.extract_score(i)
                final_items.append(i)
            return final_items
        except Exception as e: return []

    async def fetch_all(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.parse_generic(session, s, s["type"]) for s in self.sources]
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

    async def process_intelligence(self):
        await self.check_commands()
        
        tr_timezone = pytz.timezone('Europe/Istanbul')
        simdi = datetime.now(tr_timezone)
        self.last_scan_timestamp = simdi.strftime("%H:%M:%S")
        
        # 18:00 BÜLTEN KONTROLÜ
        if simdi.hour == 18 and self.last_news_report_date != str(date.today()):
            await self.send_daily_news_digest()

        logger.info("🔎 Kademeli Analiz (Dual Mode) Çalışıyor...")
        self.check_daily_reset()
        await self.check_heartbeat()

        all_threats = await self.fetch_all()
        for threat in all_threats:
            
            threat_id = threat["id"]
            current_score = threat.get('score', 0)
            previous_score = self.known_ids.get(threat_id)
            source_name = threat.get('source', '')
            
            is_news_source = source_name in self.news_sources_list
            should_notify = False
            is_update = False
            
            if previous_score is None:
                self.known_ids[threat_id] = current_score
                self.update_daily_stats(threat)
                self.log_to_monthly_json(threat)
                
                # HABER İSE -> KUMBARAYA AT (Bildirim YOK)
                if is_news_source:
                    ai_summary = await self.ask_gemini(threat.get('title',''), threat.get('desc',''), source_name, is_news=True)
                    news_item = {
                        "title": threat.get('title'),
                        "link": threat.get('link'),
                        "ai_summary": ai_summary
                    }
                    self.news_buffer.append(news_item)
                    self.save_json(self.news_buffer_file, self.news_buffer)
                    logger.info(f"📰 Haber Kumbaraya Eklendi: {threat['title'][:30]}")
                    
                # ZAFİYET İSE -> KRİTİKSE BİLDİR
                else:
                    if current_score >= 7.0: should_notify = True
                    elif threat['source'] == "CISA KEV": should_notify = True
                    elif self.check_is_critical(threat): should_notify = True
                    
                    text_check = (threat.get('title', '') + threat.get('desc', '')).lower()
                    if any(asset in text_check for asset in self.my_assets): should_notify = True

            # GÜNCELLEME (Sadece Teknik Zafiyetler İçin)
            elif not is_news_source and current_score >= 7.0 and previous_score < 7.0:
                is_update = True
                should_notify = True
                self.known_ids[threat_id] = current_score
                logger.info(f"🚨 YÜKSELTME: {threat_id}")
            
            # BİLDİRİM GÖNDERME
            if should_notify and not is_news_source:
                header = "📈 SEVİYE YÜKSELDİ" if is_update else "ACİL UYARI"
                msg = await self.format_alert_technical(threat, header)
                
                official_ref = self.extract_official_solution_link(threat.get('desc', ''))
                search_term = threat['id'] if not "http" in threat['id'] else threat['title']
                
                await self.send_telegram_card(msg, link=threat['link'], search_query=search_term, extra_ref=official_ref)
                
            if previous_score is not None and current_score != previous_score:
                 self.known_ids[threat_id] = current_score
                 
        self.save_json(self.memory_file, self.known_ids)
