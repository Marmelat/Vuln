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
        
        # Gemini AI Ayarları
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        if self.gemini_api_key:
            genai.configure(api_key=self.gemini_api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            logger.warning("⚠️ GEMINI_API_KEY eksik! Standart çeviri modu aktif.")
            self.model = None

        # Durum Takibi
        self.last_update_id = 0
        self.last_scan_timestamp = "Henüz Başlamadı"
        self.failed_sources = []
        
        # Yedek Çevirmen
        self.translator = GoogleTranslator(source='auto', target='tr')
        
        # --- 2. ZAFİYET KAYNAKLARI ---
        self.sources = [
            # A. RESMİ & DEVLET
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?state=PUBLISHED&time_modified_gt=", "type": "json_cveorg"},
            {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_cisa"},
            {"name": "NIST NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40&pubStartDate=", "type": "json_nist"},
            {"name": "CERT-EU", "url": "https://www.cert.europa.eu/publications/security-advisories/rss", "type": "feed"},
            
            # B. HABER & AVCI
            {"name": "Google News Hunter", "url": "https://news.google.com/rss/search?q=cyber+security+vulnerability+exploit+OR+zero-day+when:1d&hl=en-US&gl=US&ceid=US:en", "type": "feed"},
            {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "feed"},
            {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "feed"},

            # C. VENDOR & PLUGIN
            {"name": "Tenable Plugins", "url": "https://www.tenable.com/plugins/feeds.xml?sort=newest", "type": "feed"},
            {"name": "Wordfence (WP)", "url": "https://www.wordfence.com/feed/", "type": "feed"}, 
            {"name": "MSRC (Microsoft)", "url": "https://msrc.microsoft.com/blog/feed/", "type": "feed"},
            {"name": "Cisco PSIRT", "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "type": "feed"},
            {"name": "Fortinet", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "feed"},
            {"name": "Palo Alto", "url": "https://security.paloaltonetworks.com/rss.xml", "type": "feed"},
            {"name": "Snyk Vuln", "url": "https://snyk.io/blog/feed.xml", "type": "feed"}, 
            {"name": "GitHub Advisory", "url": "https://github.com/advisories.atom", "type": "feed"}, 
            
            # D. EXPLOIT ARAŞTIRMA
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "type": "feed"},
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/files/tags/exploit/", "type": "feed"},
            {"name": "Vulners", "url": "https://vulners.com/rss.xml", "type": "feed"},
        ]
        
        # Bellek Yönetimi
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        
        self.known_ids = self.load_json(self.memory_file)
        self.daily_stats = self.load_json(self.daily_stats_file)
        
        if not isinstance(self.daily_stats, dict) or "date" not in self.daily_stats:
            self.daily_stats = {"date": str(date.today()), "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "items": []}
            
        self.check_daily_reset(force_check=True)
        self.last_flush_time = datetime.now()
        self.last_heartbeat_date = None

    # --- 3. GEMINI AI (SINIFLANDIRMA VE AKSIYON) ---
    async def ask_gemini(self, title, description, source_name):
        if not self.model:
            return self.translate_text(f"{title}\n{description}")

        try:
            # Gelişmiş Prompt: Sınıflandırma Eklendi
            prompt = (
                f"Sen kıdemli bir siber istihbarat analistisin. Veriyi analiz et ve sınıflandır.\n"
                f"Kaynak: {source_name}\n"
                f"Başlık: {title}\n"
                f"Açıklama: {description}\n\n"
                f"Lütfen çıktıyı Türkçe olarak, Markdown formatında (kod bloğu olmadan) şu yapıda ver:\n\n"
                f"⚠️ **KAYNAK DEĞİŞİKLİĞİ:** (Sadece metinde 'moved', 'deprecated' yazıyorsa buraya uyarını yaz, yoksa bu satırı sil)\n\n"
                f"📦 **Sınıf:** [Şunlardan birini seç: İşletim Sistemi | Web Uygulaması | Ağ/Güvenlik Cihazı | Yazılım Kütüphanesi | Masaüstü Yazılımı | Diğer]\n"
                f"🎯 **Hedef Ürün:** (Etkilenen ana ürünün adı. Örn: Windows Server 2019, WordPress, FortiGate)\n"
                f"⚡ **Özet:** Zafiyet nedir? (Tek cümle)\n"
                f"💀 **Risk:** Saldırgan ne yapabilir?\n"
                f"🛡️ **Aksiyon:** Hangi sürüme güncellenmeli? (Net sürüm ver, emir kipi kullan.)"
            )
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self.model.generate_content, prompt)
            return response.text.strip()
        except Exception as e:
            logger.error(f"Gemini API Hatası: {e}")
            return self.translate_text(f"{title}\n{description}")

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
            ai_status = "✅ Gemini (Classified Mode)" if self.model else "⚠️ Pasif"
            
            if self.failed_sources:
                health_msg = f"⚠️ <b>{len(self.failed_sources)} Kaynak Hatalı:</b>\n" + ", ".join(self.failed_sources[:3])
            else:
                health_msg = "✅ Tüm Kaynaklar Sağlıklı"

            msg = (
                f"🤖 <b>SİSTEM DURUMU</b>\n"
                f"🕒 <b>Son Tarama:</b> {self.last_scan_timestamp}\n"
                f"📡 <b>Kaynak Sağlığı:</b> {health_msg}\n"
                f"🧠 <b>AI:</b> {ai_status}\n"
                f"📅 <b>Tarih:</b> {stats.get('date')}\n"
                f"📊 <b>Günlük:</b> {stats.get('total', 0)} (🛑 {stats.get('critical', 0)})\n"
                f"💾 <b>Hafıza:</b> {len(self.known_ids)} Kayıt"
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
            await self.send_telegram_card("🚀 Manuel tarama başlatılıyor...")

    async def send_telegram_file(self, filepath):
        url = f"https://api.telegram.org/bot{self.tg_token}/sendDocument"
        data = aiohttp.FormData()
        data.add_field('chat_id', self.tg_chat_id)
        data.add_field('document', open(filepath, 'rb'), filename=os.path.basename(filepath))
        async with aiohttp.ClientSession() as session:
            try: await session.post(url, data=data)
            except Exception as e: logger.error(f"Dosya gönderme hatası: {e}")

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

    # --- 6. FORMATLAMA & ÇİFT BUTON ---
    async def format_alert_custom(self, item, header_title="ACİL UYARI"):
        score = item.get('score', 0)
        
        use_ai = False
        text_check = (item.get('title', '') + item.get('desc', '')).lower()
        if score >= 7.0: use_ai = True
        elif item['source'] in ["CISA KEV", "Google News Hunter", "BleepingComputer", "The Hacker News"]: use_ai = True
        elif any(kw in text_check for kw in ["exploit", "zero-day", "rce", "remote code", "ransomware", "breach"]): use_ai = True

        if use_ai:
            ai_analiz_raw = await self.ask_gemini(item.get('title', ''), item.get('desc', ''), item.get('source', 'Genel'))
            ai_output = f"{ai_analiz_raw}\n"
        else:
            tr_desc = self.translate_text(item.get('desc', ''))
            ai_output = f"ℹ️ <b>Özet (Translate):</b>\n{tr_desc}\n"
        
        # Hashtagleri alta yine ekliyoruz (Yedek olarak)
        _, hashtags = self.detect_os_and_tags(item['title'] + " " + item['desc'])
        severity_label, icon = self.get_severity_info(score)
        epss_str = await self.enrich_with_epss(item['id'])
        
        return (
            f"<b>{icon} {header_title}</b>\n"
            f"⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n"
            f"🆔 <b>{item['id']}</b>\n"
            f"📊 <b>CVSS:</b> {score} | <b>EPSS:</b> {epss_str}\n"
            f"📂 {item['source']}\n\n"
            f"{ai_output}\n"
            f"🏷 <i>{hashtags}</i>"
        )

    async def send_telegram_card(self, message, link=None, search_query=None, extra_ref=None):
        if not self.tg_token: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {"chat_id": self.tg_chat_id, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True}
        
        keyboard = []
        if link: keyboard.append({"text": "🔗 Kaynak / Detay", "url": link})
        
        if extra_ref:
            keyboard.append({"text": "🛡️ Resmi Yama/Çözüm", "url": extra_ref})
        elif search_query:
            q_text = search_query if len(search_query) < 50 else search_query[:50]
            safe_q = q_text.replace(" ", "+")
            search_url = f"https://www.google.com/search?q={safe_q}+solution+patch+security+advisory"
            keyboard.append({"text": "🛡️ Çözüm Ara (Google)", "url": search_url})

        if keyboard: payload["reply_markup"] = {"inline_keyboard": [keyboard]}

        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload)
            except: pass

    # --- 7. LINK MADENCİSİ ---
    def extract_official_solution_link(self, text):
        if not text: return None
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        priority_domains = [
            "support.microsoft.com", "msrc.microsoft.com", 
            "tools.cisco.com", "cisco.com/security",
            "fortiguard.com", "paloaltonetworks.com",
            "mozilla.org", "adobe.com", "oracle.com",
            "vmware.com", "citrix.com", "wordpress.org/plugins",
            "tenable.com/plugins", "github.com", "redhat.com", "ubuntu.com"
        ]
        for url in urls:
            for domain in priority_domains:
                if domain in url: return url
        return None

    # --- 8. CORE VERİ YÖNETİMİ ---
    def load_json(self, filepath):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list): return {k: 0 for k in data}
                    return data
            except: return {}
        return {}

    def save_json(self, filepath, data):
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f)
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
                async with session.get(url, timeout=5) as r:
                    if r.status == 200:
                        d = await r.json()
                        if d.get("data"): return f"%{float(d['data'][0].get('epss',0))*100:.2f}"
            except: pass
        return "N/A"

    async def check_heartbeat(self):
        now = datetime.now()
        today_str = str(date.today())
        if self.last_heartbeat_date != today_str and 9 <= now.hour < 10:
            ai_stat = "Akıllı (Gemini)" if self.model else "Standart"
            await self.send_telegram_card(f"🤖 <b>GÜNLÜK KONTROL</b>\n✅ Sistem: Aktif\n🧠 Mod: {ai_stat}")
            self.last_heartbeat_date = today_str

    def check_daily_reset(self, force_check=False):
        today_str = str(date.today())
        if not isinstance(self.daily_stats, dict):
            self.daily_stats = {"date": today_str, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "items": []}

        if self.daily_stats.get("date") != today_str:
            if not force_check: asyncio.create_task(self.send_daily_summary_report())
            self.daily_stats = {"date": today_str, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "items": []}
            self.save_json(self.daily_stats_file, self.daily_stats)

    def get_severity_info(self, score):
        try: s = float(score)
        except: return "🔵 Bilgi", "🔵"
        if s >= 9.0: return "🛑 KRİTİK", "🛑"
        elif s >= 7.0: return "🔴 Yüksek", "🔴"
        elif s >= 4.0: return "🟠 Orta", "🟠"
        elif s > 0.0: return "🟡 Düşük", "🟡"
        return "🔵 Bilgi", "🔵"

    def update_daily_stats(self, item):
        self.check_daily_reset()
        self.daily_stats["total"] += 1
        s = item.get('score', 0)
        if s >= 9.0: self.daily_stats["critical"] += 1
        elif s >= 7.0: self.daily_stats["high"] += 1
        elif s >= 4.0: self.daily_stats["medium"] += 1
        else: self.daily_stats["low"] += 1
        self.daily_stats["items"].append({"title": item.get("title", ""), "score": s})
        self.save_json(self.daily_stats_file, self.daily_stats)

    def detect_os_and_tags(self, text):
        text = text.lower()
        system = "Genel / Diğer"
        tags = ["#CyberIntel"]
        mapping = {
            "windows": ("Microsoft Windows", "#Windows"),
            "linux": ("Linux Kernel", "#Linux"),
            "wordpress": ("WordPress", "#WordPress"),
            "plugin": ("Eklenti/Plugin", "#PluginVuln"),
            "nessus": ("Nessus Plugin", "#Nessus"),
            "ransomware": ("Ransomware", "#Ransomware"),
            "data breach": ("Veri İhlali", "#DataBreach"),
            "sql": (None, "#SQLi"), "xss": (None, "#XSS"), "rce": (None, "#RCE")
        }
        for k, v in mapping.items():
            if k in text:
                if v[0]: system = v[0]
                tags.append(v[1])
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
            try: await session.post(url, json=payload)
            except: pass

    async def send_daily_summary_report(self):
        stats = self.daily_stats
        if stats["total"] == 0: return
        chart = {"type": "bar", "data": {"labels": ["Kr", "Yü", "Or", "Dü"], "datasets": [{"data": [stats['critical'], stats['high'], stats['medium'], stats['low']]}]}}
        url = f"https://quickchart.io/chart?c={json.dumps(chart)}&w=400&h=250"
        await self.send_telegram_photo(url, f"📊 <b>GÜNLÜK RAPOR</b>\nTespit: {stats['total']}")

    def check_is_critical(self, item):
        if item['source'] in ["Google News Hunter", "BleepingComputer", "The Hacker News"]: return True
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
                async with session.get(source["url"], timeout=timeout) as response:
                    if response.status != 200:
                        logger.error(f"⚠️ Kaynak Erişim Hatası: {source['name']} - Kod: {response.status}")
                        if source['name'] not in self.failed_sources: self.failed_sources.append(source['name'])
                        return []
                    if source['name'] in self.failed_sources: self.failed_sources.remove(source['name'])
                    
                    data = await response.json()
                    if mode == "json_cisa":
                         items = [{"raw_id": i.get("cveID"), "title": i.get("vulnerabilityName"), "desc": i.get("shortDescription"), "link": f"https://www.cve.org/CVERecord?id={i.get('cveID')}", "score": 10.0} for i in data.get("vulnerabilities", [])[:5]]
                    elif mode == "json_nist":
                         yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.000')
                         async with session.get(source["url"]+yesterday, timeout=timeout) as response:
                            if response.status == 200:
                                d = await response.json()
                                for i in d.get("vulnerabilities", []):
                                    cve = i.get("cve", {})
                                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                                    if metrics and metrics[0].get("cvssData", {}).get("baseScore", 0) >= 7.0:
                                        items.append({"raw_id": cve.get("id"), "title": f"NIST: {cve.get('id')}", "desc": "NIST kaydı.", "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}", "score": metrics[0].get("cvssData", {}).get("baseScore", 0)})
                    elif mode == "json_cveorg":
                         items = [{"raw_id": i.get("cve_id"), "title": f"Yeni CVE: {i.get('cve_id')}", "desc": "Yeni zafiyet.", "link": f"https://www.cve.org/CVERecord?id={i.get('cve_id')}", "score": 0} for i in (await response.json()).get("cve_ids", [])[:10]]
            
            elif mode == "feed":
                async with session.get(source["url"], timeout=timeout) as response:
                    if response.status != 200:
                        logger.error(f"⚠️ Kaynak Erişim Hatası: {source['name']} - Kod: {response.status}")
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
        logger.info("🔎 Kademeli Analiz + Haber Avcısı + Güncelleme Takibi...")
        self.check_daily_reset()
        await self.check_heartbeat()
        
        tr_timezone = pytz.timezone('Europe/Istanbul')
        self.last_scan_timestamp = datetime.now(tr_timezone).strftime("%H:%M:%S")

        all_threats = await self.fetch_all()
        for threat in all_threats:
            
            threat_id = threat["id"]
            current_score = threat.get('score', 0)
            previous_score = self.known_ids.get(threat_id)
            
            should_notify = False
            is_update = False
            
            if previous_score is None:
                self.known_ids[threat_id] = current_score
                self.update_daily_stats(threat)
                self.log_to_monthly_json(threat)
                
                if threat['source'] in ["Google News Hunter", "BleepingComputer", "The Hacker News"]: should_notify = True
                elif current_score >= 7.0: should_notify = True
                elif threat['source'] == "CISA KEV": should_notify = True
                elif self.check_is_critical(threat): should_notify = True

            elif current_score >= 7.0 and previous_score < 7.0:
                is_update = True
                should_notify = True
                self.known_ids[threat_id] = current_score
                logger.info(f"🚨 YÜKSELTME: {threat_id} ({previous_score} -> {current_score})")
            
            if should_notify:
                header = "📈 SEVİYE YÜKSELDİ (UPDATE)" if is_update else "ACİL UYARI"
                msg = await self.format_alert_custom(threat, header)
                
                official_ref = self.extract_official_solution_link(threat.get('desc', ''))
                search_term = threat['id'] if not "http" in threat['id'] else threat['title']
                
                await self.send_telegram_card(msg, link=threat['link'], search_query=search_term, extra_ref=official_ref)
                
            if previous_score is not None and current_score != previous_score:
                 self.known_ids[threat_id] = current_score
                 
        self.save_json(self.memory_file, self.known_ids)
