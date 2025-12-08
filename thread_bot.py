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

        # ChatOps Takibi
        self.last_update_id = 0
        
        # Son tarama zamanı (Veri akışını kontrol etmek için)
        self.last_scan_timestamp = "Henüz Başlamadı"
        
        # Yedek Çevirmen
        self.translator = GoogleTranslator(source='auto', target='tr')
        
        # --- 2. ZAFİYET KAYNAKLARI ---
        self.sources = [
            # STANDART & DEVLET
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?state=PUBLISHED&time_modified_gt=", "type": "json_cveorg"},
            {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_cisa"},
            {"name": "NIST NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40&pubStartDate=", "type": "json_nist"},
            {"name": "CERT-EU", "url": "https://www.cert.europa.eu/publications/security-advisories/rss", "type": "feed"},
            
            # VENDOR & PLUGIN
            {"name": "Tenable Plugins", "url": "https://www.tenable.com/plugins/feeds?sort=newest", "type": "feed"}, # Nessus
            {"name": "MSRC (Microsoft)", "url": "https://msrc.microsoft.com/blog/feed/", "type": "feed"},
            {"name": "Cisco PSIRT", "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "type": "feed"},
            {"name": "Fortinet", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "feed"},
            {"name": "Palo Alto", "url": "https://security.paloaltonetworks.com/rss.xml", "type": "feed"},
            {"name": "Wordfence (WP)", "url": "https://www.wordfence.com/feed/", "type": "feed"}, 
            {"name": "Snyk Vuln", "url": "https://snyk.io/blog/feed.xml", "type": "feed"}, 
            {"name": "GitHub Advisory", "url": "https://github.com/advisories.atom", "type": "feed"}, 
            
            # EXPLOIT & ARAŞTIRMA
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "type": "feed"},
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/files/", "type": "feed"},
            {"name": "Vulners", "url": "https://vulners.com/rss.xml", "type": "feed"},
        ]
        
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        
        self.known_ids = self.load_json(self.memory_file, set_mode=True)
        self.daily_stats = self.load_json(self.daily_stats_file, set_mode=False)
        self.check_daily_reset(force_check=True)

        self.last_flush_time = datetime.now()
        self.last_heartbeat_date = None

    # --- 3. GEMINI AI ANALİZ MOTORU (AKSIYON ODAKLI) ---
    async def ask_gemini(self, title, description):
        if not self.model:
            return self.translate_text(f"{title}\n{description}")

        try:
            # Prompt: Yönetici özeti ve net aksiyon emri
            prompt = (
                f"Sen kıdemli bir siber güvenlik operasyon uzmanısın. Aşağıdaki veriyi analiz et.\n"
                f"Başlık: {title}\n"
                f"Açıklama: {description}\n\n"
                f"Lütfen çıktıyı Türkçe olarak, Markdown formatında (kod bloğu kullanmadan) hazırla:\n"
                f"1. **Özet:** Zafiyet nedir? (Tek cümle)\n"
                f"2. **Etki:** Saldırgan ne elde eder?\n"
                f"3. **Aksiyon:** Hangi sürüme güncellenmeli veya hangi ayar kapatılmalı? (Net sürüm/komut ver, tavsiye verme emir ver.)\n\n"
                f"Yanıtın kısa, teknik ve yönetici özeti tadında olsun."
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
        
        # /durum komutuna "Son Tarama Zamanı" eklendi
        if cmd in ["/durum", "/status"]:
            stats = self.daily_stats
            ai_status = "✅ Gemini (Tiered Mode)" if self.model else "⚠️ Pasif"
            msg = (
                f"🤖 <b>SİSTEM DURUMU</b>\n"
                f"🕒 <b>Son Tarama:</b> {self.last_scan_timestamp}\n"
                f"🧠 AI Motoru: {ai_status}\n"
                f"📅 Tarih: {stats.get('date')}\n"
                f"📊 Günlük Tespit: <b>{stats.get('total', 0)}</b> (🛑 {stats.get('critical', 0)})\n"
                f"📡 Aktif Kaynaklar: {len(self.sources)}"
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
            # Ay geçişini 23:50'den sonra yeni ay olarak algıla
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

    # --- 6. FORMATLAMA ---
    async def format_alert(self, item, is_hourly=False):
        score = item.get('score', 0)
        
        # AI Analizi: Sadece bildirim atılacaksa (Yüksek/Kritik) zaten buraya gelir.
        # Bu yüzden burada AI'yı direkt çalıştırabiliriz çünkü filtreleme process_intelligence'da yapıldı.
        ai_analiz_raw = await self.ask_gemini(item.get('title', ''), item.get('desc', ''))
        ai_output = f"🧠 <b>AI Analizi & Aksiyon:</b>\n{ai_analiz_raw}\n"

        system_name, hashtags = self.detect_os_and_tags(item['title'] + " " + item['desc'])
        severity_label, icon = self.get_severity_info(score)
        epss_str = await self.enrich_with_epss(item['id'])
        header = "ACİL UYARI" if not is_hourly else "ZAFİYET DETAYI"
        
        return (
            f"<b>{icon} {header}</b>\n"
            f"⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n"
            f"🎯 <b>{item['id']}</b> | {system_name}\n"
            f"📊 <b>CVSS:</b> {score} | <b>EPSS:</b> {epss_str}\n"
            f"📂 {item['source']}\n\n"
            f"{ai_output}\n"
            f"🏷 <i>{hashtags}</i>"
        )

    async def send_telegram_card(self, message, link=None, search_query=None):
        """Çift Butonlu Mesaj Gönderimi"""
        if not self.tg_token: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {"chat_id": self.tg_chat_id, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True}
        
        keyboard = []
        if link:
            keyboard.append({"text": "🔗 Detay / Kaynak", "url": link})
        
        if search_query:
            safe_q = search_query.replace(" ", "+")
            search_url = f"https://www.google.com/search?q={safe_q}+solution+patch+advisory"
            keyboard.append({"text": "🛡️ Çözüm Ara", "url": search_url})

        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": [keyboard]}

        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload)
            except: pass

    # --- 7. YARDIMCI VE CORE ---
    def load_json(self, filepath, set_mode=False):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    return set(data) if set_mode else data
            except: return set() if set_mode else {}
        return set() if set_mode else {}

    def save_json(self, filepath, data):
        try:
            with open(filepath, 'w') as f:
                json.dump(list(data) if isinstance(data, set) else data, f)
        except: pass

    def normalize_id(self, raw_id, link="", title=""):
        text = f"{raw_id} {link} {title}".upper()
        if m := re.search(r"CVE-\d{4}-\d{4,7}", text): return m.group(0)
        if m := re.search(r"GHSA-[a-zA-Z0-9-]{10,}", text): return m.group(0)
        if m := re.search(r"ZDI-\d{2}-\d{3,}", text): return m.group(0)
        if "http" in raw_id: return raw_id.split("/")[-1][:25]
        return raw_id[:25]

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
        if item['source'] == "CISA KEV": return True
        if item.get('score', 0) >= 9.0: return True
        text = (str(item.get('desc', '')) + " " + str(item.get('title', ''))).lower()
        if any(x in text for x in ["critical", "rce", "zero-day", "active exploitation"]): return True
        return False

    async def parse_generic(self, session, source, mode):
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            items = []
            if "json" in mode:
                async with session.get(source["url"], timeout=timeout) as response:
                    if response.status == 200:
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
                    if response.status == 200:
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
        except: return []

    async def fetch_all(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.parse_generic(session, s, s["type"]) for s in self.sources]
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

    async def process_intelligence(self):
        await self.check_commands()
        logger.info("🔎 Filtreli Tarama (Sadece Yüksek/Kritik Bildirimi)...")
        self.check_daily_reset()
        await self.check_heartbeat()
        
        # Son tarama zamanını kaydet (ChatOps kontrolü için)
        tr_timezone = pytz.timezone('Europe/Istanbul')
        self.last_scan_timestamp = datetime.now(tr_timezone).strftime("%H:%M:%S")

        all_threats = await self.fetch_all()
        for threat in all_threats:
            if threat["id"] not in self.known_ids:
                self.known_ids.add(threat["id"])
                
                self.update_daily_stats(threat)
                self.save_json(self.memory_file, self.known_ids)
                self.log_to_monthly_json(threat)
                
                # --- BİLDİRİM FİLTRESİ (SESSİZ MOD) ---
                score = threat.get('score', 0)
                is_urgent = False
                
                # 1. Skor 7.0 ve üzeri
                if score >= 7.0: is_urgent = True
                # 2. CISA Listesi
                elif threat['source'] == "CISA KEV": is_urgent = True
                # 3. Exploit/Zero-Day Keyword
                elif self.check_is_critical(threat): is_urgent = True
                
                if is_urgent:
                    msg = await self.format_alert(threat, is_hourly=False)
                    # Çift Buton ile gönder
                    await self.send_telegram_card(msg, link=threat['link'], search_query=threat['id'])
                else:
                    # Düşük/Orta seviye ise sadece loga yazdık, bildirim atmıyoruz.
                    pass 

        # Saatlik özet (pending_reports) artık kullanılmıyor, kaldırıldı.
        self.last_flush_time = datetime.now()
