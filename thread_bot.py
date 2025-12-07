import aiohttp
import asyncio
import logging
import json
import os
import re
import pytz
import feedparser
from datetime import datetime, timedelta, date
from dotenv import load_dotenv
from deep_translator import GoogleTranslator

# .env yükle
load_dotenv()

logger = logging.getLogger("SecurityBot")

class IntelThread:
    def __init__(self):
        # Telegram Ayarları
        self.tg_token = os.getenv("TELEGRAM_TOKEN")
        self.tg_chat_id = os.getenv("TELEGRAM_CHAT_ID")
        
        # Çevirmen
        self.translator = GoogleTranslator(source='auto', target='tr')
        
        # --- GENİŞLETİLMİŞ KAYNAKLAR (PLUGIN & APP ODAKLI) ---
        self.sources = [
            # 1. STANDART CVE/DEVLET KAYNAKLARI
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?state=PUBLISHED&time_modified_gt=", "type": "json_cveorg"},
            {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_cisa"},
            {"name": "NIST NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40&pubStartDate=", "type": "json_nist"},
            {"name": "CERT-EU", "url": "https://www.cert.europa.eu/publications/security-advisories/rss", "type": "feed"},
            
            # 2. VENDOR (ÜRETİCİ) KAYNAKLARI
            {"name": "MSRC (Microsoft)", "url": "https://msrc.microsoft.com/blog/feed/", "type": "feed"},
            {"name": "Cisco PSIRT", "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "type": "feed"},
            {"name": "Fortinet", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "feed"},
            {"name": "Palo Alto", "url": "https://security.paloaltonetworks.com/rss.xml", "type": "feed"},
            
            # 3. OPEN SOURCE & LIBRARY & PLUGIN KAYNAKLARI (OSV MANTIĞI)
            {"name": "GitHub Advisory", "url": "https://github.com/advisories.atom", "type": "feed"}, # Google OSV buradan beslenir
            {"name": "Wordfence (WP)", "url": "https://www.wordfence.com/feed/", "type": "feed"}, # WordPress Pluginleri için KRAL kaynak
            {"name": "Snyk Vuln", "url": "https://snyk.io/blog/feed.xml", "type": "feed"}, # Kütüphane ve App zafiyetleri
            {"name": "Patchstack", "url": "https://patchstack.com/database/rss", "type": "feed"}, # Plugin zafiyetleri için özel
            
            # 4. ARAŞTIRMA & EXPLOIT KAYNAKLARI
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "type": "feed"},
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/files/", "type": "feed"},
            {"name": "Vulners", "url": "https://vulners.com/rss.xml", "type": "feed"},
            {"name": "TrendMicro Research", "url": "https://feeds.feedburner.com/TrendMicroResearch", "type": "feed"},
        ]
        
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        
        self.known_ids = self.load_json(self.memory_file, set_mode=True)
        self.daily_stats = self.load_json(self.daily_stats_file, set_mode=False)
        self.check_daily_reset(force_check=True)

        self.pending_reports = []
        self.last_flush_time = datetime.now()
        self.last_heartbeat_date = None

    # --- AYLIK LOGLAMA SİSTEMİ (SENİN İSTEDİĞİN ÖZELLİK) ---
    def log_to_monthly_json(self, item):
        try:
            tr_timezone = pytz.timezone('Europe/Istanbul')
            simdi = datetime.now(tr_timezone)
            # Ayın son günü 23:50 sonrası için 10dk ileri sarıp yeni aya geçme mantığı
            sanal_zaman = simdi + timedelta(minutes=10)
            dosya_ismi = sanal_zaman.strftime("%m-%Y.json")
            
            item['log_zamani'] = simdi.strftime("%Y-%m-%d %H:%M:%S")

            mevcut_veriler = []
            if os.path.exists(dosya_ismi):
                try:
                    with open(dosya_ismi, 'r', encoding='utf-8') as f:
                        mevcut_veriler = json.load(f)
                except json.JSONDecodeError: mevcut_veriler = []

            mevcut_veriler.append(item)

            with open(dosya_ismi, 'w', encoding='utf-8') as f:
                json.dump(mevcut_veriler, f, ensure_ascii=False, indent=4)
        except Exception as e:
            logger.error(f"Aylık Loglama Hatası: {e}")

    # --- YARDIMCI FONKSİYONLAR ---
    def load_json(self, filepath, set_mode=False):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    return set(data) if set_mode else data
            except Exception: return set() if set_mode else {}
        return set() if set_mode else {}

    def save_json(self, filepath, data):
        try:
            with open(filepath, 'w') as f:
                json_data = list(data) if isinstance(data, set) else data
                json.dump(json_data, f)
        except Exception: pass

    def normalize_id(self, raw_id, link="", title=""):
        """
        GELİŞMİŞ DEDUPLICATION:
        CVE, GHSA (GitHub), ZDI ve WPVDB (Wordfence) ID'lerini yakalar.
        """
        text_search = f"{raw_id} {link} {title}".upper()
        
        # 1. CVE (Evrensel)
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", text_search)
        if cve_match: return cve_match.group(0) 
            
        # 2. GitHub Advisory (OSV ile ortak ID yapısı)
        ghsa_match = re.search(r"GHSA-[a-zA-Z0-9-]{10,}", text_search)
        if ghsa_match: return ghsa_match.group(0)

        # 3. ZDI (Zero Day Initiative)
        zdi_match = re.search(r"ZDI-\d{2}-\d{3,}", text_search)
        if zdi_match: return zdi_match.group(0)

        # 4. Fallback: URL sonu
        if "http" in raw_id: return raw_id.split("/")[-1][:25]
            
        return raw_id[:25]

    def extract_score(self, item):
        if item.get('score', 0) > 0: return float(item['score'])
        text = (item.get('title', '') + " " + item.get('desc', '')).lower()
        # CVSS skorunu metinden ayıklama
        match = re.search(r"(?:cvss|score)[\s:]*([0-9]{1,2}\.?[0-9]?)", text)
        if match:
            try: return float(match.group(1))
            except: return 0.0
        return 0.0

    async def enrich_with_epss(self, cve_id):
        if not cve_id.startswith("CVE-"): return "N/A"
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("data"):
                            epss = float(data["data"][0].get("epss", 0))
                            return f"%{epss * 100:.2f}"
            except: pass
        return "N/A"

    async def check_heartbeat(self):
        now = datetime.now()
        today_str = str(date.today())
        # Sabah 09:00 - 10:00 arası kalp atışı
        if self.last_heartbeat_date != today_str and 9 <= now.hour < 10:
            msg = f"🤖 <b>GÜNLÜK KONTROL</b>\n✅ Sistem Aktif\n📡 Kaynak: {len(self.sources)}"
            await self.send_telegram_card(msg)
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
        elif s > 0.0:  return "🟡 Düşük", "🟡"
        else: return "🔵 Bilgi", "🔵"

    def update_daily_stats(self, item):
        self.check_daily_reset()
        self.daily_stats["total"] += 1
        s = item.get('score', 0)
        if s >= 9.0: self.daily_stats["critical"] += 1
        elif s >= 7.0: self.daily_stats["high"] += 1
        elif s >= 4.0: self.daily_stats["medium"] += 1
        elif s > 0.0: self.daily_stats["low"] += 1
        self.daily_stats["items"].append({"title": item.get("title", ""), "score": s})
        self.save_json(self.daily_stats_file, self.daily_stats)

    def detect_os_and_tags(self, text):
        text = text.lower()
        system = "Genel / Diğer"
        tags = ["#CyberIntel"]
        mapping = {
            "windows": ("Microsoft Windows", "#Windows"),
            "linux": ("Linux Kernel", "#Linux"),
            "android": ("Android OS", "#Android"),
            "ios": ("Apple iOS", "#iOS"),
            "wordpress": ("WordPress", "#WordPress"),
            "plugin": ("Eklenti/Plugin", "#PluginVuln"), # YENİ TAG
            "sql": (None, "#SQLi"),
            "xss": (None, "#XSS"),
            "rce": (None, "#RCE")
        }
        for key, val in mapping.items():
            if key in text:
                if val[0]: system = val[0]
                tags.append(val[1])
        return system, " ".join(list(set(tags)))

    def translate_text(self, text):
        if not text or len(text) < 3: return text
        try: return self.translator.translate(text[:450])
        except: return text

    async def send_telegram_card(self, message, link=None):
        if not self.tg_token or not self.tg_chat_id: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {"chat_id": self.tg_chat_id, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True}
        if link:
            payload["reply_markup"] = {"inline_keyboard": [[{"text": "🔗 Kaynağa Git", "url": link}]]}
        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload)
            except: pass

    async def send_telegram_photo(self, photo_url, caption):
        if not self.tg_token or not self.tg_chat_id: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendPhoto"
        payload = {"chat_id": self.tg_chat_id, "photo": photo_url, "caption": caption, "parse_mode": "HTML"}
        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload)
            except: pass

    async def format_alert(self, item, is_hourly=False):
        tr_title = self.translate_text(item.get('title', ''))
        tr_desc = self.translate_text(item.get('desc', ''))
        system_name, hashtags = self.detect_os_and_tags(item['title'] + " " + item['desc'])
        
        score = item.get('score', 0)
        severity_label, icon = self.get_severity_info(score)
        
        epss_str = await self.enrich_with_epss(item['id'])
        
        header = "ACİL UYARI" if not is_hourly else "ZAFİYET DETAYI"
        
        return (
            f"<b>{icon} {header}</b>\n"
            f"⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n"
            f"🎯 <b>{item['id']}</b> | {system_name}\n"
            f"📊 <b>CVSS:</b> {score} | <b>EPSS:</b> {epss_str}\n"
            f"📂 {item['source']}\n\n"
            f"{tr_desc}\n\n"
            f"🏷 <i>{hashtags}</i>"
        )

    async def send_daily_summary_report(self):
        stats = self.daily_stats
        if stats["total"] == 0: return
        chart_config = {
            "type": "bar",
            "data": {
                "labels": ["Kritik", "Yüksek", "Orta", "Düşük"],
                "datasets": [{"label": "Sayı", "data": [stats['critical'], stats['high'], stats['medium'], stats['low']], "backgroundColor": ["#8B0000", "#D32F2F", "#F57C00", "#FBC02D"]}]
            },
            "options": {"plugins": {"legend": {"display": False}}}
        }
        chart_url = f"https://quickchart.io/chart?c={json.dumps(chart_config)}&w=500&h=300"
        caption = f"📊 <b>GÜNLÜK RAPOR</b>\n🗓 {stats['date']}\n🔴 Toplam: {stats['total']}"
        await self.send_telegram_photo(chart_url, caption)

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

        except Exception: return []

    async def fetch_all(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.parse_generic(session, s, s["type"]) for s in self.sources]
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

    async def process_intelligence(self):
        logger.info("🔎 Genişletilmiş Tehdit İstihbaratı Taranıyor...")
        self.check_daily_reset()
        await self.check_heartbeat()

        all_threats = await self.fetch_all()
        for threat in all_threats:
            if threat["id"] not in self.known_ids:
                self.known_ids.add(threat["id"])
                
                is_critical = self.check_is_critical(threat)
                if is_critical and threat['score'] == 0: threat['score'] = 9.5
                
                self.update_daily_stats(threat)
                self.save_json(self.memory_file, self.known_ids)
                
                # AYLIK LOGLAMA
                self.log_to_monthly_json(threat)
                
                if is_critical:
                    msg = await self.format_alert(threat, is_hourly=False)
                    await self.send_telegram_card(msg, link=threat['link'])
                else:
                    self.pending_reports.append(threat)

        time_diff = datetime.now() - self.last_flush_time
        if time_diff.total_seconds() >= 3600:
            if self.pending_reports:
                await self.send_telegram_card(f"⏰ <b>SAATLİK ÖZET ({len(self.pending_reports)})</b>")
                for item in self.pending_reports:
                    msg = await self.format_alert(item, is_hourly=True)
                    await self.send_telegram_card(msg, link=item['link'])
                    await asyncio.sleep(1)
                self.pending_reports = []
            self.last_flush_time = datetime.now()
