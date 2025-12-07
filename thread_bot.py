import aiohttp
import asyncio
import logging
import json
import os
import re
import feedparser # <--- BEST PRACTICE KÜTÜPHANESİ
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
        
        # --- KAYNAKLAR ---
        # Artık RSS ve ATOM ayrımı yapmana gerek yok. feedparser hepsini okur.
        self.sources = [
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?state=PUBLISHED&time_modified_gt=", "type": "json_cveorg"},
            {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_cisa"},
            {"name": "NIST NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40&pubStartDate=", "type": "json_nist"},
            
            # RSS/ATOM Kaynakları (Hepsi aynı 'feed' tipi oldu)
            {"name": "Vulners", "url": "https://vulners.com/rss.xml", "type": "feed"},
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
            {"name": "GitHub Advisory", "url": "https://github.com/advisories.atom", "type": "feed"}, # Atom olsa bile 'feed'
            {"name": "Cisco PSIRT", "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "type": "feed"},
            {"name": "Palo Alto", "url": "https://security.paloaltonetworks.com/rss.xml", "type": "feed"},
            {"name": "Fortinet", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "feed"},
            {"name": "CrowdStrike", "url": "https://www.crowdstrike.com/feed/", "type": "feed"},
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "type": "feed"},
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/files/", "type": "feed"},
            {"name": "Tenable", "url": "https://www.tenable.com/plugins/feeds?sort=newest", "type": "feed"},
            {"name": "MSRC", "url": "https://msrc.microsoft.com/blog/feed/", "type": "feed"}
        ]
        
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        
        self.known_ids = self.load_json(self.memory_file, set_mode=True)
        self.daily_stats = self.load_json(self.daily_stats_file, set_mode=False)
        self.check_daily_reset(force_check=True)

        self.pending_reports = []
        self.last_flush_time = datetime.now()

    # --- YARDIMCI ARAÇLAR ---
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

    def clean_id(self, item):
        raw_id = item.get("id", "")
        # Linkin içinde veya ID alanında CVE/ZDI ara
        text_search = raw_id + " " + item.get("link", "")
        match = re.search(r"(CVE-\d{4}-\d{4,7}|ZDI-\d{2}-\d{3,})", text_search, re.IGNORECASE)
        if match: return match.group(0).upper()
        
        # Yoksa ve URL ise sonunu al
        if "http" in raw_id: return raw_id.split("/")[-1]
        return raw_id[:20]

    def extract_score(self, item):
        if item.get('score', 0) > 0: return float(item['score'])
        text = (item.get('title', '') + " " + item.get('desc', '')).lower()
        match = re.search(r"(?:cvss|score)[\s:]*([0-9]{1,2}\.?[0-9]?)", text)
        if match:
            try: return float(match.group(1))
            except: return 0.0
        return 0.0

    def check_daily_reset(self, force_check=False):
        today_str = str(date.today())
        if self.daily_stats.get("date") != today_str:
            if not force_check: asyncio.create_task(self.send_daily_summary_report())
            self.daily_stats = {
                "date": today_str, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "items": []
            }
            self.save_json(self.daily_stats_file, self.daily_stats)

    def get_severity_info(self, score):
        try: s = float(score)
        except: return "🔵 Bilgi (Info)", "🔵"
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
        self.daily_stats["items"].append({"title": item.get("title", "No Title"), "score": s})
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
            "cisco": ("Cisco Systems", "#Cisco"),
            "fortinet": ("Fortinet", "#Fortinet"),
            "palo alto": ("Palo Alto", "#PaloAlto"),
            "wordpress": ("WordPress", "#WordPress"),
            "exchange": ("MS Exchange", "#Exchange"),
            "sql": (None, "#SQLi"),
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
            payload["reply_markup"] = {
                "inline_keyboard": [[
                    {"text": "🔗 Kaynağa Git", "url": link},
                    {"text": "🛡 Çözüm Ara", "url": f"https://www.google.com/search?q={link.split('/')[-1]}+solution"}
                ]]
            }

        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload)
            except Exception as e: logger.error(f"Telegram Hatası: {e}")

    async def send_telegram_photo(self, photo_url, caption):
        if not self.tg_token or not self.tg_chat_id: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendPhoto"
        payload = {"chat_id": self.tg_chat_id, "photo": photo_url, "caption": caption, "parse_mode": "HTML"}
        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload)
            except: pass

    # --- ŞABLON ---
    def format_alert(self, item, is_hourly=False):
        tr_title = self.translate_text(item.get('title', ''))
        tr_desc = self.translate_text(item.get('desc', ''))
        system_name, hashtags = self.detect_os_and_tags(item['title'] + " " + item['desc'])
        
        score = item.get('score', 0)
        severity_label, icon = self.get_severity_info(score)
        clean_id = self.clean_id(item)
        
        header = "ACİL ZAFİYET UYARISI" if not is_hourly else "ZAFİYET DETAYI"
        
        msg = (
            f"<b>{icon} {header}</b>\n"
            f"⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n"
            f"🎯 <b>{clean_id}</b> | {system_name}\n"
            f"⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n"
            f"📊 <b>Skor:</b> {score} ({severity_label.split(' ')[1]})\n"
            f"📂 <b>Kaynak:</b> {item['source']}\n\n"
            f"📝 <b>Bulgu Özeti:</b>\n"
            f"{tr_desc}\n\n"
            f"🏷 <i>{hashtags}</i>"
        )
        return msg

    async def send_daily_summary_report(self):
        stats = self.daily_stats
        if stats["total"] == 0: return

        chart_config = {
            "type": "bar",
            "data": {
                "labels": ["Kritik", "Yüksek", "Orta", "Düşük"],
                "datasets": [{
                    "label": "Zafiyet Sayısı",
                    "data": [stats['critical'], stats['high'], stats['medium'], stats['low']],
                    "backgroundColor": ["#8B0000", "#D32F2F", "#F57C00", "#FBC02D"]
                }]
            },
            "options": {"plugins": {"legend": {"display": False}}}
        }
        chart_url = f"https://quickchart.io/chart?c={json.dumps(chart_config)}&w=500&h=300"
        caption = f"📊 <b>GÜNLÜK İSTİHBARAT RAPORU</b>\n🗓 Tarih: {stats['date']}\n🔴 Toplam Tespit: {stats['total']}\n🛡 <i>SecurityBot v7.0 (FeedParser)</i>"
        await self.send_telegram_photo(chart_url, caption)

    def check_is_critical(self, item):
        if item['source'] == "CISA KEV": return True
        if item.get('score', 0) >= 9.0: return True
        text = (str(item.get('desc', '')) + " " + str(item.get('title', ''))).lower()
        keywords = ["critical", "kritik", "rce", "remote code", "zero-day", "0-day", "active exploitation"]
        for key in keywords:
            if key in text: return True
        return False

    # --- YENİLENEN GÜÇLÜ PARSER MOTORU ---
    async def parse_generic(self, session, source, mode):
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            items = []
            
            # JSON TİPLİ KAYNAKLAR (Bunlar RSS değildir, özel parser gerekir)
            if "json" in mode:
                async with session.get(source["url"], timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        if mode == "json_cisa":
                            items = [{"id": i.get("cveID"), "title": i.get("vulnerabilityName"), "desc": i.get("shortDescription"), "link": f"https://www.cve.org/CVERecord?id={i.get('cveID')}", "score": 10.0} for i in data.get("vulnerabilities", [])[:5]]
                        elif mode == "json_nist":
                             yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.000')
                             async with session.get(source["url"]+yesterday, timeout=timeout) as response:
                                if response.status == 200:
                                    d = await response.json()
                                    for i in d.get("vulnerabilities", []):
                                        cve = i.get("cve", {})
                                        metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                                        if metrics and metrics[0].get("cvssData", {}).get("baseScore", 0) >= 7.0:
                                            items.append({"id": cve.get("id"), "title": f"NIST: {cve.get('id')}", "desc": "NIST veritabanı kaydı.", "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}", "score": metrics[0].get("cvssData", {}).get("baseScore", 0)})
                        elif mode == "json_cveorg":
                             items = [{"id": i.get("cve_id"), "title": f"Yeni CVE: {i.get('cve_id')}", "desc": "Yeni zafiyet.", "link": f"https://www.cve.org/CVERecord?id={i.get('cve_id')}", "score": 0} for i in (await response.json()).get("cve_ids", [])[:10]]

            # RSS / ATOM / FEED TİPLİ KAYNAKLAR (FeedParser ile otomatik)
            elif mode == "feed":
                async with session.get(source["url"], timeout=timeout) as response:
                    if response.status == 200:
                        content = await response.read() # Raw bytes al
                        feed = feedparser.parse(content) # Feedparser işlesin
                        
                        for entry in feed.entries[:5]:
                            # Başlık ve ID
                            title = entry.get('title', 'Başlık Yok')
                            link = entry.get('link', '')
                            # Açıklama (Summary veya Description)
                            desc = entry.get('summary', '') or entry.get('description', '') or "Açıklama yok"
                            
                            # ID Çıkarma (Link'i kullan, clean_id sonra temizler)
                            unique_id = link 
                            
                            items.append({
                                "id": unique_id,
                                "title": title,
                                "desc": desc[:500], # Çok uzun metinleri kes
                                "link": link,
                                "score": 0 # Sonra extract_score ile bulacağız
                            })

            # Ortak İşleme
            for i in items:
                i['source'] = source['name']
                if i['score'] == 0: i['score'] = self.extract_score(i)
            return items

        except Exception as e: 
            # logger.error(f"Hata ({source['name']}): {e}") # Hata ayıklama için açılabilir
            return []

    async def fetch_all(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.parse_generic(session, s, s["type"]) for s in self.sources]
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

    async def process_intelligence(self):
        logger.info("🔎 Tehdit İstihbaratı Taranıyor (Best Practice)...")
        self.check_daily_reset()
        all_threats = await self.fetch_all()
        for threat in all_threats:
            if threat["id"] not in self.known_ids:
                self.known_ids.add(threat["id"])
                
                is_critical = self.check_is_critical(threat)
                if is_critical and threat['score'] == 0: threat['score'] = 9.5
                
                self.update_daily_stats(threat)
                self.save_json(self.memory_file, self.known_ids)
                
                if is_critical:
                    msg = self.format_alert(threat, is_hourly=False)
                    await self.send_telegram_card(msg, link=threat['link'])
                else:
                    self.pending_reports.append(threat)

        time_diff = datetime.now() - self.last_flush_time
        if time_diff.total_seconds() >= 3600:
            if self.pending_reports:
                await self.send_telegram_card(f"⏰ <b>SAATLİK ÖZET ({len(self.pending_reports)} kayıt)</b>")
                for item in self.pending_reports:
                    msg = self.format_alert(item, is_hourly=True)
                    await self.send_telegram_card(msg, link=item['link'])
                    await asyncio.sleep(1)
                self.pending_reports = []
            self.last_flush_time = datetime.now()
