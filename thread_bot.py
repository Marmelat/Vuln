import aiohttp
import asyncio
import logging
import json
import os
import xml.etree.ElementTree as ET
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
        
        # --- KAYNAK LİSTESİ (VENDORS EKLENDİ) ---
        self.sources = [
            # 1. GLOBAL OTORİTELER
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?state=PUBLISHED&time_modified_gt=", "type": "json_cveorg"},
            {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_cisa"},
            {"name": "NIST NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40&pubStartDate=", "type": "json_nist"},
            
            # 2. ÜRETİCİ (VENDOR) RESMİ AKIŞLARI (Doğrulanmış Linkler)
            # Cisco Security Advisories
            {"name": "Cisco PSIRT", "url": "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "type": "rss_generic"},
            # Palo Alto Networks Security Advisories
            {"name": "Palo Alto", "url": "https://security.paloaltonetworks.com/rss.xml", "type": "rss_generic"},
            # Fortinet (FortiGuard)
            {"name": "Fortinet", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "rss_generic"},
            # HPE & Aruba (HPE SIRT)
            {"name": "HPE/Aruba", "url": "https://sirt.hpe.com/feed", "type": "atom_generic"},
            # CrowdStrike Blog (Advisories)
            {"name": "CrowdStrike", "url": "https://www.crowdstrike.com/feed/", "type": "rss_generic"},
            # Check Point Research
            {"name": "Check Point", "url": "https://research.checkpoint.com/feed/", "type": "rss_generic"},

            # 3. İSTİHBARAT VE EXPLOIT KAYNAKLARI
            {"name": "Vulners", "url": "https://vulners.com/rss.xml", "type": "rss_generic"},
            {"name": "GitHub Advisory", "url": "https://github.com/advisories.atom", "type": "atom_generic"},
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "rss_generic"},
            {"name": "Tenable", "url": "https://www.tenable.com/plugins/feeds?sort=newest", "type": "rss_generic"},
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "type": "rss_generic"},
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/files/", "type": "rss_generic"}
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

    def check_daily_reset(self, force_check=False):
        today_str = str(date.today())
        if self.daily_stats.get("date") != today_str:
            if not force_check: asyncio.create_task(self.send_daily_summary_report())
            self.daily_stats = {
                "date": today_str, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "items": []
            }
            self.save_json(self.daily_stats_file, self.daily_stats)

    # --- SEVİYE VE RENK (GÖRSELE UYGUN) ---
    def get_severity_info(self, score):
        try: s = float(score)
        except: return "🔵 BİLGİ (INFO)", "🔵"
        
        if s >= 9.0: return "🛑 KRİTİK (CRITICAL)", "🛑"
        elif s >= 7.0: return "🔴 YÜKSEK (HIGH)", "🔴"
        elif s >= 4.0: return "🟠 ORTA (MEDIUM)", "🟠"
        elif s > 0.0:  return "🟡 DÜŞÜK (LOW)", "🟡"
        else: return "🔵 BİLGİ (INFO)", "🔵"

    def update_daily_stats(self, item):
        self.check_daily_reset()
        self.daily_stats["total"] += 1
        score = item.get('score', 0)
        try: s = float(score)
        except: s = 0
        if s >= 9.0: self.daily_stats["critical"] += 1
        elif s >= 7.0: self.daily_stats["high"] += 1
        elif s >= 4.0: self.daily_stats["medium"] += 1
        elif s > 0.0: self.daily_stats["low"] += 1
        self.daily_stats["items"].append({"title": item.get("title", "No Title"), "score": s})
        self.save_json(self.daily_stats_file, self.daily_stats)

    # --- MARKA VE ETİKET ALGILAMA MOTORU ---
    def detect_os_and_tags(self, text):
        text = text.lower()
        system = "Genel / Diğer"
        tags = ["#SiberGuvenlik"]
        
        # Marka Eşleştirme Listesi
        # Format: "aranan_kelime": ("Ekranda Görünecek İsim", "#Hashtag")
        mapping = {
            # İşletim Sistemleri
            "windows": ("Microsoft Windows", "#Windows"),
            "linux": ("Linux Kernel", "#Linux"),
            "android": ("Android OS", "#Android"),
            "ios": ("Apple iOS", "#iOS"),
            # Network & Güvenlik Ürünleri
            "cisco": ("Cisco Systems", "#Cisco"),
            "palo alto": ("Palo Alto Networks", "#PaloAlto"),
            "panos": ("Palo Alto PanOS", "#PanOS"),
            "fortinet": ("Fortinet", "#Fortinet"),
            "fortios": ("FortiOS", "#Fortinet"),
            "aruba": ("HPE Aruba", "#Aruba"),
            "hpe": ("Hewlett Packard", "#HPE"),
            "checkpoint": ("Check Point", "#CheckPoint"),
            "a10": ("A10 Networks", "#A10"),
            "f5": ("F5 Networks", "#F5"),
            # Kimlik & Erişim (IAM/PAM)
            "cyberark": ("CyberArk PAM", "#CyberArk"),
            "delinea": ("Delinea (Thycotic)", "#Delinea"),
            "beyondtrust": ("BeyondTrust", "#BeyondTrust"),
            "forcepoint": ("Forcepoint", "#Forcepoint"),
            "ping": ("Ping Identity", "#PingIdentity"),
            # Endpoint & Yönetim
            "crowdstrike": ("CrowdStrike", "#CrowdStrike"),
            "symantec": ("Symantec (Broadcom)", "#Symantec"),
            "broadcom": ("Broadcom/Symantec", "#Broadcom"),
            "manageengine": ("ManageEngine", "#ManageEngine"),
            "zoho": ("Zoho/ManageEngine", "#ManageEngine"),
            "ivanti": ("Ivanti", "#Ivanti"),
            "solarwinds": ("SolarWinds", "#SolarWinds"),
            # Yazılım
            "wordpress": ("WordPress", "#WordPress"),
            "exchange": ("MS Exchange", "#Exchange"),
            "sql": (None, "#SQLi"),
            "xss": (None, "#XSS"),
            "rce": (None, "#RCE")
        }
        
        for key, val in mapping.items():
            if key in text:
                if val[0]: system = val[0]
                tags.append(val[1])
                
        # Eğer özel bir şey bulamadıysa başlığı sistem adı yapmaya çalış (Kısa)
        if system == "Genel / Diğer" and len(text) < 20:
            pass 
            
        return system, " ".join(list(set(tags)))

    def translate_text(self, text):
        if not text or len(text) < 3: return text
        try: return self.translator.translate(text[:499])
        except: return text

    async def send_telegram(self, message):
        if not self.tg_token or not self.tg_chat_id: return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {"chat_id": self.tg_chat_id, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True}
        async with aiohttp.ClientSession() as session:
            try: await session.post(url, json=payload)
            except Exception as e: logger.error(f"Telegram Hatası: {e}")

    # --- BİLDİRİM ŞABLONU ---
    def format_alert(self, item, is_hourly=False):
        tr_title = self.translate_text(item.get('title', ''))
        tr_desc = self.translate_text(item.get('desc', ''))
        system_name, hashtags = self.detect_os_and_tags(item['title'] + " " + item['desc'])
        severity_label, icon = self.get_severity_info(item.get('score', 0))
        vuln_id = item.get('id', 'N/A')
        header = f"{icon} KRİTİK ZAFİYET UYARISI" if not is_hourly else f"{icon} ZAFİYET DETAYI"
        
        msg = (
            f"<b>{header}</b>\n"
            f"<pre>"
            f"╔══════════════════════════════╗\n"
            f"║ KİMLİK KARTI                 ║\n"
            f"╠══════════════════════════════╣\n"
            f"║ ID      : {vuln_id[:18].ljust(18)} ║\n"
            f"║ SİSTEM  : {system_name[:18].ljust(18)} ║\n"
            f"║ SEVİYE  : {severity_label.split(' ')[1].ljust(18)} ║\n"
            f"║ SKOR    : {str(item.get('score',0)).ljust(18)} ║\n"
            f"╚══════════════════════════════╝\n"
            f"\n"
            f"AÇIKLAMA:\n"
            f"{tr_desc}\n"
            f"</pre>\n"
            f"🔗 <a href='{item['link']}'>Kaynak ve Çözüm Linki</a>\n\n"
            f"🏷 {hashtags}\n"
            f"ℹ️ <i>Kaynak: {item['source']}</i>"
        )
        return msg

    async def send_daily_summary_report(self):
        stats = self.daily_stats
        if stats["total"] == 0: return
        msg = (
            f"📊 <b>GÜNLÜK İSTİHBARAT RAPORU</b>\n"
            f"🗓 <b>Tarih: {stats['date']}</b>\n"
            f"<pre>"
            f"┌──────────────┬──────┐\n"
            f"│ SEVİYE       │ ADET │\n"
            f"├──────────────┼──────┤\n"
            f"│ 🛑 KRİTİK    │ {str(stats['critical']).ljust(4)} │\n"
            f"│ 🔴 YÜKSEK    │ {str(stats['high']).ljust(4)} │\n"
            f"│ 🟠 ORTA      │ {str(stats['medium']).ljust(4)} │\n"
            f"│ 🟡 DÜŞÜK     │ {str(stats['low']).ljust(4)} │\n"
            f"├──────────────┼──────┤\n"
            f"│ ⚪ TOPLAM    │ {str(stats['total']).ljust(4)} │\n"
            f"└──────────────┴──────┘\n\n"
            f"TESPİT ÖZETİ:\n"
        )
        for i, item in enumerate(stats["items"]):
            sev_label, icon = self.get_severity_info(item['score'])
            msg += f"{icon} {item['title'][:25]}...\n"
            if i >= 15:
                msg += f"\n... ve {stats['total'] - 16} kayıt daha."
                break
        msg += f"</pre>\n🛡 <i>SecurityBot v5.0 (Vendor Edition)</i>"
        await self.send_telegram(msg)

    def check_is_critical(self, item):
        if item['source'] == "CISA KEV": return True
        try: s = float(item.get('score', 0))
        except: s = 0
        if s >= 9.0: return True
        text = (str(item.get('desc', '')) + " " + str(item.get('title', ''))).lower()
        keywords = ["critical", "kritik", "rce", "remote code", "zero-day", "0-day", "active exploitation"]
        for key in keywords:
            if key in text: return True
        return False

    # --- PARSERLAR ---
    async def parse_generic(self, session, source, mode):
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            # CISA
            if mode == "json_cisa":
                async with session.get(source["url"], timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        return [{
                            "id": i.get("cveID"), "source": source["name"],
                            "title": i.get("vulnerabilityName"), "desc": i.get("shortDescription"),
                            "link": f"https://www.cve.org/CVERecord?id={i.get('cveID')}",
                            "score": 10.0
                        } for i in data.get("vulnerabilities", [])[:5]]
            # NIST
            elif mode == "json_nist":
                 yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.000')
                 async with session.get(source["url"]+yesterday, timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        res = []
                        for i in data.get("vulnerabilities", []):
                            cve = i.get("cve", {})
                            metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                            if metrics:
                                score = metrics[0].get("cvssData", {}).get("baseScore", 0)
                                if score >= 7.0: 
                                    res.append({
                                        "id": cve.get("id"), "source": source["name"],
                                        "title": f"NIST: {cve.get('id')}",
                                        "desc": next(iter([d['value'] for d in cve.get('descriptions', []) if d['lang']=='en']), ""),
                                        "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                                        "score": score
                                    })
                        return res
            # RSS
            elif mode == "rss_generic":
                headers = {'User-Agent': 'Mozilla/5.0'}
                async with session.get(source["url"], headers=headers, timeout=timeout) as response:
                    if response.status == 200:
                        content = await response.text()
                        root = ET.fromstring(content)
                        # Namespace temizliği için basit çözüm
                        items = root.findall(".//item")
                        if not items: # Namespace varsa (örn: Cisco)
                             items = root.findall(".//{http://purl.org/rss/1.0/}item")
                        
                        return [{
                            "id": i.find("link").text, "source": source["name"],
                            "title": i.find("title").text, "desc": (i.find("description").text or "")[:500],
                            "link": i.find("link").text, "score": 0
                        } for i in items[:5]]

            # ATOM
            elif mode == "atom_generic":
                headers = {'User-Agent': 'Mozilla/5.0'}
                async with session.get(source["url"], headers=headers, timeout=timeout) as response:
                    if response.status == 200:
                        content = await response.text()
                        root = ET.fromstring(content)
                        ns = {'atom': 'http://www.w3.org/2005/Atom'}
                        res = []
                        for entry in root.findall("atom:entry", ns)[:5]:
                            title = entry.find("atom:title", ns).text
                            link_elem = entry.find("atom:link", ns)
                            link = link_elem.attrib.get('href') if link_elem is not None else "N/A"
                            summary = entry.find("atom:summary", ns)
                            if summary is None: summary = entry.find("atom:content", ns)
                            desc = summary.text if summary is not None else "Açıklama yok"
                            res.append({"id": link, "source": source["name"], "title": title, "desc": desc[:500], "link": link, "score": 0})
                        return res

            # CVE.ORG
            elif mode == "json_cveorg":
                since_time = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%S')
                async with session.get(source["url"]+since_time, timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        return [{
                            "id": i.get("cve_id"), "source": source["name"],
                            "title": f"Yeni CVE: {i.get('cve_id')}", "desc": "Yeni zafiyet yayınlandı.",
                            "link": f"https://www.cve.org/CVERecord?id={i.get('cve_id')}",
                            "score": 0
                        } for i in data.get("cve_ids", [])[:10]]
        except Exception: pass
        return []

    async def fetch_all(self):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for s in self.sources:
                tasks.append(self.parse_generic(session, s, s["type"]))
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

    async def process_intelligence(self):
        logger.info("🔎 Tehdit İstihbaratı Taranıyor (Vendors + Global)...")
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
                    await self.send_telegram(msg)
                else:
                    self.pending_reports.append(threat)

        time_diff = datetime.now() - self.last_flush_time
        if time_diff.total_seconds() >= 3600:
            if self.pending_reports:
                await self.send_telegram(f"⏰ <b>SAATLİK ÖZET ({len(self.pending_reports)} kayıt)</b>")
                for item in self.pending_reports:
                    msg = self.format_alert(item, is_hourly=True)
                    await self.send_telegram(msg)
                    await asyncio.sleep(1)
                self.pending_reports = []
            self.last_flush_time = datetime.now()