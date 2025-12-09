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

# Logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
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
                except:
                    pass
        
        if not self.model:
            logger.warning("⚠️ AI Pasif")

        self.last_update_id = 0
        self.last_scan_timestamp = "Henüz Başlamadı"
        self.failed_sources = {} 
        self.translator = GoogleTranslator(source='auto', target='tr')
        
        # --- 2. KAYNAKLAR ---
        self.sources = [
            {"name": "Tenable Newest", "url": "https://www.tenable.com/plugins/feeds?sort=newest", "type": "html_tenable"},
            {"name": "Tenable Updated", "url": "https://www.tenable.com/plugins/feeds?sort=updated", "type": "html_tenable"},
            {"name": "CVE.org", "url": "https://cveawg.mitre.org/api/cve-id?cveState=PUBLISHED", "type": "json_cveorg"},
            {"name": "ZeroDayInitiative", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "feed"},
        ]
        
        self.memory_file = "processed_intelligence.json"
        self.daily_stats_file = "daily_stats.json"
        
        self.known_ids = self.load_json_safe(self.memory_file)
        self.daily_stats = self.load_json_safe(self.daily_stats_file)
        
        if not isinstance(self.daily_stats, dict) or "date" not in self.daily_stats:
            self.daily_stats = {"date": str(date.today()), "total": 0, "critical": 0}
            
        self.check_daily_reset(force_check=True)
        self.last_flush_time = datetime.now()
        self.last_heartbeat_date = None

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        ]

    # --- AI: TEŞHİS UZMANI ---
    async def ask_gemini_diagnostic(self, error_report):
        if not self.model:
            return "AI Pasif, teşhis yapılamadı."
        try:
            prompt = (
                f"Sen bir Python Bot Debugger uzmanısın. Aşağıdaki hata raporunu analiz et.\n"
                f"Hata Raporu:\n{error_report}\n\n"
                f"Görevin: Hatanın nedenini (Örn: IP Ban, SSL sorunu, Parse hatası) açıkla ve 1 cümlelik çözüm önerisi sun.\n"
                f"Çıktı dili: Türkçe."
            )
            resp = await asyncio.get_event_loop().run_in_executor(None, self.model.generate_content, prompt)
            return resp.text.strip()
        except:
            return "AI Teşhis servisine ulaşılamadı."

    # --- AI: SOC ANALİSTİ ---
    async def ask_gemini(self, title, description, source_name):
        if not self.model:
            return self.translate_text(f"{title}\n{description}")
        try:
            prompt = (
                f"Sen kıdemli bir SOC Analistisin. Zafiyeti analiz et.\n"
                f"Kaynak: {source_name}\nBaşlık: {title}\nDetay: {description[:1500]}\n\n"
                f"Format (Markdown, kod bloğu YOK):\n"
                f"📦 **Sınıf:** [İşletim Sistemi | Web App | Network | Veritabanı]\n"
                f"🎯 **Hedef:** (Ürün/Versiyon)\n"
                f"💀 **Risk:** (Kısa özet)\n"
                f"🛡️ **Aksiyon:** (Emir kipi)"
            )
            resp = await asyncio.get_event_loop().run_in_executor(None, self.model.generate_content, prompt)
            return resp.text.strip()
        except:
            return self.translate_text(f"{title}\n{description}")[:300]

    # --- CHATOPS ---
    async def check_commands(self):
        if not self.tg_token:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/getUpdates"
        params = {"offset": self.last_update_id + 1, "timeout": 1}
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
            try:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        for update in data.get("result", []):
                            self.last_update_id = update["update_id"]
                            if "message" in update and "text" in update["message"]:
                                if str(update["message"]["chat"]["id"]) == str(self.tg_chat_id):
                                    await self.handle_command(update["message"]["text"])
            except:
                pass

    async def handle_command(self, command):
        cmd = command.strip().split()[0].lower()
        
        if cmd == "/durum":
            stats = self.daily_stats
            ai_status = "✅ Aktif" if self.model else "⚠️ Pasif"
            
            if self.failed_sources:
                error_log = "\n".join([f"- {k}: {v}" for k, v in self.failed_sources.items()])
                ai_diagnosis = await self.ask_gemini_diagnostic(error_log)
                health_msg = f"⚠️ <b>Sorun Var!</b>\n\n🤖 <b>AI Teşhisi:</b>\n<i>{ai_diagnosis}</i>"
            else:
                health_msg = "✅ <b>Tüm Sistemler Stabil</b>"

            msg = (
                f"🛡️ <b>SECURITY BOT DURUMU</b>\n"
                f"🕒 Son Tarama: {self.last_scan_timestamp}\n"
                f"🧠 AI Motoru: {ai_status}\n"
                f"📊 Günlük Veri: {stats.get('total', 0)} (Kritik: {stats.get('critical', 0)})\n"
                f"⎯⎯⎯⎯⎯⎯\n{health_msg}"
            )
            await self.send_telegram_card(msg)

        elif cmd == "/rapor":
            await self.generate_monthly_executive_report()

        elif cmd == "/analiz":
            await self.generate_trend_analysis()

        elif cmd == "/tara":
            await self.send_telegram_card("🚀 Manuel Tarama Başlatıldı...")

    # --- RAPORLAMA MOTORU (CISO SEVİYESİ) ---
    async def generate_monthly_executive_report(self):
        fname = datetime.now().strftime("%m-%Y.json")
        if not os.path.exists(fname):
            await self.send_telegram_card("⚠️ <b>Bu aya ait veri henüz oluşmadı.</b>")
            return

        await self.send_telegram_card("📊 <b>Yönetici Raporu Hazırlanıyor...</b>\n<i>Veriler analiz ediliyor.</i>")

        data = self.load_json_safe(fname, is_list=True)
        if not data:
            return

        # İstatistikler
        crit = sum(1 for i in data if i.get('score', 0) >= 9.0)
        high = sum(1 for i in data if 7.0 <= i.get('score', 0) < 9.0)
        top_risks = sorted(data, key=lambda x: x.get('score', 0), reverse=True)[:10]

        ai_summary = "Veri analizi yapılamadı."
        if self.model:
            risk_context = "\n".join([f"- {i['title']} ({i['score']})" for i in top_risks])
            prompt = (
                f"Aşağıdaki siber güvenlik verilerini bir CISO (Bilgi Güvenliği Yöneticisi) için özetle.\n\n"
                f"📊 GENEL DURUM:\n"
                f"- Bu ay toplam **{crit}** adet KRİTİK zafiyet tespit edildi.\n"
                f"- Bu ay toplam **{high}** adet YÜKSEK zafiyet tespit edildi.\n\n"
                f"🔍 TESPİT EDİLEN BAZI ÖRNEKLER (Bağlam için):\n{risk_context}\n\n"
                f"GÖREVİN:\n"
                f"Bu ayki tehdit manzarasını, özellikle **{crit} adet kritik zafiyetin** varlığını vurgulayarak, kurumsal risk açısından değerlendiren tek bir paragraf yaz."
            )
            try:
                resp = await asyncio.get_event_loop().run_in_executor(None, self.model.generate_content, prompt)
                ai_summary = resp.text.strip()
            except:
                pass

        # GRAFİK
        chart_config = {
            "type": "doughnut",
            "data": {
                "labels": ["Kritik", "Yüksek"],
                "datasets": [{
                    "data": [crit, high],
                    "backgroundColor": ["#E74C3C", "#F39C12"],
                    "borderWidth": 0
                }]
            },
            "options": {
                "cutoutPercentage": 60,
                "legend": {"position": "bottom", "labels": {"fontColor": "#FFF", "fontSize": 14}},
                "plugins": {
                    "datalabels": {"color": "#FFF", "font": {"weight": "bold", "size": 16}},
                    "doughnutlabel": {
                        "labels": [
                            {"text": f"{crit}", "font": {"size": 30, "color": "#E74C3C", "weight": "bold"}},
                            {"text": "KRİTİK", "font": {"size": 12, "color": "#AAA"}}
                        ]
                    }
                }
            }
        }
        
        encoded_config = urllib.parse.quote(json.dumps(chart_config))
        chart_url = f"https://quickchart.io/chart?c={encoded_config}&bkg=transparent&w=500&h=400"

        caption = (
            f"📈 <b>AYLIK GÜVENLİK RAPORU</b>\n"
            f"🗓 <b>Dönem:</b> {datetime.now().strftime('%B %Y')}\n"
            f"⎯⎯⎯⎯⎯⎯\n"
            f"🛑 <b>Kritik Zafiyetler:</b> {crit}\n"
            f"🟠 <b>Yüksek Zafiyetler:</b> {high}\n\n"
            f"📝 <b>Yönetici Özeti:</b>\n<i>{ai_summary}</i>"
        )

        await self.download_and_send_photo(chart_url, caption)

    # --- TREND ANALİZİ ---
    async def generate_trend_analysis(self):
        fname = datetime.now().strftime("%m-%Y.json")
        data = self.load_json_safe(fname, is_list=True)
        if not data:
            await self.send_telegram_card("⚠️ Analiz için yeterli veri yok.")
            return

        text_blob = " ".join([i['title'] + " " + i.get('desc','') for i in data]).lower()
        trends = []
        if "vpn" in text_blob: trends.append("VPN/Remote Access")
        if "sql" in text_blob: trends.append("Veritabanı Enjeksiyonları")
        if "linux" in text_blob: trends.append("Linux/Unix Sistemler")
        if "windows" in text_blob: trends.append("Windows Server Altyapısı")
        if "rce" in text_blob: trends.append("Uzaktan Kod Yürütme (RCE)")
        
        trend_msg = ", ".join(trends) if trends else "Genel Yazılım Güncellemeleri"
        
        msg = (
            f"🔎 <b>TREND ANALİZİ (BU AY)</b>\n"
            f"⎯⎯⎯⎯⎯⎯\n"
            f"Sistem, bu ay tespit edilen <b>{len(data)}</b> adet yüksek/kritik tehdidi inceledi.\n\n"
            f"🎯 <b>Saldırganların Odak Noktaları:</b>\n{trend_msg}\n\n"
            f"⚠️ <i>Yapay Zeka Önerisi: Bu varlık gruplarındaki yama seviyelerini acilen denetleyin.</i>"
        )
        await self.send_telegram_card(msg)

    # --- TELEGRAM GÖRSEL ---
    async def download_and_send_photo(self, image_url, caption):
        if not self.tg_token: return
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                async with session.get(image_url) as resp:
                    if resp.status == 200:
                        img_data = await resp.read()
                        url = f"https://api.telegram.org/bot{self.tg_token}/sendPhoto"
                        data = aiohttp.FormData()
                        data.add_field('chat_id', self.tg_chat_id)
                        data.add_field('photo', img_data, filename='report.png')
                        data.add_field('caption', caption)
                        data.add_field('parse_mode', 'HTML')
                        await session.post(url, data=data)
        except Exception as e:
            await self.send_telegram_card(f"{caption}\n\n(Grafik oluşturulamadı: {e})")

    # --- TENABLE DETAY ---
    async def fetch_tenable_details(self, session, url):
        try:
            await asyncio.sleep(random.uniform(1.0, 3.0))
            ua = random.choice(self.user_agents)
            headers = {"User-Agent": ua}
            async with session.get(url, headers=headers, timeout=20, ssl=ssl_context) as response:
                if response.status != 200:
                    return None
                html = await response.text()
                soup = BeautifulSoup(html, 'lxml')
                text_content = soup.get_text()
                
                risk_match = re.search(r"Risk Factor:\s*(Critical|High)", text_content, re.IGNORECASE)
                is_valid = bool(risk_match)
                
                score = 0.0
                match = re.search(r"(?:CVSS v3.*?Base Score|Base Score):\s*([\d\.]+)", text_content, re.IGNORECASE | re.DOTALL)
                if match:
                    score = float(match.group(1))

                # FİLTRE: High (7.0) ve üzeri
                if is_valid or score >= 7.0:
                    final_score = score if score > 0 else (9.5 if "Critical" in str(risk_match) else 7.5)
                    return {"score": final_score}
                return None
        except:
            return None

    # --- CVE DETAY ---
    async def fetch_cve_details(self, session, cve_id):
        url = f"https://www.cve.org/CVERecord?id={cve_id}"
        try:
            await asyncio.sleep(random.uniform(1.0, 3.0))
            async with session.get(url, ssl=ssl_context) as r:
                if r.status != 200:
                    return None
                html = await r.text()
                if "CRITICAL" in html.upper():
                    return {"score": 9.5}
                if "HIGH" in html.upper():
                    return {"score": 8.0}
        except:
            return None
        return None

    # --- DİĞER YARDIMCILAR ---
    async def send_telegram_card(self, message, link=None, search_query=None, extra_ref=None):
        if not self.tg_token:
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = {"chat_id": self.tg_chat_id, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True}
        keyboard = []
        if link:
            keyboard.append({"text": "🔗 Kaynak", "url": link})
        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": [keyboard]}
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as s:
                await s.post(url, json=payload, headers=self.headers)
        except:
            pass

    async def fetch_all(self):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as s:
            tasks = [self.parse_generic(s, src, src["type"]) for src in self.sources]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

    async def parse_generic(self, session, source, mode):
        try:
            await asyncio.sleep(random.uniform(2.0, 5.0))
            items = []
            
            if mode == "html_tenable":
                async with session.get(source["url"], timeout=45) as r:
                    if r.status != 200: 
                        self.failed_sources[source['name']] = f"HTTP {r.status}"
                        return []
                    html = await r.text()
                    soup = BeautifulSoup(html, 'lxml')
                    rows = soup.find_all('tr')
                    for row in rows[:25]:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            link_tag = row.find('a')
                            if link_tag:
                                link = "https://www.tenable.com" + link_tag['href']
                                details = await self.fetch_tenable_details(session, link)
                                if details:
                                    items.append({
                                        "raw_id": link.split('/')[-1],
                                        "title": link_tag.text.strip(),
                                        "desc": "Tenable Plugin Update",
                                        "link": link,
                                        "score": details['score']
                                    })

            elif mode == "json_cveorg":
                async with session.get(source["url"], timeout=45) as r:
                    if r.status != 200:
                        return []
                    d = await r.json()
                    if "cve_ids" in d:
                        for cve_item in d.get("cve_ids", [])[:15]:
                            cve_id = cve_item.get("cve_id")
                            details = await self.fetch_cve_details(session, cve_id)
                            if details:
                                items.append({
                                    "raw_id": cve_id,
                                    "title": f"New CVE: {cve_id}",
                                    "desc": "Official CVE Record",
                                    "link": f"https://www.cve.org/CVERecord?id={cve_id}",
                                    "score": details['score']
                                })

            elif mode == "feed":
                async with session.get(source["url"]) as r:
                    content = await r.read()
                    f = feedparser.parse(content)
                    for e in f.entries[:5]:
                        score = 0.0
                        if "9." in e.title:
                            score = 9.5 
                        items.append({"raw_id": e.link, "title": e.title, "desc": e.summary, "link": e.link, "score": score})

            final = []
            for i in items:
                i['id'] = str(i["raw_id"])[-40:]
                i['source'] = source['name']
                final.append(i)
            return final
        except Exception as e:
            self.failed_sources[source['name']] = f"Error: {e}"
            return []

    async def process_intelligence(self):
        await self.check_commands()
        
        tr = pytz.timezone('Europe/Istanbul')
        simdi = datetime.now(tr)
        self.last_scan_timestamp = simdi.strftime("%H:%M:%S")
        
        logger.info("🔎 Tarama Sürüyor (v36.0 Stable)...")
        self.check_daily_reset()

        all_threats = await self.fetch_all()
        for threat in all_threats:
            tid = threat["id"]
            curr = threat.get('score', 0)
            prev = self.known_ids.get(tid)
            
            # --- FİLTRE: SADECE HIGH (7.0+) ---
            if curr < 7.0:
                continue

            notify = False
            
            if prev is None:
                self.known_ids[tid] = curr
                self.daily_stats['total'] += 1
                self.log_to_monthly_json(threat)
                
                # --- BİLDİRİM: SADECE CRITICAL (9.0+) ---
                if curr >= 9.0 or threat['source'] == "ZeroDayInitiative":
                    notify = True
                    header = "🚨 ACİL GÜVENLİK UYARISI"

            elif curr > prev:
                self.known_ids[tid] = curr
                self.log_to_monthly_json(threat, old_score=prev)
                if curr >= 9.0:
                    notify = True
                    header = "📈 SEVİYE YÜKSELDİ (CRITICAL)"

            if notify:
                msg = await self.format_alert_technical(threat, header)
                await self.send_telegram_card(msg, link=threat['link'])
                self.save_json(self.memory_file, self.known_ids)

        self.save_json(self.memory_file, self.known_ids)
        self.save_json(self.daily_stats_file, self.daily_stats)

    # --- HELPERS (EXPANDED FOR SAFETY) ---
    def load_json_safe(self, f, is_list=False):
        try: 
            with open(f) as file:
                return json.load(file)
        except:
            if is_list:
                return []
            else:
                return {}

    def save_json(self, f, d):
        try:
            with open(f, 'w') as file:
                json.dump(d, file)
        except:
            pass

    def check_daily_reset(self, force_check=False):
        today = str(date.today())
        if not isinstance(self.daily_stats, dict):
            self.daily_stats = {"date": today, "total": 0, "critical": 0}
        
        if self.daily_stats.get("date") != today:
            self.daily_stats = {"date": today, "total": 0, "critical": 0}
            self.save_json(self.daily_stats_file, self.daily_stats)

    def log_to_monthly_json(self, i, old_score=None): 
        try:
            f = datetime.now().strftime("%m-%Y.json")
            d = self.load_json_safe(f, True)
            d.append(i)
            self.save_json(f, d)
        except:
            pass
    
    def translate_text(self, t):
        try:
            return self.translator.translate(t[:450])
        except:
            return t

    def detect_os_and_tags(self, t):
        return "", ""

    async def check_heartbeat(self):
        pass

    async def send_daily_news_digest(self, f=False):
        pass

    async def format_alert_technical(self, item, header):
        score = item['score']
        ai_txt = await self.ask_gemini(item['title'], item['desc'], item['source'])
        return f"<b>{header}</b>\n\n🆔 <b>{item['id']}</b>\n📊 <b>CVSS:</b> {score}\n📂 <b>Kaynak:</b> {item['source']}\n\n{ai_txt}"
