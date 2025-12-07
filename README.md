# 🛡️ Advanced Cyber Threat Intelligence Bot (CTI-Bot)

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Production-red)

**CTI-Bot**, siber güvenlik dünyasındaki kritik zafiyetleri, exploit kodlarını ve vendor (üretici) güvenlik duyurularını 7/24 takip eden, analiz eden ve anlık bildirim gönderen gelişmiş bir Python botudur.

## 🚀 Özellikler

- **Geniş İstihbarat Ağı:** CISA KEV, NIST NVD, CVE.org, Vulners, ZeroDayInitiative, GitHub Advisories ve daha fazlası.
- **Vendor Takibi:** Cisco, Palo Alto, Fortinet, Microsoft, CrowdStrike gibi devlerin güvenlik bültenlerini doğrudan kaynağından (RSS/Atom) çeker.
- **Akıllı Analiz Motoru:**
  - RSS, Atom ve JSON formatlarını otomatik algılar (`feedparser`).
  - Metin analizi ile etkilenen sistemi (OS) ve saldırı türünü (RCE, SQLi, XSS) tespit eder.
  - Zafiyet skoruna (CVSS) göre otomatik renk ve emoji atar (🛑 Kritik, 🔴 Yüksek vb.).
- **Türkçe & Yerel:** İngilizce gelen teknik açıklamaları yapay zeka tabanlı kütüphanelerle Türkçe'ye çevirir.
- **Görsel Raporlama:** Gün sonunda, yakalanan tehditlerin istatistiksel dağılımını içeren grafikli (Chart) rapor sunar.
- **Telegram Entegrasyonu:** Profesyonel "Zafiyet Kimlik Kartı" formatında, butonlu ve etiketli (Hashtag) bildirimler gönderir.

## 🛠️ Kurulum

Projeyi yerel makinenize veya sunucunuza (VPS) kurmak için adımları izleyin.

### Gereksinimler
- Python 3.8 veya üzeri
- `pip` paket yöneticisi

### Adım 1: Repoyu Klonlayın
```bash
git clone (https://github.com/Marmelat/Vuln)
cd Vuln

Adım 2: Sanal Ortam (Virtual Environment)
Sistem kütüphanelerini korumak için sanal ortam kullanılması önerilir.
# Venv paketini kurun (Debian/Ubuntu)
sudo apt update && sudo apt install python3-venv -y

# Sanal ortamı oluşturun
python3 -m venv venv

# Aktif edin
source venv/bin/activate

Adım 3: Kütüphaneleri Yükleyin
pip install --upgrade pip
pip install aiohttp feedparser deep-translator python-dotenv

Adım 4: Konfigürasyon (.env)
Proje ana dizininde .env dosyası oluşturun ve bilgilerinizi girin.
nano .env

Şablon:
# Çalışma Ortamı
ENV=PROD

# Telegram Ayarları (@BotFather'dan alınır)
TELEGRAM_TOKEN=SENIN_BOT_TOKENIN
TELEGRAM_CHAT_ID=SENIN_CHAT_ID

# Tarama Aralığı (Saniye)
INTERVAL=60

⚙️ 7/24 Servis Olarak Çalıştırma (Systemd)
Botun sunucu yeniden başlasa bile otomatik çalışması için servis kaydı oluşturun.

1. Servis dosyasını açın:
sudo nano /etc/systemd/system/botum.service
2. Aşağıdaki kodları yapıştırın: (Dosya yollarının /root/botum olduğunu varsayar)
[Unit]
Description=Cyber Threat Intelligence Bot
After=network.target

[Service]
# Çalışma dizini
WorkingDirectory=/root/botum

# Sanal ortamdaki Python yolu (ÖNEMLİ)
ExecStart=/root/botum/venv/bin/python /root/botum/main.py

# Hata durumunda yeniden başlat
Restart=always
RestartSec=10

# Yetkiler
User=root
Group=root

# Loglama
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target

3. Servisi Başlatın:
sudo systemctl daemon-reload
sudo systemctl start botum
sudo systemctl enable botum

4. Logları İzleyin:
sudo journalctl -u botum -f

| Sürüm | Odak Noktası | Temel Amaç | Geliştirilen Kritik Özellikler |
| :--- | :--- | :--- | :--- |
| **v1.0** | **The Foundation**<br>*(Temel Yapı)* | Tehdit verilerini toplayıp Telegram'a iletmek. | • Standart kaynaklar (NIST, CVE, CISA)<br>• Tek yönlü mesaj iletimi<br>• Google Translate ile basit çeviri |
| **v2.0** | **Data Retention**<br>*(Veri Arşivleme)* | Veri kaybını önlemek ve raporlanabilir kayıt tutmak. | • Aylık JSON rotasyonu (Örn: `12-2025.json`)<br>• Türkiye saati (pytz) entegrasyonu<br>• Otomatik ay sonu dosya geçişi |
| **v3.0** | **Enhanced Coverage**<br>*(Geniş Kapsam)* | Uygulama/Plugin zafiyetlerini yakalamak ve tekrarı önlemek. | • Yeni Kaynaklar: Tenable, Wordfence, Snyk, GitHub<br>• Gelişmiş Deduplication (Tekilleştirme)<br>• Otomatik Etiketleme (`#WordPress`, `#RCE`) |
| **v4.0** | **ChatOps**<br>*(İnteraktif Yönetim)* | Sunucuya girmeden botu uzaktan yönetebilmek. | • Komut Sistemi (`/durum`, `/indir`, `/tara`)<br>• Veritabanı dosyasını chat'ten indirme<br>• Watchdog mimarisi (Kesintisiz dinleme) |
| **v5.0** | **The Brain (AI)**<br>*(Yapay Zeka)* | Sadece çeviri değil, teknik analiz ve yorumlama yapmak. | • Google Gemini LLM entegrasyonu<br>• Uzman analizi için özel Prompt mühendisliği<br>• Hata durumunda Fallback (Yedek) mekanizması |
| **v6.0** | **Enterprise Grade**<br>*(Final Sürüm)* | Maliyeti düşürmek ve aksiyon odaklı çıktı üretmek. | • **Kademeli Analiz (Tiered):** Sadece kritiklerde AI kullanımı<br>• **Çift Buton:** Kaynak Linki + Google Çözüm Araması<br>• **Sanal Ortam:** `venv` ile izole çalışma yapısı |
