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
