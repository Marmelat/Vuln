🛡️ SecurityBot: AI-Powered Cyber Threat Intelligence (CTI) Assistant

SecurityBot, siber güvenlik operasyon ekipleri (SOC/CSIRT) için geliştirilmiş, Google Gemini AI destekli, tam otonom bir tehdit istihbarat asistanıdır.

Dünyadaki kritik zafiyet veritabanlarını (NIST, CISA, ZDI), güvenlik bloglarını ve vendor bildirimlerini 7/24 tarar; bunları önem derecesine göre analiz eder ve aksiyon alınabilir (actionable) bildirimler halinde Telegram üzerinden raporlar.
🚀 Temel Özellikler

    🧠 Kademeli Yapay Zeka Analizi (Tiered AI):

        Kritik/Yüksek Tehditler: Gemini AI tarafından derinlemesine analiz edilir, risk ve çözüm önerisi üretilir.

        Düşük/Orta Tehditler: Kaynak tüketimini azaltmak için standart çeviri ile loglanır.

    🗞️ Haber Bülteni Modu: Teknik olmayan siber güvenlik haberlerini gün boyu biriktirir ve mesai bitiminde (18:00) "Günlük Özet" olarak sunar.

    🏢 Envanter Takibi (Asset Watchlist): Sizin belirlediğiniz ürünlerde (Örn: Fortinet, WordPress) çıkan zafiyetleri puanı düşük olsa bile "Öncelikli" olarak bildirir.

    📈 Zafiyet Eskalasyon Takibi: Daha önce düşük puanlı çıkan bir zafiyetin puanı sonradan yükselirse (Örn: 5.0 -> 9.8), bot bunu fark eder ve "Seviye Yükseldi" alarmı verir.

    💬 ChatOps & Uzaktan Yönetim: Sunucuya bağlanmadan Telegram üzerinden botu yönetebilir, durum sorgulayabilir ve rapor alabilirsiniz.

    📊 Yönetici Raporları: Her ayın son Pazartesi günü (veya talep üzerine), o ayın verilerini analiz eden görselleştirilmiş (Chart) bir CISO raporu sunar.

🛠️ Kurulum

    Repoyu Klonlayın:
    Bash

git clone https://github.com/Marmelat/Vuln.git
cd Vuln

Sanal Ortamı Kurun:
Bash

python3 -m venv venv
source venv/bin/activate

Gereksinimleri Yükleyin:
Bash

pip install -r requirements.txt

Konfigürasyon (.env): .env dosyasını oluşturun ve anahtarlarınızı girin:
Ini, TOML

TELEGRAM_TOKEN=123456:ABC-DEF...
TELEGRAM_CHAT_ID=123456789
GEMINI_API_KEY=AIzaSyD...
INTERVAL=300

Çalıştırın:
Bash

    python main.py

📚 ChatOps Komut Rehberi

Bot ile etkileşime geçmek için Telegram üzerinden aşağıdaki komutları kullanabilirsiniz.
Komut	Açıklama	Örnek Çıktı / Beklenen Davranış
/durum	Sistemin anlık sağlık durumunu, en son tarama saatini ve AI modunu gösterir.	

🤖 SİSTEM DURUMU

🕒 Son Tarama: 14:05:22

📡 Kaynaklar: ✅ Sağlıklı

🧠 AI: ✅ Aktif (Gemini 1.5)

📊 Bugün: 12 veri işlendi.
/indir	O ayın veritabanı dosyasını (.json) sohbet penceresine dosya olarak gönderir.	

📂 12-2025.json yükleniyor...

(Dosya eki gönderilir)
/tara	Bekleme süresini (Sleep) atlayarak anlık manuel tarama başlatır.	🚀 Tarama başlatılıyor...
/debug	Eğer veri çekilemeyen kaynaklar varsa bunların hata kodlarını listeler.	

⚠️ 2 Kaynak Hatalı:

• NIST NVD: 503

• MSRC: 404
/aylik	İçinde bulunulan ayın özet grafiğini ve AI yönetici yorumunu oluşturur.	

📊 ÖZEL RAPOR

🗓 Dönem: Aralık 2025

(Pasta Grafiği Resmi)

📝 AI Analizi: Bu ay fidye yazılımlarında artış gözlemlendi...
/analiz	İki tarih arasındaki verileri analiz eder.	

/analiz 2025-11-01 2025-11-15

⏳ Rapor hazırlanıyor...
🔔 Bildirim Türleri ve Örnekler

Bot, tespit ettiği tehdidin türüne göre farklı formatlarda bildirim gönderir.
1. Kritik Teknik Zafiyet (Anlık)

Yüksek riskli veya envanterinizdeki bir üründe açık çıktığında.

    🛑 ACİL UYARI ⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯ 🆔 CVE-2025-1337 📊 CVSS: 9.8 | EPSS: %92.10 📂 Wordfence (WP)

    📦 Sınıf: Web Uygulaması 🎯 Hedef Sistem: Elementor Pro Plugin ⚡ Teknik Özet: Kimlik doğrulama olmadan dosya yükleme zafiyeti (Unauthenticated File Upload). 💀 Risk: Saldırganlar sunucuya webshell yükleyerek tam yetki sağlayabilir. 🛡️ Aksiyon: Eklentiyi derhal v3.18.2 sürümüne güncelleyin veya devre dışı bırakın.

    🏷️ #WordPress #RCE #PluginVuln

    [ 🔗 Kaynak ] [ 🛡️ Resmi Çözüm ]

2. Haber Bülteni (Saat 18:00)

BleepingComputer, HackerNews gibi kaynaklardan toplanan haberler.

    🗞️ SİBER GÜVENLİKTEN HAVADİSLER 📅 2025-12-08 | Gün Sonu Raporu ⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯

    🔹 Yeni Android Truva Atı Banka Hesaplarını Boşaltıyor └ AI Özeti: "GoldPickaxe" adlı yeni zararlı yazılım, yüz tanıma verilerini çalarak bankacılık uygulamalarına sızıyor.

    🔹 LockBit Fidye Yazılımı Operasyonu Çökertildi └ AI Özeti: Uluslararası polis gücü, LockBit sunucularını ele geçirerek şifre çözme anahtarlarını yayınladı.

📅 Sürüm Geçmişi (Changelog)
Sürüm	Odak Noktası	Geliştirilen Kritik Özellikler
v1.0	Temel Yapı	Standart kaynaklar (NIST, CVE), Telegram mesaj entegrasyonu.
v3.0	Geniş Kapsam	Nessus, Wordfence, GitHub kaynakları, Zafiyet Tekilleştirme (Deduplication).
v6.0	Enterprise	Kademeli Analiz (Tiered): Sadece kritiklerde AI kullanımı, Çift Buton sistemi.
v9.0	Reporting	Aylık CISO Raporlama, Grafiksel analiz, Akıllı Loglama.
v10.1	Ultimate	Haber Bülteni Modu, Zafiyet Sınıflandırma, Envanter Takibi, 404/403 Hata Korumaları.
⚙️ Yapılandırma

Kendi envanterinizi takip etmek için thread_bot.py dosyasındaki listeyi düzenleyebilirsiniz:
Python

self.my_assets = [
    "wordpress", "fortinet", "cisco", "ubuntu", 
    "nginx", "exchange server", "palo alto", "sql server"
]

⚠️ Sorumluluk Reddi

Bu araç, açık kaynaklı istihbarat (OSINT) verilerini toplar. Botun sunduğu çözüm önerileri Yapay Zeka tarafından üretilmektedir; kritik sistemlerde uygulama yapmadan önce mutlaka üretici dökümanlarını teyit ediniz.# 🛡️ SecurityBot: AI-Powered Cyber Threat Intelligence (CTI) Assistant

**SecurityBot**, siber güvenlik operasyon ekipleri (SOC/CSIRT) için geliştirilmiş, **Google Gemini AI** destekli, tam otonom bir tehdit istihbarat asistanıdır.

Dünyadaki kritik zafiyet veritabanlarını (NIST, CISA, ZDI), güvenlik bloglarını ve vendor bildirimlerini 7/24 tarar; bunları önem derecesine göre analiz eder ve **aksiyon alınabilir (actionable)** bildirimler halinde Telegram üzerinden raporlar.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![AI](https://img.shields.io/badge/AI-Google%20Gemini-orange) ![License](https://img.shields.io/badge/License-MIT-green) ![Status](https://img.shields.io/badge/Status-Production%20Ready-red)

---

## 🚀 Temel Özellikler

* **🧠 Kademeli Yapay Zeka Analizi (Tiered AI):**
    * **Kritik/Yüksek Tehditler:** Gemini AI tarafından derinlemesine analiz edilir, risk ve çözüm önerisi üretilir.
    * **Düşük/Orta Tehditler:** Kaynak tüketimini azaltmak için standart çeviri ile loglanır.
* **🗞️ Haber Bülteni Modu:** Teknik olmayan siber güvenlik haberlerini gün boyu biriktirir ve mesai bitiminde (18:00) "Günlük Özet" olarak sunar.
* **🏢 Envanter Takibi (Asset Watchlist):** Sizin belirlediğiniz ürünlerde (Örn: Fortinet, WordPress) çıkan zafiyetleri puanı düşük olsa bile "Öncelikli" olarak bildirir.
* **📈 Zafiyet Eskalasyon Takibi:** Daha önce düşük puanlı çıkan bir zafiyetin puanı sonradan yükselirse (Örn: 5.0 -> 9.8), bot bunu fark eder ve **"Seviye Yükseldi"** alarmı verir.
* **💬 ChatOps & Uzaktan Yönetim:** Sunucuya bağlanmadan Telegram üzerinden botu yönetebilir, durum sorgulayabilir ve rapor alabilirsiniz.
* **📊 Yönetici Raporları:** Her ayın son Pazartesi günü (veya talep üzerine), o ayın verilerini analiz eden görselleştirilmiş (Chart) bir CISO raporu sunar.

---

## 📚 ChatOps Komut Rehberi

Bot ile etkileşime geçmek için Telegram üzerinden aşağıdaki komutları kullanabilirsiniz:

| Komut | Açıklama | Örnek Çıktı / Beklenen Davranış |
| :--- | :--- | :--- |
| `/durum` | Sistemin anlık sağlık durumunu, en son tarama saatini ve AI modunu gösterir. | 🤖 **SİSTEM DURUMU**<br>🕒 Son Tarama: 14:05:22<br>📡 Kaynaklar: ✅ Sağlıklı<br>🧠 AI: ✅ Aktif (Gemini 1.5)<br>📊 Bugün: 12 veri işlendi. |
| `/indir` | O ayın veritabanı dosyasını (`.json`) sohbet penceresine dosya olarak gönderir. | 📂 **12-2025.json** yükleniyor...<br>*(Dosya eki gönderilir)* |
| `/tara` | Bekleme süresini (Sleep) atlayarak anlık manuel tarama başlatır. | 🚀 Tarama başlatılıyor... |
| `/debug` | Eğer veri çekilemeyen kaynaklar varsa bunların hata kodlarını listeler. | ⚠️ **2 Kaynak Hatalı:**<br>• NIST NVD: 503<br>• MSRC: 404 |
| `/aylik` | İçinde bulunulan ayın özet grafiğini ve AI yönetici yorumunu oluşturur. | 📊 **ÖZEL RAPOR**<br>🗓 Dönem: Aralık 2025<br>*(Pasta Grafiği Resmi)*<br>📝 **AI Analizi:** Bu ay fidye yazılımlarında artış gözlemlendi... |
| `/analiz` | İki tarih arasındaki verileri analiz eder. | `/analiz 2025-11-01 2025-11-15`<br>⏳ Rapor hazırlanıyor... |

---

## 🔔 Bildirim Türleri ve Örnekler

Bot, tespit ettiği tehdidin türüne göre farklı formatlarda bildirim gönderir.

### 1. Kritik Teknik Zafiyet (Anlık)
*Yüksek riskli veya envanterinizdeki bir üründe açık çıktığında.*

> 🛑 **ACİL UYARI**
> ⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯
> 🆔 **CVE-2025-1337**
> 📊 **CVSS:** 9.8 | **EPSS:** %92.10
> 📂 **Wordfence (WP)**
>
> 📦 **Sınıf:** Web Uygulaması
> 🎯 **Hedef Sistem:** Elementor Pro Plugin
> ⚡ **Teknik Özet:** Kimlik doğrulama olmadan dosya yükleme zafiyeti (Unauthenticated File Upload).
> 💀 **Risk:** Saldırganlar sunucuya webshell yükleyerek tam yetki sağlayabilir.
> 🛡️ **Aksiyon:** Eklentiyi derhal **v3.18.2** sürümüne güncelleyin veya devre dışı bırakın.
>
> 🏷️ *#WordPress #RCE #PluginVuln*
>
> [ **🔗 Kaynak** ] [ **🛡️ Resmi Çözüm** ]

### 2. Haber Bülteni (Saat 18:00)
*BleepingComputer, HackerNews gibi kaynaklardan toplanan haberler.*

> 🗞️ **SİBER GÜVENLİKTEN HAVADİSLER**
> 📅 *2025-12-08 | Gün Sonu Raporu*
> ⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯
>
> 🔹 [**Yeni Android Truva Atı Banka Hesaplarını Boşaltıyor**](https://...)
> └ *AI Özeti: "GoldPickaxe" adlı yeni zararlı yazılım, yüz tanıma verilerini çalarak bankacılık uygulamalarına sızıyor.*
>
> 🔹 [**LockBit Fidye Yazılımı Operasyonu Çökertildi**](https://...)
> └ *AI Özeti: Uluslararası polis gücü, LockBit sunucularını ele geçirerek şifre çözme anahtarlarını yayınladı.*

---

## 🛠️ Kurulum ve Çalıştırma

1.  **Repoyu Klonlayın:**
    ```bash
    git clone [https://github.com/KULLANICI_ADINIZ/SecurityBot.git](https://github.com/KULLANICI_ADINIZ/SecurityBot.git)
    cd SecurityBot
    ```

2.  **Sanal Ortamı Kurun:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Gereksinimleri Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Konfigürasyon (.env):**
    `.env` dosyasını oluşturun ve anahtarlarınızı girin:
    ```ini
    TELEGRAM_TOKEN=123456:ABC-DEF...
    TELEGRAM_CHAT_ID=123456789
    GEMINI_API_KEY=AIzaSyD...
    INTERVAL=300
    ```

5.  **Çalıştırın:**
    ```bash
    python main.py
    ```

---

## 📅 Sürüm Geçmişi (Changelog)

| Sürüm | Odak Noktası | Geliştirilen Kritik Özellikler |
| :--- | :--- | :--- |
| **v1.0** | Temel Yapı | Standart kaynaklar (NIST, CVE), Telegram mesaj entegrasyonu. |
| **v3.0** | Geniş Kapsam | Nessus, Wordfence, GitHub kaynakları, Zafiyet Tekilleştirme (Deduplication). |
| **v6.0** | Enterprise | **Kademeli Analiz (Tiered):** Sadece kritiklerde AI kullanımı, Çift Buton sistemi. |
| **v9.0** | Reporting | Aylık CISO Raporlama, Grafiksel analiz, Akıllı Loglama. |
| **v10.1**| **Ultimate** | **Haber Bülteni Modu**, Zafiyet Sınıflandırma, Envanter Takibi, 404/403 Hata Korumaları. |

---

## ⚙️ Yapılandırma (Envanter)

Kendi envanterinizi takip etmek için `thread_bot.py` dosyasındaki listeyi düzenleyebilirsiniz:

```python
self.my_assets = [
    "wordpress", "fortinet", "cisco", "ubuntu", 
    "nginx", "exchange server", "palo alto", "sql server"
]
