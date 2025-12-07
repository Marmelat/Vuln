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
git clone [https://github.com/KULLANICI_ADINIZ/REPO_ADINIZ.git](https://github.com/KULLANICI_ADINIZ/REPO_ADINIZ.git)
cd REPO_ADINIZ
