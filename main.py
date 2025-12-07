import asyncio
import logging
import sys
import os
import time
from dotenv import load_dotenv
from thread_bot import IntelThread 

# .env Yükle
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("SecurityBot")

async def main():
    logger.info("🔥 Gelişmiş Tehdit Botu (ChatOps + Multi-Source) Başlatılıyor...")
    
    bot_thread = IntelThread()
    
    # Tarama aralığı (Varsayılan 300 sn / 5 dk)
    scan_interval = int(os.getenv("INTERVAL", "300"))
    
    # Son tarama zamanını tutan sayaç
    last_scan_time = 0

    logger.info(f"✅ Sistem Aktif! Tarama Aralığı: {scan_interval} saniye.")
    logger.info("💬 ChatOps dinleniyor... Komut gönderebilirsiniz.")

    while True:
        try:
            current_time = time.time()

            # 1. GÖREV: ChatOps Komutlarını Kontrol Et (Her döngüde çalışır - Hızlı)
            # Bu sayede bot uyumaz, yazdığın an cevap verir.
            await bot_thread.check_commands()

            # 2. GÖREV: İstihbarat Taraması (Sadece süre dolunca çalışır - Ağır)
            if current_time - last_scan_time > scan_interval:
                # process_intelligence içindeki check_commands çağrısı mükerrer olabilir 
                # ama zarar vermez, güvenlik için kalabilir.
                await bot_thread.process_intelligence()
                last_scan_time = current_time
                logger.info(f"Tarama bitti. Bir sonraki tarama {scan_interval} saniye sonra...")

            # 3. CPU Dostu Bekleme
            # Döngüyü 1 saniye uyutuyoruz ki işlemciyi %100 kullanmasın.
            # Ama 60 saniye değil, sadece 1 saniye uyuyor.
            await asyncio.sleep(1)
            
        except KeyboardInterrupt:
            logger.info("🛑 Bot kullanıcı tarafından durduruldu.")
            break
        except Exception as e:
            logger.error(f"Ana Döngü Kritik Hatası: {e}")
            # Hata alsa bile sistemi tamamen çökertme, 5 saniye bekle devam et
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
