# PhoneGuard for Termux

Bu proje, Termux üzerinde çalışan güçlü bir telefon güvenlik hardening aracıdır.

Not: Gerçek bir "kuantum koruma" veya "%100 saldırıya dayanıklı" sistem yoktur. Bu proje, cihazı daha dayanıklı ve daha görünür hale getirmek için güçlü bir savunma katmanı sağlar.

## Yeni özellikler
- Başlangıçta otomatik güvenlik taraması
- Şüpheli kabuk komutları, süreçleri ve ağ portlarını tespiti
- Açılışta çalışan koruma betiği
- Anonimleşmiş güvenlik raporu üretimi
- Güvenlik olaylarını günlük dosyasına kayıt
- Daha katı dosya izinleri
- Şüpheli bağlantılar için otomatik koruma denemesi

## Kurulum
```bash
cd ~/InstaFollows
chmod +x install.sh
./install.sh
```

## Çalıştırma
```bash
python ~/.phoneguard/phoneguard.py --once
python ~/.phoneguard/phoneguard.py --watch
```

## Tavsiyeler
- Cihaz kilidi güçlü olsun
- Android cihaz şifreleme açık olsun
- Termux ve paketler güncel kalsın
- USB debugging kapalı olsun
- Güvenli bir SSH anahtarı kullanın
