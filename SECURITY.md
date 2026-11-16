# Güvenlik politikası

lephycrypy+ henüz bağımsız kriptografik denetimden geçmemiştir (bkz. docs/THREAT-MODEL.md › Diğer).
1.0 öncesi hiçbir sürüm üretim verisi için önerilmez.

## Zafiyet bildirimi

- Lütfen zafiyetleri herkese açık issue olarak **açmayın**.
- GitHub "Report a vulnerability" (Security Advisories) özelliğini kullanın; depo açıldığında etkinleştirilecektir.
- Yanıt hedefi: 7 gün içinde ilk yanıt, 90 gün koordineli açıklama.

## Kapsam

- Biçim (docs/FORMAT.md) ve anahtar türetme hataları
- Bellekte sır kalıntısı iddiaları (docs/PLAN.md › Sır envanteri'nde "Evet" olarak işaretlenmiş satırlar)
- Arşiv çıkarma (zip-slip, symlink, yinelenen ad) ve atomik yazma ihlalleri
- Tedarik zinciri (deny.toml, supply-chain/)

Kapsam dışı: docs/THREAT-MODEL.md'de açıkça "kapsam dışı" veya "önlem yok" denilen maddeler
(hibernation, swap, OS indeksleme, bulut senkron, SIGKILL, vb.).

## Desteklenen sürümler

| Sürüm | Destek |
|---|---|
| 0.x (aşama 0–3) | yalnızca geliştirme; destek yok |
