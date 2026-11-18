# lephycrypy+

Türkçe · [English](README.md)

Rust ile yazılmış, açık kaynaklı dosya ve klasör şifreleme aracı. Parolayla ya da başka
kişilerin açık anahtarlarına şifreler; dosya adları ve klasör yapısı her zaman şifrelidir; büyük
dosyalar akış hâlinde işlenir; çıktı atomik yazılır; bellekteki sırlar **en iyi çabayla** en aza
indirilir.

> **Durum: 1.0 öncesi.** Bağımsız bir güvenlik denetiminden geçmemiştir; önemli verilerinizin tek
> kopyası için kullanmayın. Biçim [docs/FORMAT.md](docs/FORMAT.md)'de, güvenlik sınırları
> [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)'de anlatılır (İngilizce).

<p>
  <img src="docs/images/tr/pick.png" width="24%" alt="Dosya bırakma ekranı">
  <img src="docs/images/tr/ready.png" width="24%" alt="Parola ve kayıt yeri ekranı">
  <img src="docs/images/tr/keys.png" width="24%" alt="Açık anahtarla şifreleme ekranı">
  <img src="docs/images/tr/done.png" width="24%" alt="İşlem tamamlandı ekranı">
</p>

## Özellikler

- **Dosya ve klasörler** tek bir `.lphy` arşivi olur: adlar, yapı ve (varsayılan olarak) boyut
  gizlenir. XChaCha20-Poly1305 ya da AES-256-GCM, Argon2id anahtar türetme (varsayılan 512 MiB).
- **Parola ya da açık anahtar.** Parola (isteğe bağlı anahtar dosyasıyla) ya da bir veya birden çok
  X25519 açık anahtarı: dosyayı yalnızca anahtar sahipleri açar, ortak parola gerekmez. İsteğe
  bağlı olarak kuantuma dayanıklı (ML-KEM-768 + X25519); gönderen imzası (Ed25519), kimliğin
  22 kelimelik kâğıt yedeği ve alıcıları sonradan değiştirme.
- **Toplu şifreleme.** Birden çok dosya ya da klasör, her biri ayrı bir `.lphy`.
- **Hasara dayanıklılık.** İsteğe bağlı Reed–Solomon hata düzeltme, bozulan USB bellek ve
  disklerdeki hasarı onarır; kurtarma modu bozuk dosyadan kurtarılabileni çıkarır.
- **Pratik ekler.** Parçalara bölme (ör. FAT32 için), sıkıştırma, parola ve anahtar dosyası
  üretici, doğrulamadan sonra orijinali güvenli silme (onaylı, sınırları açıkça belirtilerek),
  `rekey` ve `reencrypt`.
- **USB modu.** Çıkarılabilir USB belleği temizleyip yalnızca şifreli dosyayı yazar; her yıkıcı
  adımdan önce aygıt kimliğini yeniden denetler.
- **Masaüstü uygulaması** (macOS ve Windows, Türkçe ve İngilizce): sürükle-bırak, `.lphy`
  dosyasına çift tıklama, isteğe bağlı sağ tık girişleri (Finder Hızlı İşlemi, Gezgin menüsü).
- **Mühendislik.** Tüm `unsafe` kod tek küçük crate'te; biçim bağımsız bir Python referansıyla bayt
  bayt karşılaştırılır; fuzz testleri; CI'da `cargo deny`, `cargo audit` ve `cargo vet`.

age, Picocrypt, VeraCrypt ve Cryptomator ile karşılaştırma: [docs/COMPARISON.md](docs/COMPARISON.md).

## Platformlar

| Platform | Durum |
|---|---|
| macOS (aarch64, x86_64) | desteklenir |
| Windows (x86_64) | desteklenir |
| Linux | derlenir, en iyi çaba; `usb` ve masaüstü uygulaması yok |

MSRV: Rust 1.95.0 (`rust-toolchain.toml` ile sabit).

## Komut satırı

```bash
lephycrypy encrypt Belgeler/ -o a1b2c3d4.lphy
```

```bash
lephycrypy decrypt a1b2c3d4.lphy -o Belgeler
```

Dosya ve klasörler her zaman **arşiv** olarak yazılır: adlar ve yapı şifrelidir, boyut PADMÉ ile
yuvarlanır (`--no-pad` kapatır). Tek dosyalık arşiv çözülürken dosya doğrudan hedefe yazılır.
`encrypt -` (stdin) ve `--raw` ham akış üretir. Symlink'ler varsayılan olarak kurulmaz
(`--restore-symlinks`). Bilinen bulut senkron klasörlerine çıkarma onay ister.

| İş | Komut |
|---|---|
| Birden çok kaynak, her biri ayrı `.lphy` | `lephycrypy encrypt a.pdf fotograflar/ not.txt --out-dir cikti/` |
| Önce sıkıştır | `encrypt … --compress` |
| Hata düzeltme ekle (~%7 büyür) | `encrypt … --error-correction` |
| Parçalara böl | `encrypt … --split-size 650m` (çözerken `.001` dosyası verilir) |
| Doğrulamadan sonra orijinali sil | `encrypt … --delete-original` ya da `--secure-delete` |
| Bozuk dosyadan kurtarılabileni çıkar | `decrypt bozuk.lphy --recover` |
| Yazmadan doğrula | `lephycrypy verify dosya.lphy` |
| Arşivi çıkarmadan listele | `lephycrypy list dosya.lphy` |
| Yalnızca bazı yolları çıkar | `decrypt dosya.lphy --only belgeler/ --only not.txt` |
| Şifresiz başlık bilgisi | `lephycrypy info dosya.lphy` |
| Parolayı değiştir (dosya anahtarı aynı) | `lephycrypy rekey dosya.lphy` |
| Parolayı ve dosya anahtarını değiştir | `lephycrypy reencrypt dosya.lphy` |
| Parola / anahtar dosyası üret | `lephycrypy passphrase`, `lephycrypy keyfile-gen anahtar.bin` |

### Açık anahtarlar

```bash
lephycrypy keygen ben.lphykey
```

Parolayla korunan kimliğiniz `ben.lphykey` dosyasına, açık anahtarınız (`lphy1…`) `ben.pub`
dosyasına ve ekrana yazılır. Yalnızca açık anahtarı paylaşın.

```bash
lephycrypy encrypt rapor.pdf -o rapor.lphy -r lphy1… -r arkadas.pub
```

```bash
lephycrypy decrypt rapor.lphy -i ben.lphykey
```

Dosyayı kimin açabileceğini değiştirmek için mevcut alıcılardan biri listenin tamamını yeniler.
Açık anahtarlar dosyada saklanmadığından, erişimi kalacak herkesi (kendiniz dahil) verin:

```bash
lephycrypy recipients rapor.lphy -i ben.lphykey -r ben.pub -r yeni-is-arkadasi.pub
```

İçerik yeniden şifrelenmez; çıkarılan biri eski dosyanın bir kopyasını sakladıysa onu açabilir.

Gelecekteki kuantum bilgisayarlara karşı koruma için alıcıların kuantuma dayanıklı anahtarlarına
şifreleyin (ML-KEM-768 ile X25519 birlikte; `.pub` dosyalarının üçüncü satırı):

```bash
lephycrypy encrypt rapor.pdf -o rapor.lphy --pq -r arkadas.pub
```

Uygulamada "Açık anahtarla" altında **Kuantuma dayanıklı** kutusunu işaretleyin.

Gönderdiğinizi imzalayın; alıcı sizden geldiğini ve değiştirilmediğini bilsin:

```bash
lephycrypy encrypt rapor.pdf -o rapor.lphy -r arkadas.pub --sign ben.lphykey
```

```bash
lephycrypy decrypt rapor.lphy -i arkadas.lphykey --expect-signer ben.pub
```

İmza anahtarı (`lphysig1…`) `keygen` tarafından yazdırılır ve `ben.pub` dosyasının ikinci
satırında durur. İmza parolalı dosyalarda da çalışır; uygulamada gelişmiş ayarlardaki
**Kimliğimle imzala** seçeneğidir, sonuç ekranı dosyayı kimin imzaladığını gösterir.

Kimliğinizin kâğıt yedeğini alın: `lephycrypy identity backup ben.lphykey` 22 kelime gösterir
(uygulama da anahtar çiftini oluşturduktan hemen sonra bir kez gösterir);
`lephycrypy identity restore ben.lphykey` kimlik dosyasını bu kelimelerden yeniden oluşturur.
Kelimelere sahip olan herkes o anahtara şifrelenen her dosyayı açabilir. Kimlik dosyasının kendisi
hiçbir zaman çözülmez.
Uygulamada: kimlik ekranında **Alıcı listesini değiştir…**.

Parola argv'den ya da ortam değişkeninden **asla** okunmaz; betikler için `--password-stdin`,
`--password-fd` (Unix) ve `--password-file` vardır.

## USB belleğe yazma

```bash
lephycrypy usb write yedek.lphy --target /Volumes/USBBELLEK
```

Yalnızca USB veriyolundaki çıkarılabilir ortamlar kabul edilir. Komut silinecekleri gösterir,
birim etiketini ve boyutu aynen yazmanızı ister; her adımdan önce aygıt kimliği yeniden okunur.
Ayrıntılar İngilizce README'dedir.

## Masaüstü uygulaması

İlk açılışta kısa bir karşılama ekranı çıkar. Sonrasında açılış ekranında dört kart vardır:
**Şifrele**, **Şifreyi çöz**, **Anahtarlarım** (anahtar çifti oluşturma, bir kimliğin açık
anahtarlarını gösterme, kâğıt yedeği) ve **Ayarlar**. Altında bir bırakma alanı bulunur.

1. Dosya ya da klasörleri pencereye bırakın veya **Şifrele** / **Şifreyi çöz** kartlarını kullanın.
   `.lphy` dosyaları açılır, diğer her şey şifrelenir.
2. **Parolayla** ya da **Açık anahtarla** seçin. Parola iki kez istenir ve en az 8 karakter
   olmalıdır; güç tahmini ve parola üretici yardımcı olur. Açık anahtarla şifrelerken alıcıların
   anahtarlarını yapıştırın ya da kendi anahtar çiftinizi oluşturun.
3. Gerekirse kayıt yerini değiştirip **Şifrele** ya da **Şifreyi çöz**'e basın.
4. İş bitince **Klasörde göster** sonucu Finder'da ya da Gezgin'de açar.

macOS'ta `.lphy` dosyasına çift tıklamak onu uygulamada açar; her dosya ya da klasör **Birlikte
Aç → lephycrypy+** ile açılabilir.

Pencereyi kapatmak süren bir işi durdurmaz. macOS'ta kırmızı düğme uygulamayı gizler, Dock
simgesi geri getirir. Uygulama yalnızca Cmd+Q ya da Dock → Çık ile kapanır; iş sürüyorsa önce
sorar (iş iptal edilir, yarım dosya silinir). Windows'ta iş sürerken kapatmak pencereyi simge
durumuna küçültür.

**Ayarlar:**

- **Dil:** Türkçe ya da İngilizce (seçene kadar sistem dili).
- **Uygulama kilidi** (varsayılan kapalı): açarsanız uygulama her başlatıldığında parola ister.
  Yalnızca başkalarının uygulamayı kullanmasını engeller; şifreli dosyalar kendi parolaları ve
  anahtarlarıyla korunur. Parolayı unutursanız ayar dosyasını silerek kilidi kaldırabilirsiniz.
- **Finder Hızlı İşlemi** (macOS, yalnızca .app paketi): Finder'da sağ tık → **Hızlı İşlemler**
  altına "lephycrypy+ ile şifrele / aç" ekler. `~/Library/Services` içinde yalnızca geçerli
  kullanıcı için küçük bir iş akışıdır; seçilen öğeleri yalnızca uygulamada açar.
- **Gezgin entegrasyonu** (Windows): yalnızca geçerli kullanıcı için `.lphy` çift tıklamayla açılır,
  her dosya ve klasöre sağ tık girişi eklenir.

İki entegrasyon da yalnızca onaydan sonra eklenir ve kaldırılır. Uygulama yalnızca dili,
karşılama ekranının görüldüğünü ve kilit açıksa doğrulayıcısını (Argon2id) kaydeder:
`~/Library/Application Support/lephycrypy+/settings` (Windows: `%APPDATA%\lephycrypy+`). Dosya
adı ya da parola kaydedilmez.

Şifreli bir arşivde **İçeriği listele**, hiçbir şey yazmadan içinde ne olduğunu gösterir; yalnızca
işaretlediğiniz öğeler çıkarılır.

## Derleme

```bash
cargo build --locked
```

```bash
cargo test --locked --workspace
```

```bash
scripts/macos-app.sh --dmg
```

## Güvenlik

Zafiyetleri herkese açık issue olarak değil, [SECURITY.md](SECURITY.md)'deki yolla (İngilizce)
bildirin.

## Lisans

lephycrypy+ yalnızca [Apache License 2.0](LICENSE) ile lisanslanır.

Atıf zorunludur: dağıtılan her kopya, değiştirilmiş sürüm ya da türev çalışma (ticari ya da
kişisel, kaynak ya da ikili biçimde) [LICENSE](LICENSE) ve [NOTICE](NOTICE) dosyalarını korumalı ve
**lephycrypy+ contributors** adına atıf yapmalıdır (https://github.com/Seesternn/lephycrypy-plus).
Değiştirilen dosyalarda değiştirildikleri belirtilmelidir. Projeyi kullanıyor ya da çatallıyorsanız
lütfen aynı şekilde atıf yapın. Üçüncü taraf içerik için NOTICE.
