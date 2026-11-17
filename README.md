# lephycrypy+

Açık kaynaklı, Rust ile yazılmış dosya/klasör şifreleme aracı. Hedef: parolayla klasör/arşiv
saklama; adlar ve yapı her zaman şifreli; akışlı işleme; atomik yazma; bellekte sır kalıntılarını
**en iyi çaba ile** en aza indirme.

> **Durum: 1.0 öncesi.** Bağımsız bir güvenlik denetiminden geçmemiştir; önemli verileriniz için
> tek yedek olarak kullanmayın. Biçim [docs/FORMAT.md](docs/FORMAT.md)'de, güvenlik sınırları
> [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)'de anlatılır.

## Platformlar

| Platform | Durum |
|---|---|
| macOS (aarch64, x86_64) | desteklenir |
| Windows (x86_64) | desteklenir |
| Linux | derlenir, en iyi çaba; `usb` ve GUI yok |

MSRV: Rust 1.95.0 (`rust-toolchain.toml` ile sabit).

## Crate'ler

| Crate | Rol | unsafe |
|---|---|---|
| `lephy-sys` | tek FFI/unsafe crate: bellek kilitleme, süreç sertleştirme, dosya sistemi, birim, terminal, sinyal | evet, her blokta `// SAFETY:` |
| `lephy-core` | kriptografi, biçim, arşiv, pipeline | `#![forbid(unsafe_code)]` |
| `lephy-cli` | `lephycrypy` komut satırı | `#![forbid(unsafe_code)]` |
| `lephy-usb` | yalnızca çıkarılabilir USB: uygunluk, onay, kimlik yeniden denetimi, silme/biçimlendirme, doldurma, yazma, geri okuma | `#![forbid(unsafe_code)]` |
| `lephy-gui` | `lephycrypy-gui`: egui/eframe tek pencere (macOS/Windows) | `#![forbid(unsafe_code)]`; sıfırlayan global ayırıcı |

## Kullanım

```bash
lephycrypy encrypt Belgeler/ -o a1b2c3d4.lphy
```

```bash
lephycrypy decrypt a1b2c3d4.lphy -o Belgeler
```

Dosya ve klasörler her zaman **arşiv** olarak yazılır: adlar ve yapı şifrelidir, boyut PADMÉ ile
yuvarlanır (`--no-pad` kapatır). Tek dosyalık arşiv çözülürken dosya doğrudan hedefe yazılır.
`encrypt -` (stdin) ve `--raw` ham akış üretir (`--pad` ile ham akışta da dolgu; stdin'de olmaz).
Çözümde symlink'ler varsayılan kurulmaz: `--restore-symlinks` yalnızca göreli/`..`'siz hedefleri,
`--restore-symlinks unsafe` hepsini kurar. `--strict` atlanan/değiştirilen her girişi hata sayar;
`--rename-conflicts` büyük/küçük harf çakışmalarında `_2` ekler. Bilinen bulut senkron
klasörlerine çıkarma onay ister (`--allow-cloud-dir`).

Varsayılanlar: XChaCha20-Poly1305, 1 MiB chunk, Argon2id 512 MiB / 3 / 4. `--alg aes256gcm`,
`--chunk-size 64k|256k|1m|4m|16m`, `--kdf-memory/--kdf-time/--kdf-parallelism`, `--keyfile`,
`--force`, `--strict-memory`, `--delete-original`, `--stdout` (yalnızca ham akış), `--allow-large-kdf`.
Betikler için `--password-stdin`, `--password-fd` (Unix) ve `--password-file`; parola **asla**
argv/env'den alınmaz. `rekey` parolayı değiştirir ama dosya anahtarını korur; gerçek rotasyon
`reencrypt`.

## USB belleğe yazma

```bash
lephycrypy usb list
```

```bash
lephycrypy usb write yedek.lphy --target /Volumes/USBBELLEK
```

Yalnızca **USB veriyolu ve çıkarılabilir ortam** kabul edilir; dahili, sanal, sistem ve Time
Machine birimleri ile "Fixed" görünen harici USB SSD/HDD'ler reddedilir (kod 1, bayrakla aşılamaz).
Windows'ta seri numarası boş aygıtlar da reddedilir. Komut önce silinecekleri gösterir, sonra
birim etiketini **ve** boyutu GiB olarak aynen yazmanızı ister (betikte `--confirm-label` +
`--confirm-size-gib`); uyuşmazlık kod 5'tir ve hiçbir şey silinmez. Her adımdan önce aygıt kimliği
yeniden okunur; değişmişse kod 5 ile durur. Yalnızca geçerli `.lphy` dosyaları yazılır.
`--format` birimi exFAT olarak biçimlendirir (Windows'ta yönetici oturumu gerekir),
`--fill-free-space` boş alanı rastgele veriyle doldurur. FAT/exFAT dizin kalıntıları, NTFS
resident dosyalar ve wear-leveling yüzünden fiziksel silme garantisi yoktur.

## Masaüstü uygulaması

`lephycrypy-gui` (macOS ve Windows) tek pencerelik sade bir uygulamadır:

1. Bir dosya ya da klasörü pencereye bırakın veya **Dosya seç** / **Klasör seç** ile seçin.
   `.lphy` dosyaları açılır, diğer her şey şifrelenir.
2. Parolayı girin. Şifrelerken parola iki kez istenir; en az 8 karakter olmalı ve eşleşme
   anında gösterilir.
3. Kaydedilecek yeri gerekirse **Değiştir** ile seçin ve **Şifrele** ya da **Şifreyi çöz**'e basın.
4. İş bitince **Klasörde göster** sonucu Finder'da ya da Gezgin'de açar.

Parola alanı maskelidir; kopyalama ve yapıştırma kapalıdır, metin doğrudan kilitli bellekte
tutulur. **Gelişmiş ayarlar** altında algoritma, parola türetme belleği ve boyut gizleme seçilir.
Bulut senkron klasörüne çözme ayrıca onay ister. Uygulama sistemin açık/koyu temasını izler ve
sistem yazı tiplerini kullanır. Linux'ta masaüstü uygulaması yoktur.

## Derleme

```bash
cargo build --locked
```

```bash
cargo test --locked --workspace
```

Masaüstü uygulaması:

```bash
cargo run --release -p lephy-gui
```

Fuzz hedefleri `fuzz/` altındadır (ayrı workspace, nightly + `cargo-fuzz`). Biçim vektörleri,
yalnızca FORMAT.md okunarak yazılmış Python referansıyla (`tests/ref/lephy_ref.py`) bayt bayt
karşılaştırılır: `cargo test -p lephy-core --features test-vectors`.

## Çıkış kodları

| kod | anlam |
|---|---|
| 0 | başarı |
| 1 | G/Ç, ortam veya genel hata |
| 2 | kullanım hatası (yalnızca clap) |
| 3 | parola veya anahtar dosyası yanlış |
| 4 | dosya bozuk / biçim ihlali |
| 5 | kullanıcı iptali / onay uyuşmazlığı |
| 6 | KDF bütçesi/RAM yetersiz (`--allow-large-kdf`) |
| 7 | hedef mevcut (`--force`) |
| 8 | disk alanı / FAT32 4 GiB sınırı |
| 130 | SIGINT/SIGTERM/Ctrl+C (Windows'ta da 130; geleneksel 0xC000013A'dan bilinçli sapma) |

## Neden age/rage değil?

age (Go) ve rage (Rust) aynı `age-encryption.org/v1` biçimini kullanır; genel amaçlı şifreleme için
iyi araçlardır. lephycrypy+ daha dar bir hedefe yöneliktir: parolayla klasör/arşiv saklama.

- **KDF:** age parola modunda scrypt kullanır (N kullanıcı ayarlı, r=8, p=1) ve scrypt kaydı
  başlıktaki tek kayıt olmak zorundadır (DOĞRULANDI: https://github.com/C2SP/C2SP/blob/main/age.md,
  erişim 2026-11-16). lephycrypy+ Argon2id (RFC 9106), min 64 MiB, varsayılan 512 MiB.
- **Ad/yapı gizliliği:** age tek bayt akışını şifreler; klasör için `tar | age` gerekir, çıktı adı
  kullanıcıya kalır (DOĞRULANDI: age README, https://github.com/FiloSottile/age). lephycrypy+
  adları ve yapıyı her zaman şifreli arşivde tutar, varsayılan çıktı adı rastgeledir.
- **Boyut gizleme:** age spesifikasyonu dolgu tanımlamaz (DOĞRULANDI, aynı spec). lephycrypy+
  arşivde PADMÉ varsayılan.
- **Akış:** her ikisi 64 KiB chunk'lı STREAM benzeri yapı (age: 11 B BE sayaç + son-chunk bayrağı —
  DOĞRULANDI). lephycrypy+ 64 KiB–16 MiB chunk ve paralel işleme.
- **Parola değişimi:** age/rage CLI'ında yeniden şifrelemeden parola değiştiren komut yok
  (**DOĞRULANMADI**). lephycrypy+ `rekey` sunar, sınırlarıyla (THREAT-MODEL).
- **age'in avantajları:** olgun, yaygın; birden çok bağımsız uygulama ve resmî spesifikasyon;
  asimetrik alıcılar (X25519, post-kuantum hibrit, ssh anahtarları, YubiKey eklentileri).
  lephycrypy+'ta bunlar yok. age/rage için yayımlanmış bağımsız denetim raporu README'lerde
  belirtilmiyor (**DOĞRULANMADI**; "denetlenmiş" iddiası yazılmaz). lephycrypy+ henüz denetlenmedi.
- **Ne zaman age:** başkasına açık anahtarla gönderim veya boru hatlarında yaygın/kararlı biçim
  gerekiyorsa age/rage.

## Parola kaynakları

Parola argv veya ortam değişkeninden **asla** okunmaz. Betik kullanımı için `--password-stdin`
(tüm platformlar), `--password-fd <n>` (yalnızca Unix) ve `--password-file <yol>` vardır.
`--password-file` düz metin parola dosyası diskte kalır; tmpfs/RAM disk ya da isimli pipe tercih
edin. Windows'ta yalnızca yerel (`\\.\pipe\…`) ve aynı kullanıcıya ait pipe'lar kabul edilir.

## Bellek sınırları

Küçük sırlar `mlock`/`VirtualLock` ile kilitlenir; başarısızlık uyarıdır, `--strict-memory` ile
hataya dönüşür. `RLIMIT_MEMLOCK` (Unix) ve working set sınırı (Windows) kilitlemeyi engelleyebilir.
Hibernation, swap/pagefile ve OS arka plan hizmetleri için docs/THREAT-MODEL.md'ye bakın.

## Hata ayıklama

Release ikilileri macOS'ta `PT_DENY_ATTACH` kullanır ve notarize + hardened runtime ile imzalanır;
`--allow-debugger` notarize ikilide debugger bağlanmasını sağlamaz. Hata ayıklama için yerel
imzasız derleme kullanın.

## Lisans

MIT veya Apache-2.0, tercihinize göre. Üçüncü taraf içerik için NOTICE.
