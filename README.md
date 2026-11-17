# lephycrypy+

Açık kaynaklı, Rust ile yazılmış dosya/klasör şifreleme aracı. Hedef: parolayla klasör/arşiv
saklama; adlar ve yapı her zaman şifreli; akışlı işleme; atomik yazma; bellekte sır kalıntılarını
**en iyi çaba ile** en aza indirme.

> **Durum: 1.0 öncesi; 1.1 (USB) ve 1.2 (GUI) kodu da hazır.** Dosya ve klasörler adları/yapısı
> gizli bir arşiv olarak şifrelenir (varsayılan PADMÉ); stdin ve `--raw` ham akıştır. `usb`
> komutları yalnızca çıkarılabilir USB belleği temizleyip şifreli dosyayı yazar; `lephycrypy-gui`
> sürükle-bırak arayüzüdür (macOS/Windows). 1.0 için kalanlar: kripto crate'lerinin yerel
> cargo-vet denetimi, imzalama/notarization (açık karar 17–19), CI'ın gerçek runner'larda ilk
> koşusu ve bağımsız inceleme. USB yolu gerçek bir USB bellekle hiç denenmedi. Yol haritası ve tüm tasarım kararları [docs/PLAN.md](docs/PLAN.md)'de;
> biçim [docs/FORMAT.md](docs/FORMAT.md)'de; sınırlar [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)'de.
> **Bağımsız denetim yapılmamıştır; üretim verisi için kullanmayın.**

## Platformlar (R5-08)

| Platform | Durum |
|---|---|
| macOS (aarch64, x86_64) | desteklenir; CI'da tam test; imzalı/notarize ikili (1.0) |
| Windows (x86_64) | desteklenir; CI'da tam test; Authenticode açık karar (PLAN › 18) |
| Linux | derlenir, **best-effort**: test edilmez, ikili yayımlanmaz; CI'da yalnızca check/clippy/Miri/fuzz/kanarya; `usb` ve GUI desteklenmez |

MSRV: Rust 1.95.0 (`rust-toolchain.toml` ile sabit).

## Crate'ler

| Crate | Rol | unsafe |
|---|---|---|
| `lephy-sys` | tek FFI/unsafe crate: bellek kilitleme, süreç sertleştirme, dosya sistemi, birim, terminal, sinyal | evet, her blokta `// SAFETY:` |
| `lephy-core` | kriptografi, biçim, arşiv, pipeline | `#![forbid(unsafe_code)]` |
| `lephy-cli` | `lephycrypy` komut satırı | `#![forbid(unsafe_code)]` |
| `lephy-usb` (1.1) | yalnızca çıkarılabilir USB: uygunluk, onay, kimlik yeniden denetimi, silme/biçimlendirme, doldurma, yazma, geri okuma | `#![forbid(unsafe_code)]` |
| `lephy-gui` (1.2) | `lephycrypy-gui`: egui/eframe tek pencere (macOS/Windows) | `#![forbid(unsafe_code)]`; sıfırlayan global ayırıcı |

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

## Doğrulama durumu

| Ne | Nasıl | Durum |
|---|---|---|
| Argon2id, HKDF, XChaCha20-Poly1305, AES-256-GCM, BLAKE3 | resmî KAT'lar (`tests/kat/`, `cargo test -p lephy-core --test kat`) | geçiyor |
| Biçim vektörleri 1–11 (arşiv + PADMÉ dahil) | yalnızca FORMAT.md'den yazılmış Python referansı (`tests/ref/lephy_ref.py`) ile bayt bayt (`--features test-vectors`) | geçiyor |
| Kanonik son chunk, kesme, fazla bayt, `last` ortada | `pipeline` birim testleri | geçiyor |
| zip-slip (`..`, mutlak, `\`, sürücü), symlink-dizin-sonra-dosya, yinelenen ad (NFC/harf), setuid temizleme, 17 MiB çerçeve, derinlik 257, END eksik/sonrası veri, PADMÉ kuyruğu, FIFO atlama/`--strict` | `archive` birim testleri | geçiyor |
| Windows ad kuralları (CON, COM¹, ADS, sondaki nokta) | `names` birim testleri (saf fonksiyon; Windows CI'da uçtan uca) | geçiyor |
| Yanlış parola/keyfile (3), bozuk başlık/chunk (4), hedef var (7), bütçe (6) | `ops` testleri + CLI çıkış kodları | geçiyor |
| rekey (FK/chunk sabit, R4-Y2) ve reencrypt | `ops` testi | geçiyor |
| Kilitli arena, sayfa refcount, hook sıfırlaması | `lephy-sys` testleri (macOS) | geçiyor |
| Özellik testleri: STREAM sınırları, bit çevirme/kesme/ek bayt, PADMÉ, arşiv round-trip, bozulmuş arşivin kök dışına yazmaması | proptest (`tests/prop.rs`; yerelde 1500 vaka/test) | geçiyor |
| Fuzz: `header`, `archive_entry`, `names`, `decrypt_known_key` | cargo-fuzz (`fuzz/`), yerelde 60 sn/hedef + 2 hedef 5 dk | geçiyor; 1 gerçek hata bulundu ve düzeltildi (PADMÉ uzunluk öneki taşması) |
| Fuzz regresyonları + seed'ler her `cargo test`te | `tests/regress.rs` | geçiyor |
| Miri (arena, refcount, hizalama, zeroize-sonra-dealloc) | `cargo +nightly-2026-11-01 miri test -p lephy-sys` | geçiyor (FFI testleri hariç) |
| SIGINT parola isteminde (yankı geri, 130), akış ortasında SIGINT/SIGTERM (tmp yok, 130), KDF'de çift SIGINT | `crates/lephy-cli/tests/signals.rs` (Unix, pty için python3) | geçiyor; gecikme < 40 ms |
| Panik hook'u: arena + bölge sıfır, tmp silinir, SIGABRT, terminal açık | `tests/fault/panic_hook.sh` (`fault-injection` + release) | geçiyor |
| Kanarya taraması (`/proc/self/mem`) | `tests/canary.rs` (yalnızca Linux CI) | yazıldı; yerelde çalıştırılamadı |
| cargo-deny (advisory, bans, lisans, kaynak), cargo-audit | `deny.toml` | geçiyor; yasakların tetiklendiği denendi |
| cargo-vet | `supply-chain/` | geçiyor; 15 tam, 7 kısmi denetim, **90 istisna (kripto crate'leri dahil)** |
| Tekrarlanabilir derleme (imzasız) | iki ayrı dizinde release derleme | macOS arm64'te SHA256 eşit; çapraz runner CI'da |
| Windows kodu | yalnızca çapraz `cargo clippy --target x86_64-pc-windows-msvc`; CI'da çalıştırılacak | derleniyor, test edilmedi; `CTRL_BREAK` testi yazılmadı |
| USB: uygunluk (SATA/Thunderbolt/Fixed/boş seri reddi), yanlış etiket/GiB → 5 ve hiçbir şey silinmez, adımlar arası kimlik değişimi → 5 ve sonraki adım çalışmaz, symlink takip etmeyen silme, sistem klasörleri, çok dosyalı doldurma, iki geri okuma etiketi | `lephy-usb` birim testleri (sahte platform + geçici dizin) | geçiyor |
| USB: gerçek `diskutil` çıktısının ayrıştırılması; dahili diske `usb write` reddi | macOS'ta salt okunur gerçek çağrılar | geçiyor |
| USB: gerçek USB bellekte silme/biçimlendirme/yazma | — | **denenmedi** (donanım yok; gerçek diske hiçbir silme çalıştırılmadı) |
| GUI: parola alanı (yazma, backspace, pano reddi, kapasite), başsız (headless) çizim, şifrele/çöz/yanlış parola | `lephy-gui` testleri | geçiyor |
| GUI: pencere açılır; SIGTERM/SIGINT ile kapanır (130) | release ikilisi macOS'ta çalıştırıldı | geçiyor; ekran görüntüsü/erişilebilirlik denetimi yapılmadı |

Python referansı için: `python3 -m venv .venv && .venv/bin/pip install cryptography argon2-cffi blake3`,
sonra `.venv/bin/python -I tests/ref/lephy_ref.py vectors tests/kat/vectors`.

## USB (1.1)

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

## GUI (1.2)

`lephycrypy-gui` argümansız başlar (yollar argv'ye gitmez). Bir dosya ya da klasörü pencereye
bırakın: `.lphy` dosyaları çözülür, diğerleri şifrelenir. Parola alanı maskelidir, panoya
kopyalama/yapıştırma kapalıdır, metin doğrudan kilitli bellekte tutulur. "Gelişmiş" bölümünde
Argon2id belleği, algoritma ve PADMÉ seçilir. Bulut senkron klasörüne çıkarma onay ister.
Sistem yazı tipi kullanılır; gömülü yazı tipi yoktur. Linux'ta GUI yoktur.

## Derleme

```bash
cargo build --locked
```

```bash
cargo test --locked --workspace
```

`test-vectors` feature'ı yalnızca `lephy-core` testleri içindir; `lephy-cli` bu feature ile
derlenmeyi derleme zamanında reddeder (R5-02).

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

## Parola kaynakları (D3)

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
