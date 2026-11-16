# lephycrypy+

Açık kaynaklı, Rust ile yazılmış dosya/klasör şifreleme aracı. Hedef: parolayla klasör/arşiv
saklama; adlar ve yapı her zaman şifreli; akışlı işleme; atomik yazma; bellekte sır kalıntılarını
**en iyi çaba ile** en aza indirme.

> **Durum: aşama 1 (çekirdek + CLI, tek dosya).** `encrypt`/`decrypt`/`verify`/`info`/`rekey`/
> `reencrypt`/`cleanup` tek dosya ve stdin için çalışır (`content_type = 0`, dolgusuz). Klasör
> arşivi ve PADMÉ aşama 2'de. Yol haritası ve tüm tasarım kararları [docs/PLAN.md](docs/PLAN.md)'de;
> biçim [docs/FORMAT.md](docs/FORMAT.md)'de; sınırlar [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)'de.
> **Bağımsız denetim yapılmamıştır; üretim verisi için kullanmayın.**

## Platformlar (R5-08)

| Platform | Durum |
|---|---|
| macOS (aarch64, x86_64) | desteklenir; CI'da tam test; imzalı/notarize ikili (1.0) |
| Windows (x86_64) | desteklenir; CI'da tam test; Authenticode açık karar (PLAN › 18) |
| Linux | derlenir, **best-effort**: test edilmez, ikili yayımlanmaz; CI'da yalnızca check/clippy/Miri/fuzz/kanarya |

MSRV: Rust 1.95.0 (`rust-toolchain.toml` ile sabit).

## Crate'ler

| Crate | Rol | unsafe |
|---|---|---|
| `lephy-sys` | tek FFI/unsafe crate: bellek kilitleme, süreç sertleştirme, dosya sistemi, birim, terminal, sinyal | evet, her blokta `// SAFETY:` |
| `lephy-core` | kriptografi, biçim, arşiv, pipeline | `#![forbid(unsafe_code)]` |
| `lephy-cli` | `lephycrypy` komut satırı | `#![forbid(unsafe_code)]` |
| `lephy-usb` (1.1), `lephy-gui` (1.2) | ertelendi | — |

## Kullanım (aşama 1)

```bash
lephycrypy encrypt belge.pdf -o a1b2c3d4.lphy
```

```bash
lephycrypy decrypt a1b2c3d4.lphy -o belge.pdf
```

Varsayılanlar: XChaCha20-Poly1305, 1 MiB chunk, Argon2id 512 MiB / 3 / 4. `--alg aes256gcm`,
`--chunk-size 64k|256k|1m|4m|16m`, `--kdf-memory/--kdf-time/--kdf-parallelism`, `--keyfile`,
`--force`, `--strict-memory`, `--delete-original`, `--stdout`, `--allow-large-kdf`.
Betikler için `--password-stdin`, `--password-fd` (Unix) ve `--password-file`; parola **asla**
argv/env'den alınmaz. `rekey` parolayı değiştirir ama dosya anahtarını korur; gerçek rotasyon
`reencrypt`.

## Doğrulama durumu

| Ne | Nasıl | Durum |
|---|---|---|
| Argon2id, HKDF, XChaCha20-Poly1305, AES-256-GCM, BLAKE3 | resmî KAT'lar (`tests/kat/`, `cargo test -p lephy-core --test kat`) | geçiyor |
| Biçim vektörleri 1–4, 7, 9, 10, 11 | yalnızca FORMAT.md'den yazılmış Python referansı (`tests/ref/lephy_ref.py`) ile bayt bayt (`--features test-vectors`) | geçiyor |
| Kanonik son chunk, kesme, fazla bayt, `last` ortada | `pipeline` birim testleri | geçiyor |
| Yanlış parola/keyfile (3), bozuk başlık/chunk (4), hedef var (7), bütçe (6) | `ops` testleri + CLI çıkış kodları | geçiyor |
| rekey (FK/chunk sabit, R4-Y2) ve reencrypt | `ops` testi | geçiyor |
| Kilitli arena, sayfa refcount, hook sıfırlaması | `lephy-sys` testleri (macOS) | geçiyor |
| Windows kodu | yalnızca çapraz `cargo clippy --target x86_64-pc-windows-msvc`; CI'da çalıştırılacak | derleniyor, test edilmedi |
| pty sinyal testleri, kanarya taraması, Miri, fuzz | aşama 3 | yok |

Python referansı için: `python3 -m venv .venv && .venv/bin/pip install cryptography argon2-cffi blake3`,
sonra `.venv/bin/python -I tests/ref/lephy_ref.py vectors tests/kat/vectors`.

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
