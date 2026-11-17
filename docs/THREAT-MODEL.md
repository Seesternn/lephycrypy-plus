# lephycrypy+ tehdit modeli (taslak)

Hedef, sır kalıntılarını **en iyi çaba ile** en aza indirmektir; mutlak "iz bırakmama" vaat edilmez.
Her "önlem yok" / "kapsam dışı" maddesi bilinçli bir sınırdır. "DOĞRULANMADI" etiketli iddialar
kaynak bulunana kadar varsayımdır.

## Korunanlar
İçerik, adlar/yapı, isteğe bağlı boyut (PADMÉ); başlık/chunk bütünlüğü; kesme/sıra/birleştirme;
anahtar taahhüdü (commit_tag — invisible salamander / partitioning oracle); küçük sırların kilitli
ve sıfırlanan bellekte tutulması (en iyi çaba); yarım çıktı yok (atomik yazma).

## Açık (şifrelenmeyen) meta veri
Sürüm, algoritma, KDF parametreleri, keyfile/padded bayrakları, chunk boyutu, salt/nonce'lar,
commit_tag, toplam şifreli boyut (pad yoksa ±chunk), chunk sayısı; FS zaman damgaları; dosya ve
keyfile **yolları** argv'de (`ps`, Windows Event Log 4688 komut satırı alanı — denetim ilkesine
bağlı, varsayılan DOĞRULANMADI); parola asla argv'de değildir; GUI'de yollar argv'ye gitmez.

## Rekey sınırı
`rekey` FK'yı değiştirmez: eski parola + eski başlık kopyası (256 B) yeni dosyayı açar. Gerçek
rotasyon `reencrypt`.

## Bellek
Panikte Drop'lar çalışmaz (`panic=abort`); panik hook'u (1) arenayı ve kayıtlı büyük bölgeleri
sıfırlar, (2) tmp'leri siler, (3) terminali geri yükler, sonra abort eder (core dump kapalı).
Sır envanterinden (PLAN) kilitlenmeyen/sıfırlanmayanlar:
- Unicode normalleştirme yineleyicisinin iç tamponları; Argon2 H0/Blake2b iç durumu (DOĞRULANMADI).
- AEAD çağrısı başına işçi yığınındaki durumlar (ChaCha20 akış durumu, XChaCha alt anahtarı,
  Poly1305 tek kullanımlık anahtarı, GHASH kopyası, tag maskesi); Poly1305 için zeroize yok;
  bunlar chunk'a özgüdür, `data_key`'i doğrudan açığa çıkarmaz.
- HKDF/HMAC/BLAKE3 taşıma kopyaları ve yazmaç taşmaları; AES `ni`/`armv8` 0.9'da tur anahtarı
  sıfırlaması DOĞRULANMADI.
- Düz metin chunk havuzu (≤ 64 MiB) kilitlenmez; swap/pagefile'a düşebilir (kullanım sonrası
  sıfırlanır).
- Dosya/dizin adları heap'te sıfırlanmaz; ad gizliliği diskteki çıktı içindir.
- Çekirdek sayfa önbelleği, tty satır tamponu, parola dosyası/borusunun çekirdek tamponları
  kapsam dışı.
- GUI (1.2): egui/winit olay kuyruğu ve IME kompozisyonu; OS klavye kaydı kapsam dışı.
- zxcvbn (etkinse) parola kopyalarını sıfırlamaz (varsayım, kod incelemesi).
- Hibernation (kilitli bellek de sleepimage/hiberfil'e yazılabilir); swap (macOS şifreli
  varsayılan, Windows pagefile değil); mlock başarısızlığı (RLIMIT_MEMLOCK, working set) → uyarı;
  MADV_DONTDUMP/PR_SET_DUMPABLE yalnızca Linux (best-effort); macOS/Windows'ta Argon2 belleği için
  döküm hariç tutma yok, yalnızca RLIMIT_CORE=0/WER kapatma; WER dökümleri `LocalDumps` ile süreç
  dışından alınabilir (hook arenayı önceden sıfırlar, diğer kopyalar bulunabilir);
  `PT_DENY_ATTACH`/`PR_SET_DUMPABLE` caydırıcıdır, güvenlik sınırı değildir; notarize + hardened
  runtime ikilide `--allow-debugger` debugger bağlanmasını sağlamaz.
- Yan kanal: AES-GCM yazılım arka ucu bitsliced/sabit zamanlı; aynı makinedeki önbellek/zamanlama
  saldırıları kapsam dışı.

**Panik hook'u çalışmayan durumlar:** OOM (`handle_alloc_error` hook'suz abort), çift panik / hook
içinde panik, stack overflow, SIGKILL/`TerminateProcess`, `unsafe` kaynaklı SIGSEGV/SIGBUS, güç
kesintisi. Bu durumlarda tmp kalabilir (`cleanup`), arena sıfırlanmaz (kilitli olduğundan diske
yazılmaz, hibernation istisnası). Hook yığın/yazmaç/heap kopyalarına erişemez; hook sırasında
diğer iş parçacıkları çalışmaya devam eder (bozuk chunk'lar hedefe ulaşmaz); asılı FS'de tmp silme
bloklanabilir; çıkarma tmp ağacı hook'ta silinmez.

**Sinyaller:** KDF sırasında kesinti KDF bitene kadar gecikir; ikinci sinyal `_exit(130)` tmp
temizliği yapmaz; gecikme ≤ bir chunk G/Ç; Windows konsol kapatma temizliği ~5 s ile sınırlı;
oturum kapatma olayları etkileşimli uygulamalara ulaşmaz; SIGKILL yakalanamaz.

## Dosya sistemi
Çözme tmp'si düz metindir; SSD/APFS kalıntısı. `--delete-original` kalıntı bırakır; güvenli silme
sunulmaz; orijinal APFS/Time Machine snapshot, VSS ve bulut sürüm geçmişinde kalabilir. Windows'ta
dizin fsync yok. Noclobber: FAT/exFAT/ağ FS'de `RENAME_NOREPLACE`/`RENAME_EXCL` desteksiz olabilir
→ `link` geri dönüşü yoksa kontrol-sonra-rename yarış penceresi (uyarı). Windows tmp ACL
kısıtlaması DOĞRULANMADI. `--password-file` düz metin parola dosyası bırakır; tmpfs/RAM disk/pipe
tercih edilmeli. Windows isimli pipe ele geçirme: aynı adla önceden pipe açan saldırgan kendi
parolasını verebilir → yalnızca yerel ve aynı kullanıcı SID'li pipe kabul edilir.

## İşletim sistemi sızıntıları
Araç düz metni yalnızca kendi belleğinde ve geçici dosyalarında tutsa da OS arka plan hizmetleri
geçici veya nihai düz metni, adları ya da varlığı araç kontrolü dışında kopyalayabilir /
indeksleyebilir / ağa gönderebilir. "Geçici tmp" önlemleri yalnızca araç çalışırken ürettiği
dosyaları korur; kullanıcının yazdığı nihai düz metin çıktı, bulunduğu konumun normal OS
davranışına tabidir.

| Kaynak | Ne sızar | Platform | Önlem / durum |
|---|---|---|---|
| Spotlight (`.Spotlight-V100`) | içerik + ad | macOS | tmp dizin/dosya adı `.noindex` ile biter (sonek mekanizması DOĞRULANMADI); nihai çıktı normal indekslenir |
| QuickLook thumbnail önbelleği | içerik (önizleme) + ad | macOS | araç QuickLook kullanmaz; kullanıcı önizlerse önbelleğe düşebilir; 10.14+ DataVault korumalı; konum DOĞRULANMADI |
| APFS snapshot / Time Machine yerel snapshot | içerik + ad (orijinal) | macOS | önlem yok; `--delete-original` sonrası snapshot'ta kalabilir |
| iCloud Drive / OneDrive / Dropbox / Google Drive | içerik (düz metin buluta) + ad | macOS, Windows | bulut kökü tespiti → onay + `--allow-cloud-dir`; liste sezgisel, eksik olabilir |
| Windows Search indeksi | içerik + ad | Windows | tmp `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` (DOĞRULANDI); nihai çıktı dizin ayarına göre |
| VSS gölge kopyaları | içerik + ad (orijinal) | Windows | önlem yok; belgelenir |
| Microsoft Defender otomatik örnek gönderimi | içerik (dosya buluta) + ad | Windows | önlem yok; bulut analizi karara varamazsa dosya Microsoft'a gönderilebilir (DOĞRULANDI: https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission); `SubmitSamplesConsent` kullanıcı ayarı |
| Recent items / jump list / Finder Son Kullanılanlar | ad + varlık | macOS, Windows | önlem yok (shell/OS kaydeder) |
| Dosya yolları argv'de | ad + varlık | macOS (`ps`), Windows (Event Log 4688) | parola asla argv'de; yollar görünür; GUI'de argv yok |

## USB (1.1)
FAT/exFAT silinmiş dizin girişleri, NTFS resident dosyalar, sistem klasörleri, wear-leveling →
fiziksel garanti yok; `--format` denetleyici düzeyinde garanti vermez; geri okuma unmount
yapılamadıysa "önbellekten doğrulandı"; is_removable tutarsız; harici USB SSD/HDD ("Fixed")
desteklenmez; kimlik yeniden doğrulaması ile çağrı arasında TOCTOU penceresi kalır;
sistem/boot/Time Machine dışlanır.
- macOS `diskutil` seri numarası vermez: seri zorunluluğu (açık karar 16) yalnızca Windows'ta.
  macOS fiziksel kimliği `MediaName|DiskUUID|ParentWholeDisk` + boyut + `st_dev`'dir.
- Windows'ta yeniden bağlama (`FSCTL_DISMOUNT_VOLUME`) uygulanmadı: geri okuma her zaman
  "önbellekten doğrulandı" etiketi alır.
- `diskutil` anahtar adları dahili disk çıktısından doğrulandı; bir USB bellekte aldıkları değerler,
  Windows `STORAGE_DEVICE_DESCRIPTOR` alanlarının USB bellekteki değerleri, `diskutil eraseVolume`
  ve `Format-Volume -Path` uçtan uca davranışı **gerçek donanımla doğrulanmadı**.
- PowerShell `Format-Volume` değerleri komut dizgisine gömülmez, alt sürecin ortamından okunur;
  `powershell.exe` imzası (`WinVerifyTrust`) denetlenmez.
- Boş alan doldurma ChaCha20 anahtar akışıdır (dosya başına ayrı nonce, ≤ 64 GiB/dosya).

## GUI (1.2)
- egui/winit olay kuyruğu (`Event::Text`) ve IME kompozisyonu parola metninin heap kopyalarını
  üretir; sıfırlayan global ayırıcı bunları serbest bırakılırken siler, ama serbest bırakılana
  kadar ve yığın/yazmaç kopyaları için garanti yoktur. OS klavye kaydı/erişilebilirlik
  araçları kapsam dışıdır.
- Pano kapalıdır (`clipboard` feature yok; parola alanı kopyala/kes/yapıştır olaylarını yutar).
- Kalıcı ayar (`persistence`) yoktur; pencere konumu ve geçmiş yollar diske yazılmaz.
- GUI işlemleri `--strict`, symlink kurma ve `--rename-conflicts` sunmaz (varsayılan güvenli
  politika); bunlar için CLI kullanılır.
- Tedarik zinciri: egui/eframe zinciri ~400 crate ekler (cargo-vet istisnalarının çoğu);
  çekirdek bu zincirden ayrı, sıkı kademede denetlenir (deny.toml `--exclude lephy-gui`).

## Arşiv
Harf katlama erken uyarısı `char::to_lowercase` ile yapılır (CaseFolding.txt C+S ile tam eşdeğerlik
DOĞRULANMADI); otorite dosya sistemidir. Yazıcı çerçeve verisini ≤ 1 MiB'lık sıfırlanan ara
tampondan geçirir (plandaki "ayrı çerçeve tamponu yok" ifadesinden küçük sapma). mtime/izin
uygulaması best-effort'tur (başarısızlık sessizdir). Windows'ta tmp dizin ACL kısıtlaması yoktur.
xattr, ACL, resource fork, sahiplik, sert bağlar (kopya), FIFO/soket/aygıt desteklenmez;
`--stdout` kısmi çıktı; harf katlama erken uyarı, otorite FS. Symlink'ler varsayılan kurulmaz;
`--restore-symlinks` yalnızca göreli/`..`'siz hedefler; `--restore-symlinks=unsafe` ile kurulan
bağlar çıkarmadan sonra başka programlar için kök dışını gösterebilir (uyarı); Windows'ta
ayrıcalık/Developer Mode yoksa kurulamaz, ağaç eksik kalır.

## Diğer
Zayıf parola; keyfile yalnızca ek faktör. Linux best-effort: test edilmez, Linux'a özgü korumalar
(MADV_DONTDUMP, PR_SET_DUMPABLE, renameat2) doğrulanmamış sayılır. **Henüz bağımsız kriptografik
denetim yapılmamıştır.**
