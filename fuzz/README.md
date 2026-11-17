# fuzz/

cargo-fuzz hedefleri (PLAN I8, R5-14). Ayrı workspace'tir; nightly ve `cargo install cargo-fuzz`
gerektirir. CI'da Linux runner'da hedef başına 60 sn smoke; yerelde:

```bash
cargo +nightly-2026-11-01 fuzz run decrypt_known_key fuzz/seeds/decrypt_known_key -- -max_total_time=60
```

| Hedef | Ne | Değişmez |
|---|---|---|
| `header` | 256 B başlık ayrıştırıcısı | panik yok; kabul edilen başlık kanonik (gidiş-dönüş aynı bayt) |
| `archive_entry` | arşiv çıkarıcı, keyfi düz metin akışı, parçalı yazım | panik yok; kök dışına yazım yok |
| `names` | yol doğrulama, symlink sınıflandırma, kaçışlama, Windows adları | doğrulanmış yolda `..` yok; `..` hedefi güvensiz; kaçışlı çıktıda ESC/bidi yok |
| `decrypt_known_key` | bilinen anahtarla STREAM + arşiv / PADMÉ çözme hattı; ham ciphertext framing | panik yok; yalnızca `Corrupt`/G/Ç hataları; kök dışına yazım yok |

`seeds/<hedef>/` başlangıç girdileridir (commit edilir). Fuzzer'ın bulduğu çökme girdileri
`tests/regress/` altına eklenir ve `crates/lephy-core/tests/regress.rs` ile kalıcı teste dönüşür.
