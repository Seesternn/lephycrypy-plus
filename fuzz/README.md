# fuzz/

cargo-fuzz hedefleri (Linux runner, aşama 3; PLAN I8/R5-14): `header`, `archive_entry`, `names`,
`decrypt_known_key` (bilinen parola + `test-vectors` sabit KDF ile tam çözme hattı).
CI smoke: 60 sn/hedef. Bulunan girdiler `tests/regress/` altına eklenir.
