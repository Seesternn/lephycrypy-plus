//! Dosya sistemi FFI (PLAN F1, F2, F5, R4-O6, R4-O7, R5-05, R5-11).
//!
//! Aşama 1–2'de gelecek safe API:
//! - `rename_noclobber(tmp, dst) -> Result<(), NoclobberError>`: macOS `renamex_np(RENAME_EXCL)`,
//!   Windows `MoveFileExW` (`REPLACE_EXISTING` yok, `MOVEFILE_WRITE_THROUGH`), Linux (best-effort)
//!   `renameat2(RENAME_NOREPLACE)`; `ENOTSUP`/`EINVAL` → `Unsupported` (çağıran link+unlink /
//!   lstat+rename geri dönüşünü uygular ve uyarır).
//! - `rename_replace(tmp, dst)`: `--force` yolu; Windows'ta `ACCESS_DENIED`/`SHARING_VIOLATION`'da
//!   10 ms'den başlayan üstel geri çekilme, ≤ 2 s.
//! - `fsync_dir(path)`: Unix dizin fd + Apple `F_FULLFSYNC`; Windows'ta no-op.
//! - `supports_rename_excl(path)`: macOS `getattrlist` `VOL_CAP_INT_RENAME_EXCL`.
//! - `mark_not_content_indexed(path)` (Windows `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`, 0x2000).
//! - `open_tmp_share_delete(path)` (Windows `FILE_SHARE_DELETE`), `set_delete_on_close(handle)`
//!   (`FileDispositionInfo`, DOĞRULANMADI).
//! - `fs_kind(path)`, `free_space(path)`: FAT32 4 GiB ve kod 8 ön kontrolleri.
//! - `cloud_sync_roots() -> Vec<PathBuf>`: bilinen bulut kökleri (tek yer, sezgisel).
//! - `create_symlink(dir_handle, name, target, is_dir)`: Windows `CreateSymbolicLinkW` önce
//!   `SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE` ile; ayrıcalık yoksa `Err(NoPrivilege)`.
