//! lephycrypy+ USB (1.1): yalnızca **çıkarılabilir USB ortamını** temizle ve yalnızca şifreli
//! `.lphy` dosyasını yaz. `#![forbid(unsafe_code)]`; tüm FFI `lephy-sys`.
//!
//! Kurallar (hiçbiri bayrakla aşılamaz): USB veriyolu **ve** çıkarılabilir ortam; dahili/sanal/
//! sistem birimleri reddedilir; Windows'ta seri numarası zorunlu; onay etiket
//! **ve** GiB boyut; her adımdan önce aygıt kimliği yeniden okunur (fark → kod 5).
//!
//! Gerçek donanımla doğrulanmadı: `diskutil` plist anahtarlarının bir USB bellekteki değerleri,
//! Windows `STORAGE_DEVICE_DESCRIPTOR` alanlarının USB bellekteki değerleri, `diskutil eraseVolume`
//! ve `Format-Volume -Path` uçtan uca davranışı (THREAT-MODEL › USB).

#![forbid(unsafe_code)]

pub mod device;
pub mod engine;
pub mod platform;
pub mod plist_lite;

pub use device::{Bus, Device, Identity};
pub use engine::{Confirm, DryRun, FillOptions, Verification, WriteReport, WriteRequest};
pub use platform::{Platform, native};
