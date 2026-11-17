//! `lephycrypy-gui` — masaüstü arayüzü (1.2). `#![forbid(unsafe_code)]`.
//!
//! Süreç başı CLI ile aynıdır: sertleştirme → panik hook'u → sinyal işleyici. Ek olarak sıfırlayan
//! global ayırıcı açıktır. Yollar argv'ye gitmez: uygulama argümansız başlar.

#![forbid(unsafe_code)]
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

const _: () = assert!(
    !lephy_core::TEST_VECTORS_ENABLED,
    "lephy-gui, lephy-core/test-vectors feature'ı ile derlenemez"
);

#[cfg(any(target_os = "macos", windows))]
mod app;
#[cfg(any(target_os = "macos", windows))]
mod fonts;
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
mod i18n;
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
mod logic;
#[cfg(any(target_os = "macos", windows))]
mod secret_field;
#[cfg(any(target_os = "macos", windows))]
mod theme;

use std::process::ExitCode;

#[cfg(any(target_os = "macos", windows))]
use eframe::egui;

#[global_allocator]
static ALLOC: lephy_sys::alloc::ZeroizingAlloc = lephy_sys::alloc::ZeroizingAlloc;

#[cfg(not(any(target_os = "macos", windows)))]
fn main() -> ExitCode {
    eprintln!(
        "hata: lephycrypy-gui yalnızca macOS ve Windows'ta desteklenir; komut satırı için `lephycrypy`"
    );
    ExitCode::from(1)
}

#[cfg(any(target_os = "macos", windows))]
fn main() -> ExitCode {
    if let Err(e) = lephy_sys::platform::harden() {
        eprintln!("uyarı: süreç sertleştirme kısmen başarısız: {e}");
    }
    lephy_sys::platform::install_panic_hook();
    if let Err(e) = lephy_sys::signal::install() {
        eprintln!("uyarı: sinyal işleyici kurulamadı: {e}");
    }
    if cfg!(all(target_os = "macos", not(debug_assertions))) {
        let _ = lephy_sys::platform::deny_debugger();
    }
    let Some(font) = fonts::find_system_fonts() else {
        eprintln!("hata: Türkçe karakterleri kapsayan bir sistem yazı tipi bulunamadı");
        return ExitCode::from(1);
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("lephycrypy+")
            .with_inner_size([520.0, 640.0])
            .with_min_inner_size([420.0, 540.0])
            .with_drag_and_drop(true)
            .with_icon(egui::IconData {
                rgba: include_bytes!("../assets/icon-128.rgba").to_vec(),
                width: 128,
                height: 128,
            }),
        persist_window: false,
        centered: true,
        ..Default::default()
    };
    let r = eframe::run_native(
        "lephycrypy+",
        options,
        Box::new(move |cc| {
            fonts::install(&cc.egui_ctx, font);
            theme::apply(&cc.egui_ctx);
            i18n::set_lang(i18n::detect());
            Ok(app::boxed())
        }),
    );
    // Son güvence: hâlâ kayıtlı yarım tmp dosyası varsa sil.
    let _ = lephy_sys::fs::tmp_unlink_all_in_hook();
    lephy_sys::signal::mark_cleanup_done();
    match r {
        Ok(()) if lephy_sys::signal::signalled() => ExitCode::from(130),
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hata: pencere açılamadı: {e}");
            ExitCode::from(1)
        }
    }
}
