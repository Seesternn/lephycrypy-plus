//! `lephycrypy-gui` — the desktop app. `#![forbid(unsafe_code)]`.
//!
//! Process start is the same as the CLI: hardening → panic hook → signal handler. In addition the
//! zeroizing global allocator is enabled.
//!
//! Files to open arrive from the operating system: on macOS as an open-documents event
//! (double-click, "Open With", Dock), on Windows as `--open <absolute path>` from the Explorer
//! integration. No other argument is accepted.

#![forbid(unsafe_code)]
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

const _: () = assert!(
    !lephy_core::TEST_VECTORS_ENABLED,
    "lephy-gui cannot be built with the lephy-core/test-vectors feature"
);

#[cfg(any(target_os = "macos", windows))]
mod app;
#[cfg(any(target_os = "macos", windows))]
mod folder_watch;
#[cfg(any(target_os = "macos", windows))]
mod fonts;
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
mod i18n;
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
mod logic;
#[cfg(any(target_os = "macos", windows))]
mod motion;
#[cfg(any(target_os = "macos", windows))]
mod preview;
#[cfg(any(target_os = "macos", windows))]
mod preview_decode;
#[cfg(any(target_os = "macos", windows))]
mod qr;
#[cfg(any(target_os = "macos", windows))]
mod secret_field;
#[cfg(any(target_os = "macos", windows))]
mod settings;
#[cfg(any(target_os = "macos", windows))]
mod theme;
#[cfg(any(target_os = "macos", windows))]
mod vault;

use std::process::ExitCode;

#[cfg(any(target_os = "macos", windows))]
use eframe::egui;

#[global_allocator]
static ALLOC: lephy_sys::alloc::ZeroizingAlloc = lephy_sys::alloc::ZeroizingAlloc;

#[cfg(not(any(target_os = "macos", windows)))]
fn main() -> ExitCode {
    eprintln!(
        "error: lephycrypy-gui is supported only on macOS and Windows; use `lephycrypy` on the command line"
    );
    ExitCode::from(1)
}

#[cfg(any(target_os = "macos", windows))]
fn main() -> ExitCode {
    if let Err(e) = lephy_sys::platform::harden() {
        eprintln!("warning: process hardening partly failed: {e}");
    }
    lephy_sys::platform::install_panic_hook();
    if let Err(e) = lephy_sys::signal::install() {
        eprintln!("warning: the signal handler could not be installed: {e}");
    }
    if cfg!(all(target_os = "macos", not(debug_assertions))) {
        let _ = lephy_sys::platform::deny_debugger();
    }
    let Some(font) = fonts::find_system_fonts() else {
        eprintln!("error: no system font covering Turkish characters was found");
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
    let r = run(options, font);
    // Last resort: delete any half-written temp file that is still registered.
    let _ = lephy_sys::fs::tmp_unlink_all_in_hook();
    lephy_sys::signal::mark_cleanup_done();
    match r {
        Ok(()) if lephy_sys::signal::signalled() => ExitCode::from(130),
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: the window could not be opened: {e}");
            ExitCode::from(1)
        }
    }
}

/// `--open <absolute path>` pairs (Explorer integration). Anything else is ignored.
#[cfg(any(target_os = "macos", windows))]
fn open_args() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        if a == "--open"
            && let Some(p) = args.next()
        {
            let p = std::path::PathBuf::from(p);
            if p.is_absolute() {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(any(target_os = "macos", windows))]
fn run(options: eframe::NativeOptions, font: fonts::SystemFonts) -> Result<(), String> {
    use winit::platform::run_on_demand::EventLoopExtRunOnDemand;
    let mut event_loop = winit::event_loop::EventLoop::<eframe::UserEvent>::with_user_event()
        .build()
        .map_err(|e| e.to_string())?;
    // The delegate class exists now; files given at launch arrive once the loop runs.
    if cfg!(target_os = "macos")
        && !lephy_sys::open_docs::install_macos_handler("WinitApplicationDelegate")
    {
        eprintln!("warning: opening files from Finder could not be set up");
    }
    // Quitting while a job runs asks first (the close button only hides the app).
    if cfg!(target_os = "macos")
        && !lephy_sys::lifecycle::install_macos_quit_guard("WinitApplicationDelegate")
    {
        eprintln!("warning: quitting during a job could not be guarded");
    }
    lephy_sys::open_docs::push(open_args());
    let mut app = eframe::create_native(
        "lephycrypy+",
        options,
        Box::new(move |cc| {
            fonts::install(&cc.egui_ctx, font);
            theme::apply(&cc.egui_ctx);
            i18n::set_lang(i18n::detect());
            let ctx = cc.egui_ctx.clone();
            lephy_sys::open_docs::set_waker(move || ctx.request_repaint());
            Ok(app::boxed())
        }),
        &event_loop,
    );
    event_loop
        .run_app_on_demand(&mut app)
        .map_err(|e| e.to_string())
}
