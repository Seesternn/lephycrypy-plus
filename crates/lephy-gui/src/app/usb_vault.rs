//! USB sticks and vaults: a stick holding a vault is noticed when it is plugged in (a bar offers
//! to open it; nothing opens by itself), a vault whose stick is pulled out says so, and the vault
//! page can turn any stick into a vault, keeping its files or wiping it first.

use super::buttons::{self as b, Icon, Kind};
use super::{App, Palette, logic};
use crate::i18n::{Lang, lang, tr};
use eframe::egui::{self, RichText, Ui};
use lephy_core::names::escape_display;
use lephy_usb::{Device, DryRun};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

/// How often the stick watch looks.
const EVERY: Duration = Duration::from_secs(3);
/// Most vault files offered per stick.
const MAX_VAULTS: usize = 8;

/// A stick seen by the watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Stick {
    pub(super) label: String,
    pub(super) mount: PathBuf,
    /// Vault files at its root.
    pub(super) vaults: Vec<PathBuf>,
}

/// What the watch reports.
pub(super) enum StickEvent {
    /// Plugged in (or present at start).
    In(Stick),
    /// Pulled out.
    Out(PathBuf),
}

/// Stick state of the app.
#[derive(Default)]
pub(super) struct Sticks {
    rx: Option<Receiver<StickEvent>>,
    /// Sticks with vaults, offered in the bar.
    pub(super) offers: Vec<Stick>,
}

/// Vault files at the root of `mount`.
pub(super) fn vaults_on(mount: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(mount) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("lphy"))
                && p.symlink_metadata().is_ok_and(|m| m.is_file())
                && !p
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
                && crate::vault::unsuitable(p).is_none()
        })
        .collect();
    out.sort();
    out.truncate(MAX_VAULTS);
    out
}

/// Something cheap that changes when a volume comes or goes.
fn volume_marker() -> Vec<PathBuf> {
    if cfg!(windows) {
        (b'D'..=b'Z')
            .map(|c| PathBuf::from(format!("{}:\\", c as char)))
            .filter(|p| p.exists())
            .collect()
    } else {
        let mut v: Vec<PathBuf> = std::fs::read_dir("/Volumes")
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }
}

/// Eligible USB sticks now, by mount point.
fn eligible_sticks() -> BTreeMap<PathBuf, String> {
    let p = lephy_usb::native();
    p.list()
        .map(|v| {
            v.into_iter()
                .filter(|d| d.eligibility(p.require_serial()).is_ok())
                .map(|d| (d.mount, d.label))
                .collect()
        })
        .unwrap_or_default()
}

/// Compares two looks: sticks that came and went.
pub(super) fn diff(
    before: &BTreeMap<PathBuf, String>,
    now: &BTreeMap<PathBuf, String>,
) -> (Vec<(PathBuf, String)>, Vec<PathBuf>) {
    let came = now
        .iter()
        .filter(|(m, _)| !before.contains_key(*m))
        .map(|(m, l)| (m.clone(), l.clone()))
        .collect();
    let went = before
        .keys()
        .filter(|m| !now.contains_key(*m))
        .cloned()
        .collect();
    (came, went)
}

#[allow(clippy::needless_pass_by_value, reason = "the thread owns its handles")]
fn watch_loop(tx: std::sync::mpsc::Sender<StickEvent>, ctx: egui::Context) {
    let mut marker = None;
    let mut known: BTreeMap<PathBuf, String> = BTreeMap::new();
    loop {
        let m = volume_marker();
        if marker.as_ref() != Some(&m) {
            marker = Some(m);
            let now = eligible_sticks();
            let (came, went) = diff(&known, &now);
            for mount in went {
                if tx.send(StickEvent::Out(mount)).is_err() {
                    return;
                }
            }
            for (mount, label) in came {
                let vaults = vaults_on(&mount);
                let ev = StickEvent::In(Stick {
                    label,
                    mount,
                    vaults,
                });
                if tx.send(ev).is_err() {
                    return;
                }
            }
            known = now;
            ctx.request_repaint();
        }
        std::thread::sleep(EVERY);
    }
}

impl Sticks {
    /// Starts the background watch (once).
    pub(super) fn start(&mut self, ctx: &egui::Context) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        let _ = std::thread::Builder::new()
            .name("lephy-sticks".into())
            .spawn(move || watch_loop(tx, ctx));
        self.rx = Some(rx);
    }
}

/// The "turn a USB stick into a vault" form on the vault page.
#[derive(Default)]
pub(super) struct MakeUsb {
    found: Option<Result<Vec<Device>, String>>,
    list_rx: Option<Receiver<Result<Vec<Device>, String>>>,
    pick: Option<Device>,
    /// Wipe the stick first (else keep its files).
    wipe: Option<bool>,
    name: String,
    prepared: Option<Result<(Device, DryRun), String>>,
    prep_rx: Option<Receiver<Result<(Device, DryRun), String>>>,
    label: String,
    gib: String,
    wipe_rx: Option<Receiver<Result<u64, String>>>,
    err: Option<String>,
}

/// What the form hands back when it is done.
pub(super) enum MakeDone {
    /// Create a vault at this path.
    Create(PathBuf),
    /// Back to the choices.
    Back,
}

impl MakeUsb {
    fn scan(&mut self, ctx: &egui::Context) {
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let p = lephy_usb::native();
            let r = p
                .list()
                .map(|v| {
                    v.into_iter()
                        .filter(|d| d.eligibility(p.require_serial()).is_ok())
                        .collect()
                })
                .map_err(|e| logic::describe_error(&e));
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.list_rx = Some(rx);
        self.found = None;
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.list_rx
            && let Ok(r) = rx.try_recv()
        {
            self.found = Some(r);
            self.list_rx = None;
        }
        if let Some(rx) = &self.prep_rx
            && let Ok(r) = rx.try_recv()
        {
            self.prepared = Some(r);
            self.prep_rx = None;
        }
    }

    fn target(&self) -> Option<PathBuf> {
        let dev = self.pick.as_ref()?;
        let name = self.name.trim();
        if name.is_empty() || name.contains(['/', '\\', ':']) || name.starts_with('.') {
            return None;
        }
        let n = if Path::new(name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("lphy"))
        {
            name.to_owned()
        } else {
            format!("{name}.lphy")
        };
        Some(dev.mount.join(n))
    }

    /// The form. Returns what to do next, if decided.
    #[allow(
        clippy::too_many_lines,
        clippy::if_not_else,
        reason = "one form: stick, mode, confirmation; the safe choice first"
    )]
    pub(super) fn ui(&mut self, ui: &mut Ui, pal: Palette) -> Option<MakeDone> {
        let ctx = ui.ctx().clone();
        self.poll();
        if self.found.is_none() && self.list_rx.is_none() {
            self.scan(&ctx);
        }
        if self.name.is_empty() {
            self.name = tr("Kasa.lphy", "Vault.lphy").into();
        }
        let mut done = None;
        // Wiping runs.
        if let Some(rx) = &self.wipe_rx {
            match rx.try_recv() {
                Ok(Ok(_)) => {
                    self.wipe_rx = None;
                    return self.target().map(MakeDone::Create);
                }
                Ok(Err(e)) => {
                    self.wipe_rx = None;
                    self.err = Some(e);
                }
                Err(TryRecvError::Empty) => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(tr(
                            "Bellek siliniyor… Belleği çıkarmayın.",
                            "Wiping the stick… Do not remove it.",
                        ));
                    });
                    return None;
                }
                Err(TryRecvError::Disconnected) => self.wipe_rx = None,
            }
        }
        ui.label(
            RichText::new(tr("USB belleği kasa yap", "Turn a USB stick into a vault"))
                .font(crate::fonts::semibold(14.5))
                .color(pal.ink),
        );
        ui.label(
            RichText::new(tr(
                "Bellekte şifreli bir kasa dosyası oluşturulur. Açtığınızda içeriği bellekte değil, bu bilgisayarın belleğinde (RAM disk) durur; kilitleyince yalnızca şifreli dosya belleğe yazılır.",
                "An encrypted vault file is created on the stick. When open, its content lives in this computer's memory (RAM disk), not on the stick; locking writes only the encrypted file to the stick.",
            ))
            .color(pal.muted)
            .size(12.5),
        );
        ui.add_space(6.0);
        // 1. The stick.
        match &self.found {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(tr("Bellekler aranıyor…", "Looking for sticks…"));
                });
            }
            Some(Err(e)) => {
                ui.label(RichText::new(e).color(pal.danger).size(12.5));
            }
            Some(Ok(list)) if list.is_empty() => {
                ui.label(
                    RichText::new(tr(
                        "Uygun bir USB bellek bulunamadı. Belleği takıp yeniden arayın.",
                        "No suitable USB stick was found. Plug one in and search again.",
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
            }
            Some(Ok(list)) => {
                let mut picked = None;
                b::row(ui, |ui| {
                    for d in list {
                        let on = self.pick.as_ref().is_some_and(|p| p.mount == d.mount);
                        let kind = if on { Kind::Primary } else { Kind::Secondary };
                        let label = format!(
                            "{} · {}",
                            escape_display(&d.label),
                            logic::human_size(d.size_bytes)
                        );
                        if b::action(ui, pal, kind, Icon::None, &label).clicked() {
                            picked = Some(d.clone());
                        }
                    }
                });
                if let Some(d) = picked {
                    self.pick = Some(d);
                    self.wipe = None;
                    self.prepared = None;
                    self.err = None;
                }
            }
        }
        b::row(ui, |ui| {
            if b::action(
                ui,
                pal,
                Kind::Secondary,
                Icon::Retry,
                tr("Yeniden ara", "Search again"),
            )
            .clicked()
            {
                self.pick = None;
                self.scan(&ctx);
            }
        });
        let Some(dev) = self.pick.clone() else {
            if super::link_button(ui, pal, tr("‹ Geri", "‹ Back")).clicked() {
                done = Some(MakeDone::Back);
            }
            return done;
        };
        // 2. Mode and name.
        ui.add_space(8.0);
        b::row(ui, |ui| {
            for (wipe, label) in [
                (
                    false,
                    tr(
                        "Dosyaları koruyarak kasa ekle",
                        "Add a vault, keep the files",
                    ),
                ),
                (
                    true,
                    tr(
                        "Belleği silip yalnızca kasa yap",
                        "Wipe it, keep only the vault",
                    ),
                ),
            ] {
                let kind = match (self.wipe == Some(wipe), wipe) {
                    (true, true) => Kind::Danger,
                    (true, false) => Kind::Primary,
                    (false, _) => Kind::Secondary,
                };
                if b::action(ui, pal, kind, Icon::None, label).clicked() {
                    self.wipe = Some(wipe);
                    if wipe && self.prepared.is_none() && self.prep_rx.is_none() {
                        let (tx, rx) = std::sync::mpsc::channel();
                        let ctx = ctx.clone();
                        let mount = dev.mount.clone();
                        std::thread::spawn(move || {
                            let p = lephy_usb::native();
                            let r = lephy_usb::engine::prepare(p.as_ref(), &mount)
                                .map_err(|e| logic::describe_error(&e));
                            let _ = tx.send(r);
                            ctx.request_repaint();
                        });
                        self.prep_rx = Some(rx);
                        self.label.clear();
                        self.gib.clear();
                    }
                }
            }
        });
        let Some(wipe) = self.wipe else {
            return done;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(tr("Kasa dosyası:", "Vault file:")).size(13.0));
            ui.add(egui::TextEdit::singleline(&mut self.name).desired_width(200.0));
        });
        let target = self.target();
        if !wipe {
            ui.label(
                RichText::new(tr(
                    "Bellekteki dosyalar olduğu gibi kalır. Onları kasaya almak için kasa açılınca klasörüne sürükleyin, sonra bellekteki asıllarını silin (USB bellekte silinen veri kurtarılabilir; tam güvenlik için \"silip yalnızca kasa yap\" seçeneğini kullanın).",
                    "The files on the stick stay as they are. To move them into the vault, drag them into its folder once it opens, then delete the originals on the stick (deleted data on a USB stick can be recovered; for full safety use \"wipe it, keep only the vault\").",
                ))
                .color(pal.muted)
                .size(12.0),
            );
            let exists = target
                .as_ref()
                .is_some_and(|t| t.symlink_metadata().is_ok());
            if exists {
                ui.label(
                    RichText::new(tr(
                        "Bellekte bu adda bir dosya var; başka bir ad seçin.",
                        "A file with this name is on the stick; choose another name.",
                    ))
                    .color(pal.danger)
                    .size(12.5),
                );
            }
            ui.add_space(4.0);
            if b::action_enabled(
                ui,
                pal,
                Kind::Primary,
                Icon::Lock,
                tr("Devam: parolayı belirle", "Continue: set the password"),
                target.is_some() && !exists,
            )
            .clicked()
                && let Some(t) = target
            {
                done = Some(MakeDone::Create(t));
            }
        } else {
            match &self.prepared {
                None => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(tr("Bellek denetleniyor…", "Checking the stick…"));
                    });
                }
                Some(Err(e)) => {
                    ui.label(RichText::new(e).color(pal.danger).size(12.5));
                }
                Some(Ok((d, dry))) => {
                    ui.label(
                        RichText::new(match lang() {
                            Lang::Tr => format!(
                                "Silinecek: {} dosya, {} klasör ({}). Bu geri alınamaz.",
                                dry.files,
                                dry.dirs,
                                logic::human_size(dry.bytes)
                            ),
                            Lang::En => format!(
                                "To be deleted: {} files, {} folders ({}). This cannot be undone.",
                                dry.files,
                                dry.dirs,
                                logic::human_size(dry.bytes)
                            ),
                        })
                        .color(pal.danger)
                        .size(12.5),
                    );
                    for p in dry.first.iter().take(5) {
                        ui.label(RichText::new(p).monospace().size(11.5).color(pal.muted));
                    }
                    ui.label(
                        RichText::new(match lang() {
                            Lang::Tr => format!(
                                "Onaylamak için belleğin adını ({}) ve boyutunu GB olarak ({}) yazın.",
                                escape_display(&d.label),
                                d.size_gib()
                            ),
                            Lang::En => format!(
                                "To confirm, type the stick's name ({}) and its size in GB ({}).",
                                escape_display(&d.label),
                                d.size_gib()
                            ),
                        })
                        .size(12.5),
                    );
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.label)
                                .hint_text(tr("Bellek adı", "Stick name"))
                                .desired_width(160.0),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.gib)
                                .hint_text("GB")
                                .desired_width(60.0),
                        );
                    });
                    let ok = self.label == d.label
                        && self.gib.trim().parse::<u64>().ok() == Some(d.size_gib())
                        && target.is_some();
                    if b::action_enabled(
                        ui,
                        pal,
                        Kind::Danger,
                        Icon::Trash,
                        tr("Belleği sil ve devam et", "Wipe the stick and continue"),
                        ok,
                    )
                    .clicked()
                    {
                        let (tx, rx) = std::sync::mpsc::channel();
                        let ctx = ctx.clone();
                        let snap = d.clone();
                        std::thread::spawn(move || {
                            let p = lephy_usb::native();
                            // Same stick as confirmed (identity read again), then wipe through a
                            // handle checked against it.
                            let r = lephy_usb::engine::prepare(p.as_ref(), &snap.mount)
                                .and_then(|(now, _)| {
                                    if now.identity == snap.identity {
                                        Ok(now)
                                    } else {
                                        Err(lephy_core::error::Error::Cancelled(
                                            "the stick changed; nothing was deleted".into(),
                                        ))
                                    }
                                })
                                .and_then(|now| {
                                    lephy_usb::engine::wipe(&now.mount, Some(now.identity.dev_id))
                                })
                                .map_err(|e| logic::describe_error(&e));
                            let _ = tx.send(r);
                            ctx.request_repaint();
                        });
                        self.wipe_rx = Some(rx);
                    }
                }
            }
        }
        if let Some(e) = &self.err {
            ui.label(RichText::new(e).color(pal.danger).size(12.5));
        }
        if super::link_button(ui, pal, tr("‹ Geri", "‹ Back")).clicked() {
            done = Some(MakeDone::Back);
        }
        done
    }
}

impl App {
    /// Each frame: take what the stick watch reports.
    pub(super) fn poll_sticks(&mut self) {
        let Some(rx) = &self.sticks.rx else { return };
        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        for ev in events {
            match ev {
                StickEvent::In(s) => {
                    self.vault.stick_back(&s.mount);
                    let fresh: Vec<PathBuf> = s
                        .vaults
                        .iter()
                        .filter(|p| !self.vault.is_open_path(p))
                        .cloned()
                        .collect();
                    self.sticks.offers.retain(|o| o.mount != s.mount);
                    if !fresh.is_empty() {
                        self.sticks.offers.push(Stick { vaults: fresh, ..s });
                    }
                }
                StickEvent::Out(mount) => {
                    self.sticks.offers.retain(|o| o.mount != mount);
                    self.vault.stick_gone(&mount);
                }
            }
        }
    }

    /// The bar for sticks that hold vaults: open one (asks for its password) or ignore.
    pub(super) fn stick_bar(&mut self, ui: &mut Ui, pal: Palette) {
        if self.sticks.offers.is_empty() {
            return;
        }
        let mut open = None;
        let mut ignore = None;
        for (i, s) in self.sticks.offers.iter().enumerate() {
            super::vault_ui::bar(ui, pal, false, |ui| {
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!("{} belleğinde kasa var", escape_display(&s.label)),
                        Lang::En => format!("The stick {} holds a vault", escape_display(&s.label)),
                    })
                    .font(crate::fonts::semibold(14.0))
                    .color(pal.ink),
                );
                b::row(ui, |ui| {
                    for v in &s.vaults {
                        let name = v
                            .file_name()
                            .map(|n| escape_display(&n.to_string_lossy()))
                            .unwrap_or_default();
                        let label = match lang() {
                            Lang::Tr => format!("{name} aç…"),
                            Lang::En => format!("Open {name}…"),
                        };
                        if b::action(ui, pal, Kind::Primary, Icon::Lock, &label).clicked() {
                            open = Some(v.clone());
                        }
                    }
                    if b::action(ui, pal, Kind::Secondary, Icon::None, tr("Yoksay", "Ignore"))
                        .clicked()
                    {
                        ignore = Some(i);
                    }
                });
            });
        }
        if let Some(i) = ignore {
            self.sticks.offers.remove(i);
        }
        if let Some(p) = open {
            self.sticks.offers.retain(|o| !p.starts_with(&o.mount));
            self.vault.page.open_path(p);
            self.page = super::pages::Page::Vault;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sticks_that_came_and_went() {
        let m = |p: &str, l: &str| (PathBuf::from(p), l.to_owned());
        let before: BTreeMap<_, _> = [m("/Volumes/A", "A"), m("/Volumes/B", "B")].into();
        let now: BTreeMap<_, _> = [m("/Volumes/B", "B"), m("/Volumes/C", "C")].into();
        let (came, went) = diff(&before, &now);
        assert_eq!(came, vec![m("/Volumes/C", "C")]);
        assert_eq!(went, vec![PathBuf::from("/Volumes/A")]);
        let (came, went) = diff(&now, &now);
        assert!(came.is_empty() && went.is_empty());
    }

    /// Only vault-shaped `.lphy` files at the root are offered (not single files, not hidden).
    #[test]
    fn vault_files_on_a_stick() {
        let d = std::env::temp_dir().join(format!("lphy-stick-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let pw = lephy_sys::mem::SecretBytes::from_slice(b"stick vault 1234").unwrap();
        let v = crate::vault::Vault::create(&d.join("Kasa.lphy"), &pw, None, Some(&d.join("p")))
            .unwrap();
        v.close(false).unwrap();
        std::fs::write(d.join("notes.txt"), b"x").unwrap();
        std::fs::write(d.join("broken.lphy"), b"not a vault").unwrap();
        std::fs::copy(d.join("Kasa.lphy"), d.join(".hidden.lphy")).unwrap();
        assert_eq!(vaults_on(&d), vec![d.join("Kasa.lphy")]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
