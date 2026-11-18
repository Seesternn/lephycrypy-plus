//! Help texts: short, task-oriented explanations shown as fold-out boxes next to the controls they
//! explain, and all together on the Help page.

use super::{Palette, fonts, theme};
use crate::i18n::tr;
use eframe::egui::{self, CornerRadius, CursorIcon, RichText, Sense, Stroke, Ui, vec2};

/// A help topic: a question as title and a few short paragraphs or steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Topic {
    /// Password or public keys: which one to use.
    PasswordOrKeys,
    /// What an identity file is and how to create one.
    Identity,
    /// Where a recipient's public key comes from and how to share yours.
    PublicKeys,
    /// Opening a file that was encrypted to a public key.
    OpenWithIdentity,
    /// Sender signatures.
    Signatures,
    /// Backups: paper words, copies, lost passwords.
    Backup,
}

impl Topic {
    /// Every topic, in the order of the Help page.
    pub(super) const ALL: [Self; 6] = [
        Self::PasswordOrKeys,
        Self::Identity,
        Self::PublicKeys,
        Self::OpenWithIdentity,
        Self::Signatures,
        Self::Backup,
    ];

    pub(super) fn title(self) -> &'static str {
        match self {
            Self::PasswordOrKeys => tr("Parola mı, açık anahtar mı?", "Password or public keys?"),
            Self::Identity => tr(
                "Kimlik dosyası nedir, nasıl oluşturulur?",
                "What is an identity file, and how do I make one?",
            ),
            Self::PublicKeys => tr(
                "Açık anahtarı nereden bulurum, kendiminkini nasıl paylaşırım?",
                "Where do I get a public key, and how do I share mine?",
            ),
            Self::OpenWithIdentity => tr(
                "Bana açık anahtarla gönderilen dosyayı nasıl açarım?",
                "How do I open a file someone encrypted to my key?",
            ),
            Self::Signatures => tr("İmza ne işe yarar?", "What does signing do?"),
            Self::Backup => tr(
                "Kimliğimi ya da parolamı kaybedersem?",
                "What if I lose my identity or its password?",
            ),
        }
    }

    /// Paragraphs; a paragraph starting with a digit and a dot is drawn as a numbered step.
    pub(super) fn body(self) -> Vec<&'static str> {
        match self {
            Self::PasswordOrKeys => vec![
                tr(
                    "Parola: dosyayı kendiniz için ya da parolayı güvenle söyleyebileceğiniz biri için şifrelersiniz. Ek bir hazırlık gerekmez.",
                    "Password: you encrypt for yourself, or for someone you can tell the password safely. Nothing to set up.",
                ),
                tr(
                    "Açık anahtar: dosyayı belirli kişilere şifrelersiniz; ortak bir parola gerekmez. Her alıcının bir kez anahtar çifti oluşturması ve size açık anahtarını vermesi gerekir.",
                    "Public keys: you encrypt for chosen people without sharing a password. Each recipient creates a key pair once and gives you their public key.",
                ),
            ],
            Self::Identity => vec![
                tr(
                    "Kimlik dosyası (.lphykey) sizin gizli anahtarınızdır ve seçtiğiniz parolayla şifreli durur. Size açık anahtarla gönderilen dosyaları yalnızca onunla açabilirsiniz; dosyaları imzalamak için de kullanılır.",
                    "An identity file (.lphykey) holds your secret key, encrypted with a password you choose. Only it opens files sent to your public key; it also signs files.",
                ),
                tr(
                    "1. Ana sayfada Anahtarlarım'ı açın, \"Anahtar çifti oluştur…\" düğmesine basın.",
                    "1. On the home screen open My keys and press \"Create a key pair…\".",
                ),
                tr(
                    "2. Kimlik için bir parola belirleyin (en az 12 karakter) ve iki kez yazın.",
                    "2. Choose a password for the identity (at least 12 characters) and type it twice.",
                ),
                tr(
                    "3. Kaydedilecek yeri seçin. İki dosya oluşur: ad.lphykey (gizli; kimseye vermeyin) ve ad.pub (açık anahtar; paylaşın).",
                    "3. Choose where to save it. Two files are made: name.lphykey (secret; never share it) and name.pub (public key; share it).",
                ),
                tr(
                    "4. Ekranda çıkan 22 kelimelik kâğıt yedeğini yazıp güvenli bir yerde saklayın.",
                    "4. Write down the 22-word paper backup shown on screen and keep it somewhere safe.",
                ),
                tr(
                    "Aynı ekrandaki \"Açık anahtarla\" bölümünden, şifrelerken de anahtar çifti oluşturabilirsiniz.",
                    "You can also create a key pair while encrypting, in the \"With public keys\" section.",
                ),
            ],
            Self::PublicKeys => vec![
                tr(
                    "Alıcıdan açık anahtarını isteyin: lphy1… ile başlayan bir metin ya da .pub dosyası. Açık anahtar gizli değildir; e-postayla, mesajla gönderilebilir.",
                    "Ask the recipient for their public key: text starting with lphy1…, or a .pub file. It is not secret; email or a message is fine.",
                ),
                tr(
                    "Anahtarın gerçekten o kişiden geldiğini başka bir yoldan (telefonla, yüz yüze) ilk ve son birkaç harfini okuyarak doğrulayın. Sahte bir anahtar, dosyayı başkasına açar.",
                    "Check that the key really is theirs by another channel (a call, in person): read out its first and last few letters. A fake key opens the file to someone else.",
                ),
                tr(
                    "Kendi anahtarınızı paylaşmak için: Anahtarlarım → \"Kimliğimi aç\" ile .lphykey dosyanızı açın ve açık anahtarın yanındaki Kopyala'ya basın; ya da .pub dosyasını gönderin.",
                    "To share yours: My keys → \"Open my identity\", open your .lphykey and press Copy next to the public key; or send the .pub file.",
                ),
                tr(
                    "Dosyayı sonra kendiniz de açmak istiyorsanız kendi açık anahtarınızı da listeye ekleyin.",
                    "Add your own public key to the list too if you want to open the file yourself later.",
                ),
            ],
            Self::OpenWithIdentity => vec![
                tr(
                    "1. Şifreli dosyayı açın; uygulama dosyanın bir açık anahtara şifrelendiğini kendisi anlar.",
                    "1. Open the encrypted file; the app sees that it was encrypted to a public key.",
                ),
                tr(
                    "2. \"Seç\" ile kendi kimlik dosyanızı (.lphykey) seçin ve onun parolasını girin (dosyanın değil, kimliğin parolası).",
                    "2. Press \"Choose\", pick your identity file (.lphykey) and enter its password (the identity's password, not a file password).",
                ),
                tr(
                    "Kimliğiniz yoksa bu dosya size açılamaz: gönderen kişi sizin açık anahtarınızı kullanmamıştır. Önce bir anahtar çifti oluşturup açık anahtarınızı gönderene verin; dosyayı yeniden şifrelemesini isteyin.",
                    "Without an identity this file cannot open for you: the sender did not use your public key. Create a key pair, give the sender your public key and ask them to encrypt the file again.",
                ),
            ],
            Self::Signatures => vec![
                tr(
                    "İmzalı bir dosyayı açan kişi, dosyayı kimin hazırladığını (lphysig1… imza anahtarı) görür ve sonradan değiştirilmediğini doğrular.",
                    "Whoever opens a signed file sees who made it (the lphysig1… signer key) and that it was not changed afterwards.",
                ),
                tr(
                    "İmzalamak için kimlik dosyanız ve parolası gerekir. İmza anahtarınız .pub dosyanızın ikinci satırıdır; alıcılarınız onu bilirse imzanın gerçekten sizden geldiğinden emin olur.",
                    "Signing needs your identity file and its password. Your signer key is the second line of your .pub file; recipients who know it can be sure the signature is yours.",
                ),
            ],
            Self::Backup => vec![
                tr(
                    "Kimlik dosyası ya da parolası kaybolursa ona şifrelenmiş dosyalar açılamaz; kimse (biz de) kurtaramaz.",
                    "If the identity file or its password is lost, files encrypted to it cannot be opened; nobody, including us, can recover them.",
                ),
                tr(
                    "Anahtar oluştururken gösterilen 22 kelimeyi kâğıda yazın. Sonradan da Anahtarlarım → \"Kimliğimi aç\" ile kâğıt yedeğini yeniden alabilirsiniz.",
                    "Write down the 22 words shown when the key is created. You can take the paper backup later as well: My keys → \"Open my identity\".",
                ),
                tr(
                    "Kelimelerden kimliği geri getirmek için: lephycrypy identity restore yeni.lphykey (komut satırında). Kelimeleri gören herkes dosyalarınızı açabilir; fotoğrafını çekmeyin, buluta koymayın.",
                    "To restore the identity from the words: lephycrypy identity restore new.lphykey (command line). Anyone who sees the words can open your files; do not photograph them or store them in the cloud.",
                ),
                tr(
                    "Parolayla şifrelenmiş dosyalar için kurtarma yoktur: parolayı bir parola yöneticisinde saklayın.",
                    "Files encrypted with a password cannot be recovered without it: keep the password in a password manager.",
                ),
            ],
        }
    }
}

/// Paragraphs of a topic: plain text, or numbered steps with a small badge.
pub(super) fn body_ui(ui: &mut Ui, pal: Palette, topic: Topic) {
    for para in topic.body() {
        let para = &para;
        let step = para
            .split_once(". ")
            .filter(|(n, _)| n.len() == 1 && n.chars().all(|c| c.is_ascii_digit()));
        if let Some((n, text)) = step {
            ui.horizontal_top(|ui| {
                let (r, _) = ui.allocate_exact_size(vec2(22.0, 18.0), Sense::hover());
                ui.painter()
                    .circle_filled(r.center() - vec2(3.0, 0.0), 9.0, pal.accent);
                ui.painter().text(
                    r.center() - vec2(3.0, 0.0),
                    egui::Align2::CENTER_CENTER,
                    n,
                    fonts::semibold(11.0),
                    pal.on_accent,
                );
                ui.add(egui::Label::new(RichText::new(text).color(pal.ink).size(13.0)).wrap());
            });
        } else {
            ui.add(egui::Label::new(RichText::new(*para).color(pal.ink).size(13.0)).wrap());
        }
        ui.add_space(6.0);
    }
}

/// A fold-out help box: a "?" badge and the question; clicking shows the answer.
pub(super) fn help_box(ui: &mut Ui, pal: Palette, topic: Topic) {
    let id = ui.scope_id().with(("lephy-help", topic as u8));
    let mut open = ui.ctx().data(|d| d.get_temp::<bool>(id).unwrap_or(false));
    egui::Frame::new()
        .fill(pal.accent_soft.gamma_multiply(0.6))
        .stroke(Stroke::new(1.0, pal.accent.gamma_multiply(0.25)))
        .corner_radius(CornerRadius::same(theme::R_INPUT))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let head = ui
                .horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 9.0, pal.accent);
                    ui.painter().text(
                        r.center(),
                        egui::Align2::CENTER_CENTER,
                        "?",
                        fonts::semibold(12.0),
                        pal.on_accent,
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(topic.title())
                                .font(fonts::semibold(13.5))
                                .color(pal.ink),
                        )
                        .wrap(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (r, _) = ui.allocate_exact_size(vec2(14.0, 14.0), Sense::hover());
                        let c = r.center();
                        let d = if open { -3.0 } else { 3.0 };
                        let st = Stroke::new(1.6, pal.accent);
                        ui.painter()
                            .line_segment([c + vec2(-5.0, -d / 1.5), c + vec2(0.0, d)], st);
                        ui.painter()
                            .line_segment([c + vec2(0.0, d), c + vec2(5.0, -d / 1.5)], st);
                    });
                })
                .response;
            let click = ui.interact(head.rect, id.with("head"), Sense::click());
            let click = click.on_hover_cursor(CursorIcon::PointingHand);
            if click.clicked() {
                open = !open;
            }
            if open {
                ui.add_space(8.0);
                body_ui(ui, pal, topic);
            }
        });
    ui.ctx().data_mut(|d| d.insert_temp(id, open));
    ui.add_space(8.0);
}

#[cfg(test)]
mod tests {
    use super::Topic;
    use crate::i18n::{Lang, set_lang};

    #[test]
    fn every_topic_has_text_in_both_languages() {
        for l in [Lang::Tr, Lang::En] {
            set_lang(l);
            for t in Topic::ALL {
                assert!(!t.title().is_empty());
                assert!(t.body().iter().all(|p| !p.is_empty()));
            }
        }
        set_lang(Lang::Tr);
    }
}
