//! `lephycrypy` komut satırı. Aşama 0: komut ağacı ve çıkış kodu eşlemesi; komutlar henüz
//! uygulanmadı (kod 1 ile "henüz uygulanmadı").

#![forbid(unsafe_code)]

// R5-02: `test-vectors` feature'ı ile derlenen bir çekirdek ikiliye asla giremez.
const _: () = assert!(
    !lephy_core::TEST_VECTORS_ENABLED,
    "lephy-cli, lephy-core/test-vectors feature'ı ile derlenemez (PLAN R5-02)"
);

use std::path::PathBuf;
use std::process::ExitCode as ProcessExit;

use clap::{Parser, Subcommand};
use lephy_core::error::{Error, ExitCode};

#[derive(Parser)]
#[command(
    name = "lephycrypy",
    version,
    about = "lephycrypy+ — parolayla dosya/klasör şifreleme"
)]
struct Cli {
    /// Ayrıntılı hata nedenleri (sır içermez).
    #[arg(long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dosya veya klasörü şifreler.
    Encrypt {
        /// Kaynak dosya/klasör ("-" = stdin).
        input: PathBuf,
        /// Çıktı yolu (varsayılan: <8 rastgele hex>.lphy).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// `.lphy` dosyasını çözer.
    Decrypt {
        /// Şifreli dosya.
        input: PathBuf,
        /// Çıktı yolu.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Dosyayı yazmadan doğrular.
    Verify {
        /// Şifreli dosya.
        input: PathBuf,
    },
    /// Açık başlık meta verisini gösterir (kaçışlanmış).
    Info {
        /// Şifreli dosya.
        input: PathBuf,
    },
    /// Parolayı değiştirir; dosya anahtarı (FK) değişmez — gerçek rotasyon için `reencrypt`.
    Rekey {
        /// Şifreli dosya.
        input: PathBuf,
        /// Sonucu tam doğrula.
        #[arg(long)]
        verify: bool,
    },
    /// Yeni dosya anahtarı ile tüm chunk'ları yeniden şifreler.
    Reencrypt {
        /// Şifreli dosya.
        input: PathBuf,
    },
    /// Bir dizindeki bayat `.lphy-tmp-*` dosyalarını onayla siler.
    Cleanup {
        /// Taranacak dizin.
        dir: PathBuf,
    },
}

fn main() -> ProcessExit {
    // Hiçbir sır oluşmadan ve clap'ten önce (PLAN › Süreç başı, adım 0–3).
    if let Err(e) = lephy_sys::platform::harden() {
        eprintln!("uyarı: süreç sertleştirme kısmen başarısız: {e}");
    }

    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ProcessExit::from(0),
        Err(e) => {
            eprintln!("hata: {e}");
            if let (true, Some(d)) = (cli.verbose, e.detail()) {
                eprintln!("ayrıntı: {d}");
            }
            exit_with(e.exit_code())
        }
    }
}

fn run(cli: &Cli) -> lephy_core::error::Result<()> {
    let name = match &cli.command {
        Command::Encrypt { .. } => "encrypt",
        Command::Decrypt { .. } => "decrypt",
        Command::Verify { .. } => "verify",
        Command::Info { .. } => "info",
        Command::Rekey { .. } => "rekey",
        Command::Reencrypt { .. } => "reencrypt",
        Command::Cleanup { .. } => "cleanup",
    };
    Err(Error::Environment(format!(
        "`{name}` henüz uygulanmadı (aşama 0 iskeleti; bkz. docs/PLAN.md)"
    )))
}

fn exit_with(code: ExitCode) -> ProcessExit {
    // 130 dahil tüm kodlar u8'e sığar.
    u8::try_from(code.code()).map_or(ProcessExit::FAILURE, ProcessExit::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_password_argument_exists() {
        // D3: parola argv'den asla alınmaz.
        let cmd = Cli::command();
        for sub in cmd.get_subcommands() {
            for arg in sub.get_arguments() {
                let id = arg.get_id().as_str();
                assert!(
                    !id.contains("password")
                        || id.ends_with("stdin")
                        || id.ends_with("fd")
                        || id.ends_with("file"),
                    "argv parola argümanı: {id}"
                );
            }
        }
    }
}
