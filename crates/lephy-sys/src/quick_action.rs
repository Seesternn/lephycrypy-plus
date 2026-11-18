//! macOS Finder Quick Action for the current user only (`~/Library/Services`; nothing outside the
//! user's own home folder).
//!
//! [`install`] writes one Automator workflow, `lephycrypy+.workflow`, that appears in Finder under
//! the right-click menu's **Quick Actions** for every file and folder. Its only action is
//! `/usr/bin/open -b <bundle id> <selected items>`: the items are handed to the app through the
//! normal "open documents" path, so nothing is encrypted without the app's own screens.
//! [`uninstall`] removes exactly that workflow, and only while it is still ours.

use std::io;
use std::path::{Path, PathBuf};

/// Name of the workflow bundle.
pub const WORKFLOW: &str = "lephycrypy+.workflow";
/// Bundle identifier written into the workflow; [`uninstall`] removes only workflows carrying it.
pub const MARKER: &str = "io.github.seesternn.lephycrypy.quickaction";

/// The user's `~/Library/Services` folder.
///
/// # Errors
/// `HOME` missing or not absolute.
#[allow(clippy::disallowed_methods)] // only HOME is read; not a secret
pub fn services_dir() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home folder not found"))?;
    Ok(home.join("Library").join("Services"))
}

/// Writes the workflow into `dir` (normally [`services_dir`]). `menu` is the text shown in Finder,
/// `app_id` the bundle identifier of the app that receives the items. An existing workflow of ours
/// is replaced; anything else with the same name is left alone and reported.
///
/// # Errors
/// File-system errors, a foreign item at the target, or an unsupported platform.
pub fn install(dir: &Path, menu: &str, app_id: &str) -> io::Result<()> {
    if !cfg!(target_os = "macos") {
        return Err(unsupported());
    }
    if !app_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid bundle identifier",
        ));
    }
    let target = dir.join(WORKFLOW);
    match std::fs::symlink_metadata(&target) {
        Ok(_) if !is_ours(&target) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and was not created by this app",
                    target.display()
                ),
            ));
        }
        Ok(_) => std::fs::remove_dir_all(&target)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::create_dir_all(dir)?;
    // Built next to the target and renamed into place, so Finder never sees a half-written bundle.
    let tmp = dir.join(format!(".{WORKFLOW}.tmp-{}", std::process::id()));
    if std::fs::symlink_metadata(&tmp).is_ok() {
        std::fs::remove_dir_all(&tmp)?;
    }
    let contents = tmp.join("Contents");
    std::fs::create_dir_all(&contents)?;
    let written = std::fs::write(contents.join("Info.plist"), info_plist(menu))
        .and_then(|()| std::fs::write(contents.join("document.wflow"), document(app_id)))
        .and_then(|()| std::fs::rename(&tmp, &target));
    if written.is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    written?;
    refresh();
    Ok(())
}

/// Removes the workflow from `dir` if it is ours; does nothing if it is absent.
///
/// # Errors
/// File-system errors, or a foreign item at the target.
pub fn uninstall(dir: &Path) -> io::Result<()> {
    let target = dir.join(WORKFLOW);
    match std::fs::symlink_metadata(&target) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(_) if !is_ours(&target) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} was not created by this app", target.display()),
            ));
        }
        Ok(_) => std::fs::remove_dir_all(&target)?,
    }
    refresh();
    Ok(())
}

/// Whether our workflow is installed in `dir`.
#[must_use]
pub fn is_installed(dir: &Path) -> bool {
    is_ours(&dir.join(WORKFLOW))
}

/// A real folder (not a symlink) whose `Info.plist` carries [`MARKER`].
fn is_ours(target: &Path) -> bool {
    std::fs::symlink_metadata(target).is_ok_and(|m| m.is_dir())
        && std::fs::read_to_string(target.join("Contents").join("Info.plist"))
            .is_ok_and(|s| s.contains(MARKER))
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "Quick Actions are macOS-only")
}

/// Asks the system to re-read `~/Library/Services` (best effort; it also does so on its own).
fn refresh() {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/System/Library/CoreServices/pbs")
            .arg("-update")
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn info_plist(menu: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>{MARKER}</string>
	<key>CFBundleName</key>
	<string>lephycrypy+</string>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSIconName</key>
			<string>NSActionTemplate</string>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>{}</string>
			</dict>
			<key>NSMessage</key>
			<string>runWorkflowAsService</string>
			<key>NSRequiredContext</key>
			<dict>
				<key>NSApplicationIdentifier</key>
				<string>com.apple.finder</string>
			</dict>
			<key>NSSendFileTypes</key>
			<array>
				<string>public.item</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
"#,
        xml_escape(menu)
    )
}

/// The shell command run by the workflow. Finder passes absolute paths as arguments.
fn command(app_id: &str) -> String {
    format!("exec /usr/bin/open -b {app_id} \"$@\"")
}

#[allow(clippy::too_many_lines, reason = "one fixed plist template")]
fn document(app_id: &str) -> String {
    let cmd = xml_escape(&command(app_id));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AMApplicationBuild</key>
	<string>534</string>
	<key>AMApplicationVersion</key>
	<string>2.10</string>
	<key>AMDocumentVersion</key>
	<string>2</string>
	<key>actions</key>
	<array>
		<dict>
			<key>action</key>
			<dict>
				<key>AMAccepts</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Optional</key>
					<true/>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>AMActionVersion</key>
				<string>2.0.3</string>
				<key>AMApplication</key>
				<array>
					<string>Automator</string>
				</array>
				<key>AMParameterProperties</key>
				<dict>
					<key>COMMAND_STRING</key>
					<dict/>
					<key>CheckedForUserDefaultShell</key>
					<dict/>
					<key>inputMethod</key>
					<dict/>
					<key>shell</key>
					<dict/>
					<key>source</key>
					<dict/>
				</dict>
				<key>AMProvides</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>ActionBundlePath</key>
				<string>/System/Library/Automator/Run Shell Script.action</string>
				<key>ActionName</key>
				<string>Run Shell Script</string>
				<key>ActionParameters</key>
				<dict>
					<key>COMMAND_STRING</key>
					<string>{cmd}</string>
					<key>CheckedForUserDefaultShell</key>
					<true/>
					<key>inputMethod</key>
					<integer>1</integer>
					<key>shell</key>
					<string>/bin/sh</string>
					<key>source</key>
					<string></string>
				</dict>
				<key>BundleIdentifier</key>
				<string>com.apple.RunShellScript</string>
				<key>CFBundleVersion</key>
				<string>2.0.3</string>
				<key>CanShowSelectedItemsWhenRun</key>
				<false/>
				<key>CanShowWhenRun</key>
				<true/>
				<key>Category</key>
				<array>
					<string>AMCategoryUtilities</string>
				</array>
				<key>Class Name</key>
				<string>RunShellScriptAction</string>
				<key>InputUUID</key>
				<string>6E1F3A52-0C1D-4B8E-9A61-3C7D2B5E8F01</string>
				<key>Keywords</key>
				<array>
					<string>Shell</string>
					<string>Script</string>
				</array>
				<key>OutputUUID</key>
				<string>6E1F3A52-0C1D-4B8E-9A61-3C7D2B5E8F02</string>
				<key>UUID</key>
				<string>6E1F3A52-0C1D-4B8E-9A61-3C7D2B5E8F03</string>
				<key>UnlocalizedApplications</key>
				<array>
					<string>Automator</string>
				</array>
				<key>arguments</key>
				<dict>
					<key>0</key>
					<dict>
						<key>default value</key>
						<integer>0</integer>
						<key>name</key>
						<string>inputMethod</string>
						<key>required</key>
						<string>0</string>
						<key>type</key>
						<string>0</string>
						<key>uuid</key>
						<string>0</string>
					</dict>
					<key>1</key>
					<dict>
						<key>default value</key>
						<false/>
						<key>name</key>
						<string>CheckedForUserDefaultShell</string>
						<key>required</key>
						<string>0</string>
						<key>type</key>
						<string>0</string>
						<key>uuid</key>
						<string>1</string>
					</dict>
					<key>2</key>
					<dict>
						<key>default value</key>
						<string></string>
						<key>name</key>
						<string>source</string>
						<key>required</key>
						<string>0</string>
						<key>type</key>
						<string>0</string>
						<key>uuid</key>
						<string>2</string>
					</dict>
					<key>3</key>
					<dict>
						<key>default value</key>
						<string></string>
						<key>name</key>
						<string>COMMAND_STRING</string>
						<key>required</key>
						<string>0</string>
						<key>type</key>
						<string>0</string>
						<key>uuid</key>
						<string>3</string>
					</dict>
					<key>4</key>
					<dict>
						<key>default value</key>
						<string>/bin/sh</string>
						<key>name</key>
						<string>shell</string>
						<key>required</key>
						<string>0</string>
						<key>type</key>
						<string>0</string>
						<key>uuid</key>
						<string>4</string>
					</dict>
				</dict>
				<key>conversionLabel</key>
				<integer>0</integer>
				<key>isViewVisible</key>
				<integer>1</integer>
				<key>location</key>
				<string>309.000000:305.000000</string>
			</dict>
			<key>isViewVisible</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>connectors</key>
	<dict/>
	<key>workflowMetaData</key>
	<dict>
		<key>applicationBundleIDsByPath</key>
		<dict/>
		<key>applicationPaths</key>
		<array/>
		<key>inputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>outputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>presentationMode</key>
		<integer>15</integer>
		<key>processesInput</key>
		<false/>
		<key>serviceApplicationBundleID</key>
		<string>com.apple.finder</string>
		<key>serviceApplicationPath</key>
		<string>/System/Library/CoreServices/Finder.app</string>
		<key>serviceInputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>serviceOutputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>serviceProcessesInput</key>
		<false/>
		<key>systemImageName</key>
		<string>NSActionTemplate</string>
		<key>useAutomaticInputType</key>
		<false/>
		<key>workflowTypeIdentifier</key>
		<string>com.apple.Automator.servicesMenu</string>
	</dict>
</dict>
</plist>
"#
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lephy-qa-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn menu_text_is_escaped() {
        let p = info_plist("a <b> & \"c\"");
        assert!(p.contains("a &lt;b&gt; &amp; &quot;c&quot;"));
        assert!(p.contains(MARKER));
    }

    #[test]
    fn command_passes_items_as_arguments() {
        assert_eq!(command("x.y"), "exec /usr/bin/open -b x.y \"$@\"");
        assert!(document("x.y").contains("exec /usr/bin/open -b x.y &quot;$@&quot;"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[cfg_attr(miri, ignore = "file system; does not run under Miri")]
    fn install_and_uninstall_in_a_scratch_folder() {
        let d = scratch("ok");
        assert!(!is_installed(&d));
        install(&d, "Menu", "io.example.app").unwrap();
        assert!(is_installed(&d));
        // Installing again replaces our own workflow.
        install(&d, "Menu 2", "io.example.app").unwrap();
        let info = std::fs::read_to_string(d.join(WORKFLOW).join("Contents/Info.plist")).unwrap();
        assert!(info.contains("Menu 2"));
        uninstall(&d).unwrap();
        assert!(!is_installed(&d));
        assert!(!d.join(WORKFLOW).exists());
        uninstall(&d).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[cfg_attr(miri, ignore = "file system; does not run under Miri")]
    fn foreign_workflow_is_left_alone() {
        let d = scratch("foreign");
        std::fs::create_dir_all(d.join(WORKFLOW).join("Contents")).unwrap();
        std::fs::write(d.join(WORKFLOW).join("Contents/Info.plist"), "other").unwrap();
        assert!(!is_installed(&d));
        assert!(install(&d, "Menu", "io.example.app").is_err());
        assert!(uninstall(&d).is_err());
        assert!(d.join(WORKFLOW).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "file system; does not run under Miri")]
    fn bad_bundle_id_is_rejected() {
        let d = scratch("bad");
        assert!(install(&d, "Menu", "x; rm -rf /").is_err());
        assert!(!d.exists());
    }
}
