#!/usr/bin/env bash
# Builds the macOS app bundle: target/macos/lephycrypy+.app (and a disk image with --dmg).
# The signature is ad hoc (to run it on this Mac only); distribution also needs a Developer ID
# signature and notarization.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
OUT=target/macos
APP="$OUT/lephycrypy+.app"

# Strip local paths (home directory, checkout location) from the binary.
export RUSTFLAGS="--remap-path-prefix=$HOME=~ --remap-path-prefix=$PWD=."
cargo build --release --locked -p lephy-gui

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/lephycrypy-gui "$APP/Contents/MacOS/lephycrypy-gui"

ICONSET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z "$s" "$s" crates/lephy-gui/assets/icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2))
  sips -z "$d" "$d" crates/lephy-gui/assets/icon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$(dirname "$ICONSET")"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>lephycrypy+</string>
  <key>CFBundleDisplayName</key><string>lephycrypy+</string>
  <key>CFBundleIdentifier</key><string>io.github.seesternn.lephycrypy</string>
  <key>CFBundleExecutable</key><string>lephycrypy-gui</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleDevelopmentRegion</key><string>tr</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key><true/>
  <key>UTExportedTypeDeclarations</key>
  <array>
    <dict>
      <key>UTTypeIdentifier</key><string>io.github.seesternn.lephycrypy.encrypted</string>
      <key>UTTypeDescription</key><string>lephycrypy+ encrypted file</string>
      <key>UTTypeConformsTo</key><array><string>public.data</string></array>
      <key>UTTypeIconFile</key><string>AppIcon</string>
      <key>UTTypeTagSpecification</key>
      <dict><key>public.filename-extension</key><array><string>lphy</string></array></dict>
    </dict>
  </array>
  <key>CFBundleDocumentTypes</key>
  <array>
    <!-- .lphy: double-click opens the app. -->
    <dict>
      <key>CFBundleTypeName</key><string>lephycrypy+ encrypted file</string>
      <key>CFBundleTypeRole</key><string>Editor</string>
      <key>LSHandlerRank</key><string>Owner</string>
      <key>LSItemContentTypes</key><array><string>io.github.seesternn.lephycrypy.encrypted</string></array>
    </dict>
    <!-- Any file or folder: listed under "Open With" in Finder's context menu (never the default). -->
    <dict>
      <key>CFBundleTypeName</key><string>Any file or folder</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>LSHandlerRank</key><string>Alternate</string>
      <key>LSItemContentTypes</key><array><string>public.item</string></array>
    </dict>
  </array>
</dict>
</plist>
PLIST

# Extended attributes (provenance, Finder info) make codesign refuse the bundle.
xattr -cr "$APP"
codesign --force --options runtime --sign - "$APP"
echo "$APP"

if [ "${1:-}" = "--dmg" ]; then
  DMG="$OUT/lephycrypy-plus-${VERSION}.dmg"
  STAGE="$(mktemp -d)"
  cp -R "$APP" "$STAGE/"
  ln -s /Applications "$STAGE/Applications"
  hdiutil create -quiet -volname "lephycrypy+" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
  rm -rf "$STAGE"
  # Checksum next to the image, for "Verify your download" in the README.
  (cd "$(dirname "$DMG")" && shasum -a 256 "$(basename "$DMG")" > "$(basename "$DMG").sha256")
  echo "$DMG"
  echo "$DMG.sha256"
fi
