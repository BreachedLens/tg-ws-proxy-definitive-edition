# tg-ws-proxy-definitive-edition

**tg-ws-proxy-definitive-edition** is a fork of [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) maintained at [BreachedLens/tg-ws-proxy-definitive-edition](https://github.com/BreachedLens/tg-ws-proxy-definitive-edition). It extends the local Telegram WebSocket proxy with an out-of-the-box route for networks that block Cloudflare CDN: **Google CDN is selected by default**, without requiring a VPN or administrator privileges. Domain-fronting availability depends on the CDN and network; no provider can be guaranteed to work everywhere.

The proxy runs locally on your computer, preserves Telegram MTProto encryption, and does not require a separate remote proxy server.

## Features

- **Multi-CDN & Domain Fronting:** built-in presets for **Google CDN** (default), **Fastly**, **Akamai**, **Amazon CloudFront**, **Bunny CDN**, **Gcore**, **Vercel Edge**, the classic **Cloudflare CDN** route, and **Custom SNI / Host**. Availability and routing behavior depend on each CDN and network.
- **Modular `bypass/` package:** independent transport layer with availability checks and automatic fallback to another configured route when a connection fails.
- **Updated UI and tray:** dynamic settings show only the controls for the selected mode, with Custom fields shown only for Custom SNI / Host. The active route appears in the settings window and tray tooltip. Proxy restarts run in the background so the tray menu remains responsive. Automatic startup update checks are disabled by default.

## Quick start — Windows

### Standalone EXE

1. Download `tg-ws-proxy-definitive.exe` from the project's Releases page.
2. Run it. The default Google CDN route does not require administrator privileges.
3. From the system tray menu, choose **Open in Telegram** to configure Telegram Desktop automatically, or **Copy Link** to copy the proxy link.
4. Use the tray icon to open settings and logs, restart the proxy, or exit.

To configure Telegram Desktop manually, open **Settings → Advanced → Connection type → Proxy**, choose MTProto, and enter server `127.0.0.1`, port `1443`, and the secret shown in the app or logs.

### Run from source

Install Python 3.10 or newer, open PowerShell in the repository root, and run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe windows.py
```

### Build the Windows EXE

Install the project dependencies and the pinned PyInstaller build extra, then build with the Windows spec:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[build]"
.\.venv\Scripts\python.exe -m PyInstaller packaging/windows.spec --noconfirm
```

The single-file, windowed output is `dist\tg-ws-proxy-definitive.exe`.

## How the local proxy works

```text
Telegram Desktop → MTProto proxy (127.0.0.1:1443) → WebSocket/TLS → Telegram DC
```

The application listens locally, identifies the Telegram data center from the MTProto initialization packet, and opens a WebSocket connection to that DC. Configured fallback routes are used when a selected route is unavailable. Telegram's MTProto encryption protects the transmitted data.

If Telegram cannot connect, check the configured DC addresses and selected CDN in settings; a CDN may reject fronting in a particular network, so try another provider.

## Documentation

See the [full project README](docs/README.md), [Windows packaging spec](packaging/windows.spec), [build workflow](.github/workflows/build.yml), and [MIT license](LICENSE).
