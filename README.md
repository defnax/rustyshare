# rustyshare

A RetroShare-compatible client written in Rust, originally started by
[sehraf](https://github.com/sehraf) as a Rust learning project.
It talks the real RetroShare wire protocol, so it can connect to normal
RetroShare peers using your existing RetroShare identity.

> ⚠️ **Experimental and unfinished.** The original development stopped in 2022.
> Peers are **not verified**, almost nothing is written to disk, and many
> RetroShare features are missing. Use a test identity, not your main one.
> See [`readme.adoc`](readme.adoc) for the original developer's progress notes.

---

## What works / what doesn't

| Works (partly) | Missing |
| --- | --- |
| Loading an existing RetroShare PGP keyring and locations | File sharing / downloads |
| Decrypting `peers.cfg` and `general.cfg` | Forums, channels, boards, mail |
| Outgoing TCP connections to friends | Peer certificate verification |
| Services: bwctrl, discovery, heartbeat, rtt, service_info, status, turtle (forwarding) | Saving anything (state is in-memory) |
| Chat lobbies (join, read, send) | Incoming connections (broken, "no shared cipher") |
| GXS identities (request/answer) | |
| Creating profiles and locations (new, experimental) | |
| REST API compatible with part of the RetroShare JSON API | A desktop GUI |

---

## 1. Requirements

You need an **existing RetroShare account** (made with normal RetroShare).
rustyshare cannot create one itself.

### Windows

1. **Rust** – install from <https://rustup.rs> and keep the default
   `stable-x86_64-pc-windows-msvc` toolchain.
2. **Visual Studio Build Tools** – <https://visualstudio.microsoft.com/visual-cpp-build-tools/>
   with the **"Desktop development with C++"** workload.
3. **Perl** – [Strawberry Perl](https://strawberryperl.com/). Needed to build OpenSSL from source.
4. **OpenSSL** – easiest through vcpkg:

   ```powershell
   git clone https://github.com/microsoft/vcpkg C:\vcpkg
   C:\vcpkg\bootstrap-vcpkg.bat
   C:\vcpkg\vcpkg install openssl:x64-windows-static-md
   setx VCPKG_ROOT C:\vcpkg
   ```

   Open a **new** terminal after `setx` so the variable is picked up.
5. **Free disk space** – a full build needs about 3–5 GB in `target\`.

### Linux (Debian/Ubuntu)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install build-essential pkg-config libssl-dev clang llvm nettle-dev libsqlite3-dev
```

---

## 2. Windows fix: sequoia-openpgp crypto backend

`sequoia-openpgp` uses the **Nettle** C library by default, which is hard to
get on Windows. Switch it to the Windows-native backend (CNG) in **both**
`Cargo.toml` and `retroshare_compat/Cargo.toml`:

```toml
# replace:  sequoia-openpgp = "1.9"
sequoia-openpgp = { version = "1.9", default-features = false, features = ["crypto-cng", "compression"] }
```

On Linux you can leave it as is (Nettle is used).

---

## 3. Build

```powershell
cd C:\Users\<you>\Documents\GitHub\rustyshare
cargo build --release
```

The binary ends up in `target\release\rustyshare.exe`.

Optional feature flags:

| Command | Effect |
| --- | --- |
| `cargo build --release` | Default build, with the web API (`webui_actix`) |
| `cargo build --release --no-default-features` | No web server at all |
| `cargo build --release --features use_tracing` | Use `tracing` for logging instead of flexi_logger |

### If the build fails

The repository has **no `Cargo.lock`**, so Cargo picks the newest compatible
versions of all dependencies, some of which are much newer than the 2022 code.
Common fixes:

- **Errors inside a dependency** (not in `src/`): pin it to an older version,
  e.g. `cargo update -p <crate> --precise <older-version>`.
- **Old `rustls` / `tokio-rustls` / `rusqlite` API errors**: keep the versions
  from `Cargo.toml` (`rustls 0.20`, `tokio-rustls 0.23`, `rusqlite 0.27`), don't upgrade them.
- **New compiler warnings** are harmless; only `error[...]` lines matter.

Once it builds, commit the generated `Cargo.lock` (and remove `Cargo.lock`
from `.gitignore`) so the build stays reproducible.

---

## 4. Point it at your RetroShare data

rustyshare looks for RetroShare data in **`<home>\.retroshare`**
(`C:\Users\<you>\.retroshare` on Windows, `~/.retroshare` on Linux).

On Windows, normal RetroShare keeps its data in **`%APPDATA%\RetroShare`**.
Point rustyshare at it with the `RETROSHARE_DIR` environment variable:

```bat
set RETROSHARE_DIR=%APPDATA%\RetroShare
```

(or copy it: `robocopy "%APPDATA%\RetroShare" "%USERPROFILE%\.retroshare" /E`)

The folder must contain the PGP keyring (in `pgp\` for older RetroShare or
`rnp\` for newer versions) and one or more
`LOC06_<ssl-id>` location folders, each with `keys\user_cert.pem` and
`config\peers.cfg` / `config\general.cfg`.

> Close the real RetroShare first, or use a different identity. Two clients
> running with the same location will kick each other off the network.

### Portable mode

Put an empty file called `portable` next to `rustyshare.exe` (or start it with
`--portable`). The data folder is then `data\` next to the executable and is
created automatically.

### Creating a profile / location

If no location exists, rustyshare starts the creation wizard automatically.
Otherwise choose `[n]` in the location menu. You can create a completely new
profile (PGP key) or add a new location to an existing profile. The files are
written in the same format RetroShare uses (RSA-4096 PGP key in the
`rnp`/`pgp` keyring, PGP-signed SSL certificate, `LOC06_<id>` folder), so the
profile should also open in RetroShare. A backup of the keyring is saved as
`retroshare_secret_keyring.gpg.bak` before it is changed.

---

## 5. Run

```powershell
.\target\release\rustyshare.exe
```

or during development:

```powershell
cargo run --release
```

What happens:

1. It lists the locations it found:
   ```
   Please select a location:
    [1]: 'LOC06_0123abcd…' by 'MyName (Generated by RetroShare) <>'
   >
   ```
   Type the number and press Enter.
2. Enter your **RetroShare password** for that location.
3. It loads your friends from `peers.cfg` and starts connecting to them over TCP.
4. It starts the web API on **<http://127.0.0.1:9095>** (local only).

Logs are printed to the terminal and also written to a `rustyshare*.log`
file in the current folder. Log levels per module are set in
`src/log_internal.rs`.

Stop it with **Ctrl+C**.

---

## 6. GUI (web interface)

There is no desktop GUI. rustyshare serves:

- a subset of the **RetroShare JSON API** on `http://127.0.0.1:9095`
  (no login/auth):
  - `/rsPeers/` – `getFriendList`, `getPeerDetails`, `isOnline`, `GetRetroshareInvite`, `GetShortInvite`
  - `/rsMsgs/` – `getChatLobbyList`, `getListOfNearbyChatLobbies`, `getChatLobbyInfo`, `sendChat`, `joinVisibleChatLobby`, `unsubscribeChatLobby`
  - `/rsIdentity/` – `getIdentitiesSummaries`, `getOwnSignedIds`, `getOwnPseudonimousIds`, `getIdDetails`
  - `/rsEvents/registerEventsHandler` – live events (Server-Sent Events)
- static files from the **`webui\`** folder inside the project, at `/`.

Quick API test:

```powershell
curl -X POST http://127.0.0.1:9095/rsPeers/getFriendList -H "Content-Type: application/json" -d "{}"
```

### Using RetroShare's official web UI (RSNewWebUI)

1. Get it: <https://github.com/RetroShare/RSNewWebUI>
2. In `webui-src/app/rswebui.js`, make every request send JSON, by adding:
   ```js
   headers['Content-type'] = 'application/json';
   ```
   (rustyshare's server rejects requests without this header.)
3. Build it following its own README.
4. Copy the built output (the files with `index.html`) into
   `rustyshare\webui\`.
5. **Rebuild rustyshare.** The `webui` path is baked in at compile time
   (`CARGO_MANIFEST_DIR/webui/`), so the folder must stay inside the project.
6. Open <http://127.0.0.1:9095> in your browser.

Only the pages backed by the endpoints above (friends, chat lobbies,
identities) will work. The rest of the UI will show errors or stay empty.

---

## Project layout

```
src/
  main.rs              startup: pick location, unlock key, start core + web API
  controller/          core task and per-peer tasks
  transport/           TCP + TLS (openssl / rustls)
  services/            RetroShare services (chat, discovery, turtle, rtt, …)
  gxs/                 GXS / NXS backend (identities)
  model/               shared state (DataCore)
  webui/               actix-web REST API
retroshare_compat/     wire format: serde-based TLV (de)serialization,
                       config files, keyring, SQLCipher GXS databases
```

## Credits & license

Original author: sehraf. Licensed under the terms in [`LICENSE`](LICENSE).
Related project: [Xeres](https://xeres.io/), a RetroShare client written in Java.
