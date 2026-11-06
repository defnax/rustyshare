# rustyshare

A RetroShare-compatible client written in Rust. It was started by
[sehraf](https://github.com/sehraf) as a Rust learning project (development
stopped in 2022) and is being revived to cover more of what libretroshare does.
It speaks the real RetroShare wire protocol, so it connects to normal
RetroShare nodes with a RetroShare profile, and it comes with its own small
web interface.

> ⚠️ **Experimental.** Many RetroShare features are still missing (see below).
> Use a test profile, not your main one. The original developer's notes are in
> [`HISTORY.adoc`](HISTORY.adoc).

---

## What works

| Area | Status |
| --- | --- |
| Profiles | Load RetroShare profiles (`rnp`/`pgp` keyring, `LOC06_…` locations); create new profiles and locations at runtime; portable mode |
| Security | Friends' certificates fully checked (SSL id, PGP signature, friend check, TLS handshake signature); config files verified (`.sgn`) with `.tmp` fallback |
| Friends | Add friends from a RetroShare certificate, remove locations, `peers.cfg` saved encrypted and signed; other locations of accepted PGP keys are added from discovery like RetroShare |
| Network | Outgoing and incoming TLS connections, reconnects, discovery, UPnP port forwarding, external IP finder (OpenDNS), download / upload limits |
| Chat | Private chat, chat rooms (join, leave, members, topic), chat history (last 200 messages per chat) |
| GXS identities | Sync with RetroShare, create signed and anonymous identities, signatures checked like current RetroShare, stored in `gxsid_db` |
| Status | Own status (online / away / busy) and status message exchanged with friends like RetroShare (status service, chat custom state); friends' status shown |
| Forums | Receive and serve forums and posts, subscribe, post, create forums, sync period per forum, unread counts |
| Reputation | Exchange opinions with friends (rsReputations), rate identities, banned identities are hidden in chat rooms |
| Web UI | Home, Friends, People, Messages, Chats, Forums, Settings (see below) |

**Missing:** channels, boards, mail, distant chat, circles,
file sharing, Tor/I2P, UDP/DHT. Progress and plans are tracked in the
roadmap document.

---

## 1. Requirements

### Windows

1. **Rust** – <https://rustup.rs>, default `stable-x86_64-pc-windows-msvc` toolchain.
2. **Visual Studio Build Tools** – <https://visualstudio.microsoft.com/visual-cpp-build-tools/>
   with the **"Desktop development with C++"** workload.
3. **Perl** – [Strawberry Perl](https://strawberryperl.com/) (vcpkg needs it to build OpenSSL).
4. **OpenSSL** through vcpkg:

   ```powershell
   git clone https://github.com/microsoft/vcpkg C:\vcpkg
   C:\vcpkg\bootstrap-vcpkg.bat
   C:\vcpkg\vcpkg install openssl:x64-windows-static-md
   setx VCPKG_ROOT C:\vcpkg
   setx OPENSSL_DIR C:\vcpkg\installed\x64-windows-static-md
   setx OPENSSL_STATIC 1
   ```

   Open a **new** terminal afterwards so the variables are picked up.
   (`start-rustyshare.bat` sets them itself.)
5. About 3–5 GB free disk space for `target\`.

`sequoia-openpgp` is already configured with the Windows-native `crypto-cng`
backend, so Nettle/libclang are not needed.

### Linux (Debian/Ubuntu)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install build-essential pkg-config libssl-dev libsqlite3-dev
```

On Linux you may switch `sequoia-openpgp` back to its default Nettle backend
(then also install `clang llvm nettle-dev`).

---

## 2. Build

```powershell
cd C:\Users\<you>\Documents\GitHub\rustyshare
cargo build            # debug build: target\debug\rustyshare.exe
cargo build --release  # release build: target\release\rustyshare.exe
```

`Cargo.lock` is committed, so everyone builds with the same dependency
versions. Compiler warnings are harmless; only `error[...]` lines matter.

---

## 3. Start

### The easy way (Windows)

Double-click **`start-rustyshare.bat`**. It builds rustyshare if needed,
starts it in portable mode and opens the web interface in your browser once
you have logged in.

### By hand

```powershell
.\target\debug\rustyshare.exe --portable
```

1. Pick a location from the list, or `[n]` to create a new profile/location.
2. Enter the profile password.
3. rustyshare connects to your friends and starts the web interface on
   **<http://127.0.0.1:9095>** (local only).

Stop it with **Ctrl+C**. Logs go to the terminal and to `rustyshare*.log`;
log levels per module are set in `src/log_internal.rs`.

### Where the data lives

| Mode | Folder |
| --- | --- |
| Portable (`--portable`, or a file named `portable` next to the exe) | `data\` next to `rustyshare.exe`, created automatically |
| `RETROSHARE_DIR` set | that folder, e.g. `set RETROSHARE_DIR=%APPDATA%\RetroShare` |
| otherwise | `<home>\.retroshare` |

> Don't run RetroShare and rustyshare with the **same location** at the same
> time: they would kick each other off the network.

### Command line options

| Option | Effect |
| --- | --- |
| `--portable` | Portable mode (see above) |
| `--port <n>` | Listening port (otherwise the saved one, or a random port on first start) |
| `--no-upnp` | No UPnP port forwarding on the router (also: Settings → NAT) |
| `--no-ip-finder` | Don't look up the external IP address via DNS (also: Settings) |
| `--add-friend <file>` | Add the friend whose RetroShare certificate is in `<file>` |
| `--show-invite` | Print your own certificate (to give to friends) |

### Files rustyshare writes

All in the location's `config\` folder, encrypted and signed with the location
key like RetroShare's own config files (except the lobby list):

| File | Content |
| --- | --- |
| `peers.cfg` | Friends and their locations (RetroShare's file, unknown entries are kept) |
| `rustyshare_history.cfg` | Chat history |
| `rustyshare_presence.cfg` | Own status and status message |
| `rustyshare_contacts.cfg` | Identities added to / removed from the contacts (People page) |
| `servicecontrol.cfg` | Service permissions (RetroShare's file, shared) |
| `rustyshare_settings.cfg` | Chat history size, default forum sync period |
| `general.cfg` | RetroShare's file: rustyshare only changes the bandwidth limits (`PQIH_FTR`), all other entries are kept |
| `rustyshare_reputation.cfg` | Own opinions and friends' votes |
| `rustyshare_lobbies.json` | Joined chat rooms and the identity used |

RetroShare's `chat.cfg` and `history.cfg` are not changed.

---

## 4. Web interface

Open <http://127.0.0.1:9095>:

- **Home** – your certificate to share, add a friend.
- **Friends** – your own profile on top (status dot: click to change
  online / away / busy; status message: click to edit), friend list with
  status and status message, details: PGP key, locations with status, last
  seen, address; chat with or remove a location.
- **Messages** – private chats (conversations, newest first).
- **Chats** – chat rooms: join/leave, messages, members, topic.
- **People** – identities with type, owner profile, reputation (👍/👎);
  create new identities.
- **Forums** – subscribed and known forums, threads, posting, new forums.
- **Settings** – node info; network like RetroShare (network mode, NAT,
  local / external address, dynamic DNS, external IP finder, download and
  upload limits); chat history size; default forum sync period; theme.

### JSON API

The web interface uses a REST API on the same port. Where RetroShare has the
same function, the name and parameters follow the RetroShare JSON API:

- `/rsPeers/` – `getFriendList`, `getPeerDetails`, `isOnline`,
  `GetRetroshareInvite`, `acceptInvite`, `removeFriendLocation`,
  `setLocalAddress`, `setExtAddress`, `setDynDNS`, `setNetworkMode`,
  `setVisState`, `allowServerIPDetermination`, `getAllowServerIPDetermination`;
  rustyshare specific: `getFriendsOverview`, `getFriendsOfFriends`
- `/rsChats/` (like RetroShare's `rschats.h`) – `getChatLobbyList`,
  `getListOfNearbyChatLobbies`, `getChatLobbyInfo`, `sendChat`,
  `joinVisibleChatLobby`, `unsubscribeChatLobby`, `invitePeerToLobby`,
  `getPendingChatLobbyInvites`, `acceptLobbyInvite`, `denyLobbyInvite`,
  `getCustomStateString`, `getOwnCustomStateString`, `setCustomStateString`;
  rustyshare specific: `getLobbyParticipants`, `getChatHistory`
- `/rsIdentity/` – `getIdentitiesSummaries`, `getOwnSignedIds`,
  `getOwnPseudonimousIds`, `getIdDetails`, `createIdentity`, `setAsRegularContact`,
  `isARegularContact`; rustyshare specific: `getIdentityInfo`, `getRegularContacts`
- `/rsServiceControl/` – `getOwnServices`, `getServicesProvided`, `getServicesAllowed`,
  `getServicePermissions`, `updateServicePermissions`
- `/rsReputations/` – `setOwnOpinion`, `getOwnOpinion`, `getReputationInfo`,
  `overallReputationLevel`, `isIdentityBanned`
- `/rsStatus/` – `getOwnStatus`, `getStatusList`, `getStatus`, `sendStatus`
- `/rsConfig/` – `GetMaxDataRates`, `SetMaxDataRates`, `GetCurrentDataRates`
- `/rsEvents/registerEventsHandler` – live events
- `/rustyshare/` – `version`, `getSettings`, `setSettings`, `clearChatHistory`

```powershell
curl -X POST http://127.0.0.1:9095/rsPeers/getFriendList -H "Content-Type: application/json" -d "{}"
```

There is no login: the API only listens on 127.0.0.1.

---

## Project layout

```
src/
  main.rs              startup: pick location, unlock key, start core + web API
  profile.rs           creating profiles and locations
  invite.rs            RetroShare certificates (invites), adding friends
  peers_cfg.rs         loading/saving peers.cfg
  history.rs           chat history
  reputation.rs        reputation data
  upnp.rs              UPnP and external IP finder
  controller/          core task and per-peer connections
  transport_ng/        TLS connections, certificate checks, listener
  services/            RetroShare services (chat, discovery, reputation, turtle, …)
  gxs/                 GXS / NXS backend (identities)
  model/               shared state (DataCore)
  webui/               REST API (actix-web)
webui/index.html       the web interface
retroshare_compat/     wire format: TLV (de)serialization, config files,
                       keyring, SQLCipher GXS databases
start-rustyshare.bat   start with a double click (Windows)
```

## Credits & license

Original author: sehraf. Licensed under the terms in [`LICENSE`](LICENSE).
Related projects: [RetroShare](https://retroshare.cc/),
[Xeres](https://xeres.io/) (a RetroShare client in Java).
