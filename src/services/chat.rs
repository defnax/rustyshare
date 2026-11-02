#[allow(deprecated)]
use std::{
    collections::hash_map::Entry,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use nanorand::Rng;
use retroshare_compat::{
    basics::{GxsId, PeerId},
    events::{ChatMessage, EventType},
    serde::{from_retroshare_wire, to_retroshare_wire, Toggleable},
    services::{
        chat::{
            ChatIdType, ChatLobbyBouncingObject, ChatLobbyConnectChallengeItem, ChatLobbyEvent,
            ChatLobbyEventItem, ChatLobbyFlags, ChatLobbyId, ChatLobbyInviteItem,
            ChatLobbyListItem, ChatLobbyMsgItem, ChatMsgItem, ChatStatusItem,
        },
        service_info::RsServiceInfo,
    },
    tlv::tlv_keys::{KeyId, TlvKeyFlags, TlvKeySignature, TlvKeySignatureInner},
};
use serde::Serialize;
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::{interval, Interval},
};

use crate::{
    gxs::gxsid::{generate_signature, verify_signature},
    history::{HistoryChat, HistoryEntry},
    low_level_parsing::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    model::{
        intercom::Intercom,
        services::chat::{ChatCmd, Lobby},
        DataCore,
    },
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

const CHAT_SUB_TYPE_CHAT_DEFAULT: u8 = 0x01;
const CHAT_SUB_TYPE_CHAT_AVATAR: u8 = 0x03;
const CHAT_SUB_TYPE_CHAT_STATUS: u8 = 0x04;
const CHAT_SUB_TYPE_PRIVATECHATMSG_CONFIG: u8 = 0x05;
#[deprecated]
const CHAT_SUB_TYPE_CHAT_LOBBY_MSG_DEPRECATED: u8 = 0x06; // don't use ! Deprecated
#[deprecated]
const CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_DEPREC: u8 = 0x07; // don't use ! Deprecated
const CHAT_SUB_TYPE_CHAT_LOBBY_ACCEPT: u8 = 0x08;
const CHAT_SUB_TYPE_CHAT_LOBBY_CHALLENGE: u8 = 0x09;
const CHAT_SUB_TYPE_CHAT_LOBBY_UNSUBSCRIBE: u8 = 0x0A;
#[deprecated]
const CHAT_SUB_TYPE_CHAT_LOBBY_EVENT_DEPREC: u8 = 0x0B; // don't use ! Deprecated
const CHAT_SUB_TYPE_CHAT_LOBBY_MSG: u8 = 0x0C; // will be deprecated when only signed messages are accepted (02/2015)
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST: u8 = 0x0D;
#[deprecated]
#[allow(non_upper_case_globals)]
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated: u8 = 0x0E; // to be removed
#[deprecated]
#[allow(non_upper_case_globals)]
const CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_deprecated: u8 = 0x0F; // to be removed
const CHAT_SUB_TYPE_CHAT_LOBBY_EVENT: u8 = 0x10;
#[deprecated]
#[allow(non_upper_case_globals)]
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated2: u8 = 0x11; // to be removed (deprecated since 02 Dec. 2012)
#[deprecated]
#[allow(non_upper_case_globals)]
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated3: u8 = 0x12;
const CHAT_SUB_TYPE_DISTANT_INVITE_CONFIG: u8 = 0x13;
const CHAT_SUB_TYPE_CHAT_LOBBY_CONFIG: u8 = 0x15;
const CHAT_SUB_TYPE_DISTANT_CHAT_DH_PUBLIC_KEY: u8 = 0x16;
const CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG: u8 = 0x17;
const CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT: u8 = 0x18;
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST: u8 = 0x19;

#[deprecated]
const CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_DEPRECATED: u8 = 0x1A; // to be removed (deprecated since May 2017)
const CHAT_SUB_TYPE_CHAT_LOBBY_INVITE: u8 = 0x1B;
const CHAT_SUB_TYPE_OUTGOING_MAP: u8 = 0x1C;
const CHAT_SUB_TYPE_SUBSCRIBED_CHAT_LOBBY_CONFIG: u8 = 0x1D;

pub const CHAT_MAX_KEEP_MSG_RECORD: Duration = Duration::from_secs(1200); // 20 minutes
const CONNECTION_CHALLENGE_MAX_MSG_AGE: Duration = Duration::from_secs(30); // maximum age of a message to be used in a connection challenge

macro_rules! verify_item {
    ($self:expr, $item:expr, $packet:expr) => {
        let key_id = $item.bounce_obj.signature.key_id.to_owned();

        let header: ServiceHeader = $packet.header.to_owned().into();
        let mut item_to_verify = $item.to_owned();
        item_to_verify.bounce_obj.signature.turn_off();
        let payload = to_retroshare_wire(&item_to_verify);
        let header: Header = ServiceHeader::new(header.service, header.sub_type, &payload).into();
        let data_signed = Packet::new_without_location(header, payload).to_bytes();

        if !$self
            .verify_message(&key_id, &data_signed, &$item.bounce_obj.signature.sign_data)
            .await
        {
            debug!("{} verification failed!", stringify!($item));
            debug!(" -> {:?}", $item);
            return;
        } else {
            trace!("verified {} successful", stringify!($item));
        }
    };
}

macro_rules! sign_item {
    ($self:expr, $item:expr, $header:expr) => {{
        let key_id = $item.bounce_obj.signature.key_id.to_owned();

        let header: ServiceHeader = $header;
        let mut item_to_sign = $item.to_owned();
        item_to_sign.bounce_obj.signature.turn_off();
        let payload = to_retroshare_wire(&item_to_sign);
        let header: Header = ServiceHeader::new(header.service, header.sub_type, &payload).into();
        let data_to_sign = Packet::new_without_location(header, payload).to_bytes();

        match $self.sign_message(&key_id, &data_to_sign).await {
            Some(signature) => {
                trace!("signed {} successful", stringify!($item));
                $item.bounce_obj.signature.sign_data = signature.into();
                true
            }
            None => {
                debug!("[Chat] {} signing failed!", stringify!($item));
                debug!(" -> {:?}", $item);
                // TODO error handling
                false
            }
        }
    }};
}

// ChatLobbyId lobby_id ;						// unique id of the lobby
// std::string lobby_name ;					// name to use for this lobby
// std::string lobby_topic ;					// topic to use for this lobby
// std::set<RsPeerId> participating_friends ;	// list of direct friend who participate.

// uint32_t total_number_of_peers ;			// total number of participating peers. Might not be
// rstime_t last_report_time ; 					// last time the lobby was reported.
// ChatLobbyFlags lobby_flags ;				// see RS_CHAT_LOBBY_PRIVACY_LEVEL_PUBLIC / RS_CHAT_LOBBY_PRIVACY_LEVEL_PRIVATE

/// rustyshare's own list of joined lobbies (in the location's config folder).
/// RetroShare's chat.cfg is left untouched.
const LOBBIES_FILE: &str = "rustyshare_lobbies.json";

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct SavedLobbies {
    lobbies: Vec<SavedLobby>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedLobby {
    /// lobby id as decimal string (u64 doesn't fit into JSON numbers safely)
    id: String,
    /// identity used in this lobby (hex)
    gxs_id: String,
}

fn load_joined_lobbies(file: &std::path::Path) -> std::collections::HashMap<ChatLobbyId, GxsId> {
    let saved: SavedLobbies = std::fs::read_to_string(file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    saved
        .lobbies
        .into_iter()
        .filter_map(|l| {
            let id = l.id.parse::<ChatLobbyId>().ok()?;
            let gxs = hex::decode(&l.gxs_id).ok()?;
            if gxs.len() != 16 {
                return None;
            }
            Some((id, GxsId::from(gxs)))
        })
        .collect()
}

pub struct Chat {
    rx: UnboundedReceiver<Intercom>,

    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,

    cmd_rx: UnboundedReceiver<ChatCmd>,

    /// joined lobbies and the identity used for each, re-joined after a restart
    auto_join: std::sync::Mutex<std::collections::HashMap<ChatLobbyId, GxsId>>,
    lobbies_file: std::path::PathBuf,

    timer_lobby_request: Interval,
    timer_lobby_maintenance: Interval,
    timer_lobby_keep_alive: Interval,
}

/*
TODOs:
- banning
*/

impl Chat {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Chat {
        let data = core.get_service_data().chat();

        let (tx_chat, rx_chat) = unbounded_channel();
        *data.cmd.write().await = Some(tx_chat);

        // lobbies we joined before (and with which identity)
        let lobbies_file = core.get_config_dir().await.join(LOBBIES_FILE);
        let auto_join = load_joined_lobbies(&lobbies_file);
        if !auto_join.is_empty() {
            info!("will re-join {} chat lobbies", auto_join.len());
        }

        Chat {
            rx,

            core: core.clone(),
            core_tx,

            cmd_rx: rx_chat,

            auto_join: std::sync::Mutex::new(auto_join),
            lobbies_file,

            timer_lobby_request: interval(Duration::from_secs(120)),
            timer_lobby_maintenance: interval(Duration::from_secs(30)),
            timer_lobby_keep_alive: interval(Duration::from_secs(120)),
        }
    }

    fn send_packet<T>(&self, sub_type: u8, item: &T, receiving_peer: Arc<PeerId>)
    where
        T: Serialize,
    {
        let payload = to_retroshare_wire(item);
        let header = ServiceHeader::new(ServiceType::Chat, sub_type, &payload);
        let packet = Packet::new(header.into(), payload, receiving_peer);

        self.core_tx
            .send(Intercom::Send(packet))
            .expect("failed to send to core");
    }

    /// `p3ChatService::handleRecvChatStatusItem()`: status messages (custom state
    /// strings) of friends, see `presence.rs`.
    fn handle_chat_status(&self, mut packet: Packet) {
        use crate::presence::{
            chat_status_packet, CHAT_FLAG_CUSTOM_STATE, CHAT_FLAG_CUSTOM_STATE_AVAILABLE,
            CHAT_FLAG_PRIVATE, CHAT_FLAG_REQUEST_CUSTOM_STATE,
        };

        let peer = packet.peer_id.clone();
        let item: ChatStatusItem = from_retroshare_wire(&mut packet.payload);
        let text: String = item.status_string.into();

        if item.flags & CHAT_FLAG_REQUEST_CUSTOM_STATE != 0 {
            // the friend wants our status message
            let own = self.core.own_presence();
            self.core_tx
                .send(Intercom::Send(chat_status_packet(
                    Some(peer),
                    CHAT_FLAG_CUSTOM_STATE,
                    &own.message,
                )))
                .expect("failed to send to core");
        } else if item.flags & CHAT_FLAG_CUSTOM_STATE != 0 {
            // the friend's status message
            self.core.presence_set_peer_message(&peer.to_string(), text);
        } else if item.flags & CHAT_FLAG_CUSTOM_STATE_AVAILABLE != 0 {
            // the friend changed it, ask for the new one
            self.core_tx
                .send(Intercom::Send(chat_status_packet(
                    Some(peer),
                    CHAT_FLAG_PRIVATE | CHAT_FLAG_REQUEST_CUSTOM_STATE,
                    "",
                )))
                .expect("failed to send to core");
        } else {
            // typing notifications ("is typing...") are not shown yet
            trace!("[Chat] status from {peer}: {:#06x} {text:?}", item.flags);
        }
    }

    async fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) {
        trace!("[Chat] {header:?}");

        // just a read on a RwLock
        let data = self.core.get_service_data().chat();

        #[allow(non_upper_case_globals)]
        match header.sub_type {
            CHAT_SUB_TYPE_CHAT_AVATAR => debug!("AVATAR"),
            // RS_PKT_SUBTYPE_CHAT_AVATAR_INFO (avatars are not supported yet)
            0x1E => debug!("AVATAR INFO"),
            CHAT_SUB_TYPE_CHAT_STATUS => self.handle_chat_status(packet),
            CHAT_SUB_TYPE_CHAT_LOBBY_ACCEPT
            | CHAT_SUB_TYPE_CHAT_LOBBY_CONFIG
            | CHAT_SUB_TYPE_CHAT_LOBBY_EVENT
            | CHAT_SUB_TYPE_CHAT_LOBBY_INVITE
            | CHAT_SUB_TYPE_CHAT_LOBBY_UNSUBSCRIBE => debug!("LOBBY"),
            CHAT_SUB_TYPE_CHAT_LOBBY_MSG => debug!("MSG"),

            CHAT_SUB_TYPE_DISTANT_CHAT_DH_PUBLIC_KEY | CHAT_SUB_TYPE_DISTANT_INVITE_CONFIG => {
                debug!("DISTANT")
            }
            CHAT_SUB_TYPE_OUTGOING_MAP => debug!("OUTGOING MAP"),
            CHAT_SUB_TYPE_PRIVATECHATMSG_CONFIG => debug!("PRIVATE MSG"),
            CHAT_SUB_TYPE_SUBSCRIBED_CHAT_LOBBY_CONFIG => debug!("SUBSCRIBED CHAT"),

            #[allow(deprecated)]
            CHAT_SUB_TYPE_CHAT_LOBBY_EVENT_DEPREC
            | CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_DEPREC
            | CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_DEPRECATED
            | CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_deprecated
            | CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated
            | CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated2
            | CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated3
            | CHAT_SUB_TYPE_CHAT_LOBBY_MSG_DEPRECATED => debug!("DEPRECATED"),

            // ---
            CHAT_SUB_TYPE_CHAT_DEFAULT => {
                trace!("[Chat] ChatMsgItem");

                let msg: ChatMsgItem = from_retroshare_wire(&mut packet.payload);
                trace!("CHAT_SUB_TYPE_CHAT_DEFAULT {msg:?}");

                // RetroShare also sends empty items to exchange status strings and
                // avatars, only real messages go to the web UI
                let control = ChatLobbyFlags::CUSTOM_STATE
                    | ChatLobbyFlags::REQUEST_CUSTOM_STATE
                    | ChatLobbyFlags::CUSTOM_STATE_AVAILABLE
                    | ChatLobbyFlags::REQUESTS_AVATAR
                    | ChatLobbyFlags::CONTAINS_AVATAR
                    | ChatLobbyFlags::AVATAR_AVAILABLE;
                let text: String = msg.message.to_owned().into();
                if msg.chat_flags.contains(ChatLobbyFlags::PRIVATE)
                    && !msg.chat_flags.intersects(control)
                    && !text.is_empty()
                {
                    let peer_id: PeerId = *packet.peer_id;
                    let nickname = self
                        .core
                        .get_location_by_id(packet.peer_id.clone())
                        .map(|loc| loc.get_person().get_name().to_owned())
                        .unwrap_or_default();
                    info!("received private chat message from {nickname} ({peer_id})");

                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as u32;
                    self.core.record_chat(
                        HistoryChat::Private(peer_id.to_string()),
                        HistoryEntry {
                            from: nickname.to_owned(),
                            author: String::new(),
                            text: text.to_owned(),
                            time: msg.send_time,
                            incoming: true,
                        },
                    );

                    let event_msg = ChatMessage {
                        chat_id: peer_id.into(),
                        peer_alternate_nickname: nickname,
                        send_time: msg.send_time,
                        recv_time: now,
                        msg: text,
                        incoming: true,
                        online: true,
                        ..Default::default()
                    };
                    self.core_tx
                        .send(Intercom::Event(EventType::ChatMessage { msg: event_msg }))
                        .expect("failed to send to core");
                }
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_CHALLENGE => {
                trace!("[Chat] lobby challenge");
                let challenge: ChatLobbyConnectChallengeItem =
                    from_retroshare_wire(&mut packet.payload);
                trace!("{challenge:?}");

                let now = SystemTime::now();
                let mut lock = data.lobbies.write().await;
                for (lobby_id, lobby) in &mut *lock {
                    if !lobby.joined {
                        continue;
                    }

                    for (msg_id, ts) in &lobby.msg_cache {
                        if ts.checked_add(CONNECTION_CHALLENGE_MAX_MSG_AGE).unwrap() < now {
                            continue;
                        }

                        if challenge.challenge_code
                            == self.calculate_lobby_challenge(lobby_id, msg_id)
                        {
                            debug!("found a fitting lobby challenge for {}", lobby.lobby_name);
                            // found a match!
                            *lobby
                                .participating_friends
                                .entry(packet.peer_id.to_owned())
                                .or_insert(SystemTime::now()) = SystemTime::now();

                            let packet = self.build_lobby_invite(lobby);
                            self.core_tx
                                .send(Intercom::Send(packet))
                                .expect("failed to send to core");
                            break;
                        }
                    }
                }
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST => {
                trace!("[Chat] requested lobbies");
                assert!(packet.payload.is_empty());

                let lobbies = data
                    .lobbies
                    .read()
                    .await
                    .iter()
                    .map(|(_id, lobby)| lobby.into())
                    .collect();
                let list = ChatLobbyListItem { lobbies };

                // let payload = to_retroshare_wire(&list);
                // let header =
                //     ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_LOBBY_LIST, &payload)
                //         .into();
                // return handle_packet!(Packet::new(header, payload, packet.peer_id.to_owned()));
                self.send_packet(
                    CHAT_SUB_TYPE_CHAT_LOBBY_LIST,
                    &list,
                    packet.peer_id.to_owned(),
                )
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST => {
                let list: ChatLobbyListItem = from_retroshare_wire(&mut packet.payload);

                let mut lock = data.lobbies.write().await;

                info!("[Chat] received lobbies:");
                for lobby in list.lobbies {
                    info!(" - {lobby:?}");

                    let entry = lock.entry(lobby.id).or_insert(lobby.to_owned().into());
                    entry.last_activity = std::time::SystemTime::now();
                    entry.update_participant(packet.peer_id.to_owned());
                    entry.update_max_peers(lobby.count);
                }

                // for auto_join in &self.auto_join {
                //     if let Some(lobby) = lock.get_mut(auto_join) {
                //         if !lobby.joined {
                //             // FIXME, we are holding the lock for the whole duration of the call
                //             // this also triggers a keep alive
                //             self.join_lobby(lobby, self.own_gxs_id.to_owned()).await;
                //         }
                //     }
                // }

                // check for joinable lobbies
                let join_id: Vec<(ChatLobbyId, GxsId)> = self
                    .auto_join
                    .lock()
                    .expect("lock poisoned")
                    .iter()
                    .filter(|(id, _)| matches!(lock.get(*id), Some(lobby) if !lobby.joined))
                    .map(|(id, gxs_id)| (*id, *gxs_id))
                    .collect();
                drop(lock);

                for (lobby_id, gxs_id) in join_id {
                    self.join_lobby(lobby_id, Arc::new(gxs_id)).await;
                }

                // for lobby_id in joined_id {
                //     let lobby = {
                //         match data.lobbies.read().await.get(&lobby_id) {
                //             Some(l) => l.to_owned(),
                //             None => continue,
                //         }
                //     };

                //     let packet = self.build_lobby_invite(&lobby);

                //     for (peer, _) in &lobby.participating_friends {
                //         let mut p = packet.to_owned();
                //         p.peer_id = peer.to_owned();
                //         self.core_tx
                //             .send(Intercom::Send(p))
                //             .expect("failed to send");
                //     }

                //     // send join event
                //     for packet in self
                //         .send_lobby_event(&lobby, ChatLobbyEvent::PeerJoined, None)
                //         .await
                //     {
                //         self.core_tx
                //             .send(Intercom::Send(packet))
                //             .expect("failed to send");
                //     }
                // }
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT => {
                trace!("[Chat] signed event");
                trace!("{}", hex::encode(&packet.payload));

                // read from a copy: the packet is forwarded to the other friends in the
                // room as it is (reading the original empties it, and the friend would get
                // a header without data -> "BAD Packet Read" in RetroShare)
                let event: ChatLobbyEventItem = from_retroshare_wire(&mut packet.payload.to_owned());
                trace!("{event:?}");

                self.handle_chat_lobby_event(event, packet).await;
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG => {
                trace!("[Chat] signed msg");

                let msg: ChatLobbyMsgItem = from_retroshare_wire(&mut packet.payload.to_owned());
                trace!("{msg:?}");

                self.handle_chat_lobby_msg(msg, packet).await;
            }

            sub_type => {
                warn!("[Chat] received unknown sub typ {sub_type}");
            }
        }
    }

    async fn handle_chat_lobby_event(&self, event: ChatLobbyEventItem, packet: Packet) {
        let data = self.core.get_service_data().chat();

        // filter
        if !self.filter_event(&event).await {
            return;
        }
        // verify
        verify_item!(self, event, packet);

        // remember the participant's nickname
        data.nicknames.write().expect("lock poisoned").insert(
            event.bounce_obj.signature.key_id.to_owned().into(),
            event.bounce_obj.nick.to_string(),
        );

        let mut lock = data.lobbies.write().await;
        if let Some(lobby) = lock.get_mut(&event.bounce_obj.public_lobby_id) {
            // this quite noisy
            if log::log_enabled!(log::Level::Debug) {
                debug!("event {:?} in {}", event.event_type, lobby.lobby_name);
            } else {
                match event.event_type {
                    ChatLobbyEvent::KeepAlive => {}
                    ref event @ _ => info!("event {event:?} in {}", lobby.lobby_name),
                }
            }

            // bounce!
            for (participant, _) in &lobby.participating_friends {
                // skip origin
                if participant == &packet.peer_id {
                    continue;
                }

                let mut packet = packet.to_owned();
                packet.peer_id = participant.to_owned();
                self.core_tx
                    .send(Intercom::Send(packet))
                    .expect("failed to send");
            }

            let key_id = &event.bounce_obj.signature.key_id;

            use ChatLobbyEvent::*;
            match event.event_type {
                KeepAlive => {
                    *lobby
                        .participants
                        .entry(Arc::new(key_id.to_owned().into()))
                        .or_insert(SystemTime::now()) = SystemTime::now();
                }
                PeerChangeNickname => (),
                PeerJoined => {
                    let check = lobby
                        .participants
                        .insert(Arc::new(key_id.to_owned().into()), SystemTime::now());
                    if check.is_some() {
                        warn!(
                            "added peer {} to lobby {} but they are already part of it",
                            key_id.to_string(),
                            lobby.lobby_name
                        )
                    }
                    // FIXME?
                    // trigger a keep alive packets so as to inform the new participant of our presence in the chatroom
                    // it->second.last_keep_alive_packet_time = 0 ;
                }
                PeerLeft => {
                    _ = lobby
                        .participants
                        .remove(&Arc::new(key_id.to_owned().into()))
                }
                PeerStatus => (),
            }

            // TODO fire event to the rest of the code
            // self.core.webui_send(Event)
        }
    }

    async fn handle_chat_lobby_msg(&self, msg: ChatLobbyMsgItem, packet: Packet) {
        let data = self.core.get_service_data().chat();

        // filter
        if !self.filter_message(&msg).await {
            return;
        }
        // verify
        verify_item!(self, msg, packet);

        // identities we banned (own opinion negative) are ignored completely, like
        // RetroShare: not shown, not stored and not forwarded
        if self
            .core
            .reputation_is_banned(&msg.bounce_obj.signature.key_id.to_string())
        {
            debug!(
                "dropping room message from banned identity {}",
                msg.bounce_obj.signature.key_id
            );
            return;
        }

        // remember the author's nickname
        data.nicknames.write().expect("lock poisoned").insert(
            msg.bounce_obj.signature.key_id.to_owned().into(),
            msg.bounce_obj.nick.to_string(),
        );

        // chat history
        self.core.record_chat(
            HistoryChat::Room(msg.bounce_obj.public_lobby_id),
            HistoryEntry {
                from: msg.bounce_obj.nick.to_string(),
                author: msg.bounce_obj.signature.key_id.to_string(),
                text: msg.msg_obj.message.to_owned().into(),
                time: msg.msg_obj.send_time,
                incoming: true,
            },
        );

        let lock = data.lobbies.read().await;
        if let Some(lobby) = lock.get(&msg.bounce_obj.public_lobby_id) {
            info!("received message in {}:", lobby.lobby_name);
            info!(" -> [{}] {}", msg.bounce_obj.nick, msg.msg_obj.message);

            // bounce!
            for (participant, _) in &lobby.participating_friends {
                // skip origin
                if participant == &packet.peer_id {
                    continue;
                }

                let mut packet = packet.to_owned();
                packet.peer_id = participant.to_owned();
                self.core_tx
                    .send(Intercom::Send(packet))
                    .expect("failed to send");
            }
        }

        // fire event
        self.core_tx
            .send(Intercom::Event(EventType::ChatMessage { msg: msg.into() }))
            .expect("failed to send to core");
    }

    fn request_lobbies(&self) {
        let payload = vec![];

        let header = ServiceHeader::new(
            self.get_id(),
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST,
            &payload,
        )
        .into();
        let packet = Packet::new_without_location(header, payload);

        self.core_tx
            .send(Intercom::Send(packet))
            .expect("failed to send to core");
    }

    async fn build_bouncing_obj(
        &self,
        lobby_id: ChatLobbyId,
        key_id: &KeyId,
    ) -> ChatLobbyBouncingObject {
        let msg_id = nanorand::WyRand::new().generate();
        let nick = {
            self.core
                .get_service_data()
                .gxs_id()
                .get_group_meta(&key_id.to_owned().into())
                .await
                .map_or(String::new(), |details| details.group_name)
        };

        ChatLobbyBouncingObject {
            public_lobby_id: lobby_id,
            msg_id,
            nick: nick.into(),
            signature: Toggleable::new(TlvKeySignature::new(TlvKeySignatureInner::new(
                key_id.to_owned(),
            ))),
        }
    }

    async fn send_lobby_event(
        &self,
        lobby: &Lobby,
        event: ChatLobbyEvent,
        string1: Option<String>,
    ) -> Vec<Packet> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let key_id: KeyId = match lobby.gxs_id {
            Some(id) => id.into(),
            None => {
                warn!("no identity for lobby {}, can't send event", lobby.lobby_name);
                return vec![];
            }
        };

        let bounce_obj = self.build_bouncing_obj(lobby.lobby_id, &key_id).await;
        let mut event = ChatLobbyEventItem {
            event_type: event,
            send_time: now,
            string1: string1.unwrap_or_default().into(),

            bounce_obj,
        };

        let header = ServiceHeader::new(
            self.get_id(),
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT,
            &vec![],
        );
        if !sign_item!(self, event, header) {
            return vec![];
        }

        let payload = to_retroshare_wire(&event);
        let header = ServiceHeader::new(
            self.get_id(),
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT,
            &payload,
        );
        let packet = Packet::new_without_location(header.into(), payload);

        lobby
            .participating_friends
            .iter()
            .map(|(peer, _)| {
                let mut p = packet.to_owned();
                p.peer_id = peer.to_owned();
                p
            })
            .collect()
    }

    async fn keep_alive(&self, lobby: Option<&Lobby>) {
        let data = self.core.get_service_data().chat();
        let lock = data.lobbies.read().await;

        let lobbies: Vec<_> = {
            lock.iter()
                .filter(|(_id, l)| {
                    if let Some(lobby) = lobby {
                        l.lobby_id == lobby.lobby_id
                    } else {
                        l.joined
                    }
                })
                .collect()
        };

        let mut packets = vec![];
        for (_, lobby) in lobbies {
            // let header =
            packets.extend(
                self.send_lobby_event(lobby, ChatLobbyEvent::KeepAlive, None)
                    .await,
            );
        }
        for packet in packets {
            self.core_tx
                .send(Intercom::Send(packet))
                .expect("failed to send to core");
        }
    }

    fn build_lobby_invite(&self, lobby: &Lobby) -> Packet {
        let invite: ChatLobbyInviteItem = lobby.into();
        let payload = to_retroshare_wire(&invite);
        let header = ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_LOBBY_INVITE, &payload);
        Packet::new_without_location(header.into(), payload)
    }

    async fn join_lobby(&self, lobby: ChatLobbyId, gxs_id: Arc<GxsId>) {
        // get lobby
        let mut lock = self.core.get_service_data().chat().lobbies.write().await;
        let mut lobby = {
            match lock.get_mut(&lobby) {
                Some(lobby) => lobby,
                None => {
                    warn!("called join_lobby with unknown lobby id, this is likely a bug!");
                    return;
                }
            }
        };

        info!("joining lobby {}", lobby.lobby_name);

        // update lobby
        lobby.joined = true;
        lobby.gxs_id = Some(*gxs_id);
        *lobby
            .participants
            .entry(gxs_id)
            .or_insert(SystemTime::now()) = SystemTime::now();

        // drop lock and keep a local copy of the lobby
        let lobby = lobby.to_owned();
        drop(lock);

        let packet = self.build_lobby_invite(&lobby);

        for (peer, _) in &lobby.participating_friends {
            let mut p = packet.to_owned();
            p.peer_id = peer.to_owned();
            self.core_tx
                .send(Intercom::Send(p))
                .expect("failed to send");
        }

        // send join event
        for packet in self
            .send_lobby_event(&lobby, ChatLobbyEvent::PeerJoined, None)
            .await
        {
            self.core_tx
                .send(Intercom::Send(packet))
                .expect("failed to send");
        }
    }

    async fn leave_lobby(&self, lobby: &mut Lobby) {
        info!("leaving lobby {}", lobby.lobby_name);

        // send leave event first, it is signed with our lobby identity
        for packet in self
            .send_lobby_event(lobby, ChatLobbyEvent::PeerLeft, None)
            .await
        {
            self.core_tx
                .send(Intercom::Send(packet))
                .expect("failed to send");
        }

        lobby.joined = false;
        if let Some(gxs_id) = lobby.gxs_id.take() {
            lobby.participants.remove(&gxs_id);
        }
    }

    async fn send_message_lobby(&self, lobby: &Lobby, msg: &str) {
        let history_text = msg.to_owned();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let key_id: KeyId = match lobby.gxs_id {
            Some(id) => id.into(),
            None => {
                warn!("no identity for lobby {}, can't send message", lobby.lobby_name);
                return;
            }
        };

        let bounce_obj = self.build_bouncing_obj(lobby.lobby_id, &key_id).await;
        let msg_obj = ChatMsgItem {
            chat_flags: ChatLobbyFlags::LOBBY | ChatLobbyFlags::PRIVATE,
            send_time: now,
            message: msg.into(),
            recv_time: now,
        };
        let mut msg = ChatLobbyMsgItem {
            msg_obj,
            parent_msg_id: 0,
            bounce_obj,
        };

        let header =
            ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG, &vec![]);
        if !sign_item!(self, msg, header) {
            return;
        }

        let payload = to_retroshare_wire(&msg);
        let header =
            ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG, &payload);
        let packet = Packet::new_without_location(header.into(), payload);

        for (peer, _) in &lobby.participating_friends {
            let mut p = packet.to_owned();
            p.peer_id = peer.to_owned();
            self.core_tx
                .send(Intercom::Send(p))
                .expect("failed to send");
        }

        self.core.record_chat(
            HistoryChat::Room(lobby.lobby_id),
            HistoryEntry {
                from: String::new(),
                author: lobby.gxs_id.map(|id| id.to_string()).unwrap_or_default(),
                text: history_text,
                time: now,
                incoming: false,
            },
        );
    }

    /// Private (one-to-one) message to a directly connected friend.
    fn send_message_private(&self, peer: PeerId, msg: &str) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let item = ChatMsgItem {
            chat_flags: ChatLobbyFlags::PRIVATE,
            send_time: now,
            message: msg.into(),
            recv_time: now,
        };
        let payload = to_retroshare_wire(&item);
        let header = ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_DEFAULT, &payload);
        let packet = Packet::new(header.into(), payload, Arc::new(peer));
        self.core_tx
            .send(Intercom::Send(packet))
            .expect("failed to send to core");

        self.core.record_chat(
            HistoryChat::Private(peer.to_string()),
            HistoryEntry {
                from: String::new(),
                author: String::new(),
                text: msg.to_owned(),
                time: now,
                incoming: false,
            },
        );
    }

    fn save_joined_lobbies(&self) {
        let lobbies: Vec<SavedLobby> = self
            .auto_join
            .lock()
            .expect("lock poisoned")
            .iter()
            .map(|(id, gxs_id)| SavedLobby {
                id: id.to_string(),
                gxs_id: gxs_id.to_string(),
            })
            .collect();
        match serde_json::to_string_pretty(&SavedLobbies { lobbies }) {
            Ok(json) => {
                if let Err(err) = std::fs::write(&self.lobbies_file, json) {
                    warn!("can't save joined lobbies: {err}");
                }
            }
            Err(err) => warn!("can't save joined lobbies: {err}"),
        }
    }

    async fn handle_cmd(&self, msg: ChatCmd) {
        let data = self.core.get_service_data().chat();

        match msg {
            ChatCmd::JoinLobby(lobby, gxs_id) => {
                info!("Joining lobby {lobby:?}");

                let gxs_id = Arc::new(gxs_id);

                // let mut lock = data.lobbies.write().await;
                // if let Some(lobby) = lock.get_mut(&lobby) {
                //     self.join_lobby(lobby, gxs_id);
                // }
                if !data.lobbies.read().await.contains_key(&lobby) {
                    warn!("cannot join lobby {lobby}, it is unknown");
                    return;
                }
                // lobby exists and lock is dropped
                self.join_lobby(lobby, gxs_id.clone()).await;

                // remember it for the next start
                self.auto_join
                    .lock()
                    .expect("lock poisoned")
                    .insert(lobby, *gxs_id);
                self.save_joined_lobbies();
            }
            ChatCmd::LeaveLobby(lobby) => {
                info!("leaving lobby {lobby:?}");

                self.auto_join.lock().expect("lock poisoned").remove(&lobby);
                self.save_joined_lobbies();

                let mut lock = data.lobbies.write().await;
                if let Some(lobby) = lock.get_mut(&lobby) {
                    self.leave_lobby(lobby).await;
                }
            }
            ChatCmd::SendMessage(lobby_id, msg) => {
                info!("SendMessage: msg {msg} to {lobby_id:?}");

                match lobby_id.ty {
                    ChatIdType::TypeLobby => {
                        // get lobby but don't hold the lock, tbd if this is useful
                        let lobby = if let Some(lobby) =
                            data.lobbies.read().await.get(&lobby_id.lobby_id.into())
                        {
                            lobby.to_owned()
                        } else {
                            return;
                        };

                        if !lobby.joined {
                            warn!("trying to send message to unjoined lobby! {lobby:?}");
                            return;
                        }

                        self.send_message_lobby(&lobby, &msg).await;
                    }
                    ChatIdType::TypePrivate => {
                        let peer: PeerId = *lobby_id.peer_id;
                        self.send_message_private(peer, &msg);
                    }
                    _ => warn!("chat type {:?} is not supported", lobby_id.ty),
                }
            }
        }
    }

    fn filter_time(&self, send_time: u32) -> bool {
        let send_time = send_time as i128;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i128;

        debug!("now: {now}, send_time: {send_time}");

        // simply copy RS for now
        if now + 100 > send_time + CHAT_MAX_KEEP_MSG_RECORD.as_secs() as i128 {
            warn!(
                "Received severely outdated lobby event item ({} seconds in the past)! Dropping it!",
                now - send_time
            );
            return false;
        }
        if now + 600 < send_time {
            warn!(
                "Received event item from the future ({} seconds in the future)! Dropping it!",
                now - send_time
            );
            return false;
        }

        true
    }

    async fn filter_bouncing_obj(&self, bounce_obj: &ChatLobbyBouncingObject) -> bool {
        let data = self.core.get_service_data().chat();
        let mut lock = data.lobbies.write().await;

        match lock.entry(bounce_obj.public_lobby_id) {
            Entry::Occupied(mut entry) => {
                // now check cache
                match entry.get_mut().msg_cache.entry(bounce_obj.msg_id) {
                    Entry::Occupied(mut entry) => {
                        *entry.get_mut() = SystemTime::now();
                        false
                    }
                    Entry::Vacant(entry) => {
                        _ = entry.insert(SystemTime::now());
                        true
                    }
                }
            }
            Entry::Vacant(_entry) => {
                // no corresponding lobby found, dropping
                warn!(
                    "received chat message for unknown lobby {}, dropping",
                    bounce_obj.public_lobby_id
                );

                // trigger lobby request
                self.request_lobbies();

                false
            }
        }
    }

    async fn filter_event(&self, event: &ChatLobbyEventItem) -> bool {
        if !self.filter_time(event.send_time) {
            return false;
        }

        // TODO reputation

        // check cache
        self.filter_bouncing_obj(&event.bounce_obj).await
    }

    async fn filter_message(&self, msg: &ChatLobbyMsgItem) -> bool {
        if !self.filter_time(msg.msg_obj.send_time) {
            return false;
        }
        // TODO reputation

        // check cache
        self.filter_bouncing_obj(&msg.bounce_obj).await
    }

    async fn generate_lobby_challenge(&self, lobby: &Lobby) -> Option<u64> {
        let lobby_id = lobby.lobby_id;
        let msg_id = {
            let limit = SystemTime::now()
                .checked_sub(CONNECTION_CHALLENGE_MAX_MSG_AGE)
                .unwrap();
            lobby
                .msg_cache
                .iter()
                .find(|(_, &ts)| ts > limit)
                .map(|(msg_id, _)| msg_id)
        }?;

        Some(self.calculate_lobby_challenge(&lobby_id, msg_id))
    }

    fn calculate_lobby_challenge(&self, lobby_id: &ChatLobbyId, msg_id: &u64) -> u64 {
        let peer_id = self.core.get_own_location().get_location_id();

        let mut state = 0u64;

        for b in peer_id.to_vec() {
            // state += msg_id;
            // state ^= state >> 35;
            // state += state << 6;
            // state ^= b as u64 * lobby_id;
            // state += state << 26;
            // state ^= state >> 13;
            state = state.wrapping_add(*msg_id);
            state ^= state >> 35;
            state = state.wrapping_add(state << 6);
            state ^= (b as u64).wrapping_mul(*lobby_id);
            state = state.wrapping_add(state << 26);
            state ^= state >> 13;
        }
        state
    }

    async fn verify_message(&self, key_id: &GxsId, data_signed: &[u8], signature: &[u8]) -> bool {
        // get keys
        let key = match self
            .core
            .get_service_data()
            .gxs_id()
            .get_pub_keys_by_id(&key_id)
            .await
        {
            Some(key) => key,
            None => {
                // this can be common (and thus quite noisy)
                info!("failed to find key for {key_id}");
                return false;
            }
        };

        // assert!((key.key_flags & 0x40) > 0);
        assert!(
            key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN),
            "key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN): {key:?}"
        );

        match verify_signature(&key, data_signed, signature) {
            Ok(true) => {
                trace!("successfully verified message");
                true
            }
            Ok(false) => {
                warn!("failed to verified message");
                false
            }
            Err(err) => {
                warn!("failed to verify: {err:#}");
                false
            }
        }
    }

    async fn sign_message(&self, key_id: &GxsId, data_to_sign: &[u8]) -> Option<Vec<u8>> {
        // get keys
        let key = match self
            .core
            .get_service_data()
            .gxs_id()
            .get_priv_keys_by_id(&key_id)
            .await
        {
            Some(key) => key,
            None => {
                // we miss out own key?!
                warn!("failed to find key for {key_id}");
                return None;
            }
        };

        // assert!((key.key_flags & 0x02) > 0);
        assert!(
            key.key_flags.contains(TlvKeyFlags::TYPE_FULL),
            "key.key_flags.contains(TlvKeyFlags::TYPE_FULL): {key:?}"
        );

        let res = match generate_signature(&key, data_to_sign) {
            Ok(signature) => Some(signature),
            Err(err) => {
                warn!("failed to sign: {err:#}");
                None
            }
        };

        if let Some(signature) = &res {
            if !self.verify_message(&key_id, data_to_sign, &signature).await {
                log::error!("signed message does not pass validation!");
            }
        }

        trace!("successfully signed message");

        res
    }
}

#[async_trait]
impl Service for Chat {
    fn get_id(&self) -> ServiceType {
        ServiceType::Chat
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "chat")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");

                            match msg {
                                Intercom::Receive(packet) =>
                                    self.handle_incoming(&packet.header.to_owned().into(), packet).await,
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        }
                    }
                    command = self.cmd_rx.recv() => {
                        if let Some(command) = command {
                            self.handle_cmd(command).await;
                        }
                    }
                    _ = self.timer_lobby_keep_alive.tick() => {
                        trace!("keep alive");

                        self.keep_alive(None).await
                    }
                    _ = self.timer_lobby_maintenance.tick() => {
                        trace!("maintaining lobbies");
                        self.core.flush_chat_history();

                        let mut lock = self.core.get_service_data().chat().lobbies.write().await;

                        // trigger cleanup
                        lock.iter_mut()
                            .for_each(|(_, lobby)| lobby.maintain_lobby());

                        // gen challenges
                        for (_id, lobby) in &mut *lock {
                            if let Some(challenge_code) = self.generate_lobby_challenge(lobby).await {
                                let item = ChatLobbyConnectChallengeItem { challenge_code };
                                let payload = to_retroshare_wire(&item);
                                let header = ServiceHeader::new(
                                    self.get_id(),
                                    CHAT_SUB_TYPE_CHAT_LOBBY_CHALLENGE,
                                    &payload,
                                );
                                let packet = Packet::new_without_location(header.into(), payload);

                                self.core_tx.send(Intercom::Send(packet)).expect("failed to send to core");
                            }
                        }
                    }
                    _ = self.timer_lobby_request.tick() => {
                        trace!("requesting lobbies");

                        self.request_lobbies();
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod test_chat {
    use retroshare_compat::{
        basics::PeerId,
        services::chat::{ChatLobbyId, ChatLobbyMsgId},
    };

    fn calculate_lobby_challenge(lobby_id: &ChatLobbyId, msg_id: &u64, peer_id: &PeerId) -> u64 {
        let mut state = 0u64;

        for b in peer_id.to_vec() {
            state = state.wrapping_add(*msg_id);
            state ^= state >> 35;
            state = state.wrapping_add(state << 6);
            state ^= (b as u64).wrapping_mul(*lobby_id);
            state = state.wrapping_add(state << 26);
            state ^= state >> 13;
        }
        state
    }

    #[test]
    fn test_lobby_challenge() {
        let sets: Vec<(PeerId, ChatLobbyId, ChatLobbyMsgId, u64)> = vec![
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            // the following are from Xeres
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                140257447151802099,
                1540395435043678632,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                3128845210392038968,
                9133905927926710723,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                15552989625937603562,
                2213486716447545487,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                140257447151802099,
                1540395435043678632,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                3128845210392038968,
                9133905927926710723,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                15552989625937603562,
                2213486716447545487,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                140257447151802099,
                1540395435043678632,
            ),
        ];

        for (peer_id, lobby_id, msg_id, result) in sets {
            assert_eq!(
                calculate_lobby_challenge(&lobby_id, &msg_id, &peer_id),
                result
            );
        }
    }
}
