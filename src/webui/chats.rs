//! rsChats: chat rooms, private chat and status messages, like RetroShare's
//! `retroshare/rschats.h` (RetroShare moved chat out of rsMsgs, which keeps mail).

use std::sync::Arc;

use actix_web::{post, web, Responder, Result};
use retroshare_compat::{
    basics::GxsIdHex,
    services::chat::{ChatId, ChatLobbyId},
    webui::{
        chat::{ChatLobbyIdWrapped, ChatLobbyInfo, VisibleChatLobbyRecord},
        XInt64,
    },
};

use crate::{
    gen_webui_param_type, gen_webui_return_type,
    model::{services::chat::ChatCmd, DataCore},
    services::gxs_tunnel,
    webui::RetVal,
};

// rsChats/getChatLobbyList
// /**
//  * @brief getChatLobbyList get ids of subscribed lobbies
//  * @jsonapi{development}
//  * @param[out] cl_list lobby list
//  */
//  virtual void getChatLobbyList(std::list<ChatLobbyId> &cl_list) = 0;
gen_webui_return_type!(GetChatLobbyList, cl_list, Vec<XInt64<u64>>);
#[post("/getChatLobbyList")]
pub async fn rs_chats_get_chat_lobby_list(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    let chat_lobby_list = state
        .get_service_data()
        .chat()
        .lobbies
        .read()
        .await
        .iter()
        .filter_map(|(&id, lobby)| if lobby.joined { Some(id.into()) } else { None })
        .collect();

    Ok(web::Json(GetChatLobbyList {
        retval: true,
        cl_list: chat_lobby_list,
    }))
}

// rsChats/getListOfNearbyChatLobbies
// /**
//  * @brief getListOfNearbyChatLobbies get info about all lobbies, subscribed and unsubscribed
//  * @jsonapi{development}
//  * @param[out] public_lobbies list of all visible lobbies
//  */
//  virtual void getListOfNearbyChatLobbies(std::vector<VisibleChatLobbyRecord> &public_lobbies) = 0 ;
gen_webui_return_type!(
    GetListOfNearbyChatLobbies,
    public_lobbies,
    Vec<VisibleChatLobbyRecord>
);
#[post("/getListOfNearbyChatLobbies")]
pub async fn rs_chats_get_list_of_nearby_chat_lobbies(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    let public_lobbies = state
        .get_service_data()
        .chat()
        .lobbies
        .read()
        .await
        .iter()
        .map(|(_, lobby)| lobby.into())
        .collect();

    Ok(web::Json(GetListOfNearbyChatLobbies {
        retval: true,
        public_lobbies,
    }))
}

// rsChats/getChatLobbyInfo
// /**
//  * @brief getChatLobbyInfo get lobby info of a subscribed chat lobby. Returns true if lobby id is valid.
//  * @jsonapi{development}
//  * @param[in] id id to get infos from
//  * @param[out] info lobby infos
//  * @return true on success
//  */
//  virtual bool getChatLobbyInfo(const ChatLobbyId &id, ChatLobbyInfo &info) = 0 ;
gen_webui_return_type!(GetChatLobbyInfo, info, Option<ChatLobbyInfo>);
#[post("/getChatLobbyInfo")]
pub async fn rs_chats_get_chat_lobby_info(
    state: web::Data<Arc<DataCore>>,
    id: web::Json<ChatLobbyIdWrapped>,
) -> Result<impl Responder> {
    match state
        .get_service_data()
        .chat()
        .lobbies
        .read()
        .await
        .get(&id.0.into())
    {
        Some(info) => Ok(web::Json(GetChatLobbyInfo {
            retval: true,
            info: Some(info.into()),
        })),
        None => Ok(web::Json(GetChatLobbyInfo {
            retval: false,
            info: None,
        })),
    }
}

// rsChats/sendChat
// /*!
//  * Send a chat message.
//  * @param destination where to send the chat message
//  * @param msg the message
//  * @see ChatId
//  */
// virtual bool sendChat(ChatId destination, std::string msg) override ;
gen_webui_param_type!(MsgsSendChat, id: ChatId, msg: String);
#[post("/sendChat")]
pub async fn rs_chats_send_chat(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<MsgsSendChat>,
) -> Result<impl Responder> {
    let id = params.0.id;
    let msg = params.0.msg;

    // distant chat: through the GXS tunnel (turtle service)
    if matches!(id.ty, retroshare_compat::services::chat::ChatIdType::TypePrivateDistant) {
        let tunnel = (*id.distant_chat_id).0;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let ok = gxs_tunnel::command(gxs_tunnel::TunnelCmd::SendChat { tunnel, text: msg, reply: tx })
            && matches!(rx.await, Ok(Ok(())));
        return Ok(web::Json(RetVal { retval: ok }));
    }

    let lock = state.get_service_data().chat().cmd.read().await;
    match &*lock {
        Some(tx) => _ = tx.send(ChatCmd::SendMessage(id, msg)),
        None => return Ok(web::Json(RetVal { retval: false })),
    }

    Ok(web::Json(RetVal { retval: true }))
}

// rsChats/joinVisibleChatLobby
// /**
//  * @brief joinVisibleChatLobby join a lobby that is visible
//  * @jsonapi{development}
//  * @param[in] lobby_id lobby to join to
//  * @param[in] own_id chat id to use
//  * @return true on success
//  */
//  virtual bool joinVisibleChatLobby(const ChatLobbyId &lobby_id, const RsGxsId &own_id) = 0 ;
gen_webui_param_type!(
    JoinVisibleChatLobby,
    lobby_id: ChatLobbyId,
    own_id: GxsIdHex
);
#[post("/joinVisibleChatLobby")]
pub async fn rs_chats_join_visible_chat_lobby(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<JoinVisibleChatLobby>,
) -> Result<impl Responder> {
    let lobby = params.0.lobby_id;
    let gxs_id = *params.0.own_id;

    let lock = state.get_service_data().chat().cmd.read().await;
    match &*lock {
        Some(tx) => _ = tx.send(ChatCmd::JoinLobby(lobby, gxs_id)),
        None => return Ok(web::Json(RetVal { retval: false })),
    }

    Ok(web::Json(RetVal { retval: true }))
}

// rsChats/unsubscribeChatLobby
// /**
//  * @brief unsubscribeChatLobby leave a chat lobby
//  * @jsonapi{development}
//  * @param[in] lobby_id lobby to leave
//  */
//  virtual void unsubscribeChatLobby(const ChatLobbyId &lobby_id) = 0;
gen_webui_param_type!(UnsubscribeChatLobby, lobby_id: ChatLobbyId);
#[post("/unsubscribeChatLobby")]
pub async fn rs_chats_unsubscribe_chat_lobby(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<UnsubscribeChatLobby>,
) -> Result<impl Responder> {
    let lobby = params.0.lobby_id;

    let lock = state.get_service_data().chat().cmd.read().await;
    match &*lock {
        Some(tx) => _ = tx.send(ChatCmd::LeaveLobby(lobby)),
        None => return Ok(web::Json(RetVal { retval: false })),
    }

    Ok(web::Json(RetVal { retval: true }))
}

// rsChats/getLobbyParticipants (rustyshare specific): participants with nicknames
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LobbyParticipant {
    id: String,
    nick: String,
    /// seconds since the last sign of life (keep alive, message)
    last_seen: u64,
}
#[derive(serde::Serialize)]
pub struct LobbyParticipants {
    retval: bool,
    participants: Vec<LobbyParticipant>,
}
#[post("/getLobbyParticipants")]
pub async fn rs_chats_get_lobby_participants(
    state: web::Data<Arc<DataCore>>,
    id: web::Json<ChatLobbyIdWrapped>,
) -> Result<impl Responder> {
    let chat = state.get_service_data().chat();
    let lobby_id: ChatLobbyId = id.0.into();
    let participants = match chat.lobbies.read().await.get(&lobby_id) {
        Some(lobby) => {
            let nicks = chat.nicknames.read().expect("lock poisoned");
            let mut list: Vec<_> = lobby
                .participants
                .iter()
                .map(|(gxs_id, seen)| LobbyParticipant {
                    id: gxs_id.to_string(),
                    nick: nicks.get(&**gxs_id).cloned().unwrap_or_default(),
                    last_seen: seen.elapsed().map(|d| d.as_secs()).unwrap_or(0),
                })
                .collect();
            list.sort_by(|a, b| a.nick.to_lowercase().cmp(&b.nick.to_lowercase()));
            list
        }
        None => vec![],
    };
    Ok(web::Json(LobbyParticipants {
        retval: true,
        participants,
    }))
}

// rsChats/getChatHistory (rustyshare specific): stored messages of all chats,
// {"retval": true, "chats": [{"room_id": "...", "peer_id": "...", "messages": [...]}]}
#[derive(serde::Serialize)]
pub struct ChatHistoryResult {
    retval: bool,
    chats: Vec<crate::history::HistoryChatOut>,
}
#[post("/getChatHistory")]
pub async fn rs_chats_get_chat_history(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    Ok(web::Json(ChatHistoryResult {
        retval: true,
        chats: state.get_chat_history(),
    }))
}

// rsChats/getCustomStateString, rsChats/getOwnCustomStateString, rsChats/setCustomStateString
// (status messages, see presence.rs)
//  virtual std::string getCustomStateString(const RsPeerId& peer_id) = 0;
//  virtual std::string getOwnCustomStateString() = 0;
//  virtual void setCustomStateString(const std::string& status_string) = 0;
#[derive(serde::Deserialize)]
pub struct CustomStateParam {
    peer_id: String,
}
#[post("/getCustomStateString")]
pub async fn rs_chats_get_custom_state_string(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CustomStateParam>,
) -> Result<impl Responder> {
    let id = params.peer_id.trim().to_lowercase();
    let message = if id == state.get_own_location().get_location_id().to_string() {
        state.own_presence().message
    } else {
        state.presence_of_peer(&id).message
    };
    Ok(web::Json(RetVal { retval: message }))
}

#[post("/getOwnCustomStateString")]
pub async fn rs_chats_get_own_custom_state_string(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    Ok(web::Json(RetVal {
        retval: state.own_presence().message,
    }))
}

#[derive(serde::Deserialize)]
pub struct SetCustomStateParam {
    status_string: String,
}
#[post("/setCustomStateString")]
pub async fn rs_chats_set_custom_state_string(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetCustomStateParam>,
) -> Result<impl Responder> {
    state.set_own_status_message(&params.status_string).await;
    Ok(web::Json(RetVal { retval: true }))
}

// rsChats/invitePeerToLobby, getPendingChatLobbyInvites, acceptLobbyInvite,
// denyLobbyInvite (room invitations, like retroshare/rschats.h)
//  virtual void invitePeerToLobby(const ChatLobbyId &lobby_id, const RsPeerId &peer_id) = 0;
#[derive(serde::Deserialize)]
pub struct InvitePeerParam {
    lobby_id: ChatLobbyId,
    peer_id: retroshare_compat::basics::SslIdHex,
}
#[post("/invitePeerToLobby")]
pub async fn rs_chats_invite_peer_to_lobby(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<InvitePeerParam>,
) -> Result<impl Responder> {
    let lock = state.get_service_data().chat().cmd.read().await;
    let ok = match &*lock {
        Some(tx) => tx
            .send(ChatCmd::InviteFriends(params.lobby_id, vec![*params.peer_id]))
            .is_ok(),
        None => false,
    };
    Ok(web::Json(RetVal { retval: ok }))
}

//  virtual void getPendingChatLobbyInvites(std::list<ChatLobbyInvite> &invites) = 0;
#[derive(serde::Serialize)]
pub struct ChatLobbyInviteOut {
    lobby_id: XInt64<u64>,
    peer_id: String,
    lobby_name: String,
    lobby_topic: String,
    lobby_flags: u32,
}
#[derive(serde::Serialize)]
pub struct PendingInvitesOut {
    retval: bool,
    invites: Vec<ChatLobbyInviteOut>,
}
#[post("/getPendingChatLobbyInvites")]
pub async fn rs_chats_get_pending_chat_lobby_invites(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    let invites = state
        .get_service_data()
        .chat()
        .invites
        .read()
        .expect("lock poisoned")
        .values()
        .map(|i| ChatLobbyInviteOut {
            lobby_id: i.lobby_id.into(),
            peer_id: i.peer_id.to_string(),
            lobby_name: i.lobby_name.to_owned(),
            lobby_topic: i.lobby_topic.to_owned(),
            lobby_flags: i.lobby_flags.bits(),
        })
        .collect();
    Ok(web::Json(PendingInvitesOut {
        retval: true,
        invites,
    }))
}

//  virtual bool acceptLobbyInvite(const ChatLobbyId& id, const RsGxsId& identity) = 0;
#[derive(serde::Deserialize)]
pub struct AcceptInviteParam {
    id: ChatLobbyId,
    identity: GxsIdHex,
}
#[post("/acceptLobbyInvite")]
pub async fn rs_chats_accept_lobby_invite(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<AcceptInviteParam>,
) -> Result<impl Responder> {
    let data = state.get_service_data().chat();
    if !data.invites.read().expect("lock poisoned").contains_key(&params.id) {
        return Ok(web::Json(RetVal { retval: false }));
    }
    let lock = data.cmd.read().await;
    let ok = match &*lock {
        Some(tx) => tx.send(ChatCmd::AcceptInvite(params.id, *params.identity)).is_ok(),
        None => false,
    };
    Ok(web::Json(RetVal { retval: ok }))
}

//  virtual void denyLobbyInvite(const ChatLobbyId& id) = 0;
#[derive(serde::Deserialize)]
pub struct DenyInviteParam {
    id: ChatLobbyId,
}
#[post("/denyLobbyInvite")]
pub async fn rs_chats_deny_lobby_invite(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<DenyInviteParam>,
) -> Result<impl Responder> {
    let removed = state
        .get_service_data()
        .chat()
        .invites
        .write()
        .expect("lock poisoned")
        .remove(&params.id)
        .is_some();
    Ok(web::Json(RetVal { retval: removed }))
}

// --- distant chat (rsChats, like RetroShare's DistantChatService) --------------------

fn tunnel_id(hex_id: &str) -> Option<[u8; 16]> {
    hex::decode(hex_id.trim()).ok()?.try_into().ok()
}
fn gxs_id(hex_id: &str) -> Option<retroshare_compat::basics::GxsId> {
    let b = hex::decode(hex_id.trim()).ok()?;
    (b.len() == 16).then(|| b.into())
}

// rsChats/initiateDistantChatConnexion {to_pid, from_pid, notify}: {retval, pid, error_code}
#[derive(serde::Deserialize)]
pub struct InitiateDistantChat {
    to_pid: String,
    from_pid: String,
}
#[post("/initiateDistantChatConnexion")]
pub async fn rs_chats_initiate_distant_chat(params: web::Json<InitiateDistantChat>) -> Result<impl Responder> {
    let (Some(to), Some(from)) = (gxs_id(&params.to_pid), gxs_id(&params.from_pid)) else {
        return Ok(web::Json(serde_json::json!({ "retval": false, "pid": "", "error_code": 1, "error": "invalid identity" })));
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    if !gxs_tunnel::command(gxs_tunnel::TunnelCmd::OpenChat { to, from, reply: tx }) {
        return Ok(web::Json(serde_json::json!({ "retval": false, "pid": "", "error_code": 1, "error": "the tunnel service isn't running" })));
    }
    Ok(web::Json(match rx.await {
        Ok(Ok(pid)) => serde_json::json!({ "retval": true, "pid": pid, "error_code": 0 }),
        Ok(Err(e)) => serde_json::json!({ "retval": false, "pid": "", "error_code": 1, "error": e }),
        Err(_) => serde_json::json!({ "retval": false, "pid": "", "error_code": 1, "error": "no answer" }),
    }))
}

#[derive(serde::Deserialize)]
pub struct DistantChatPid {
    pid: String,
}
// rsChats/getDistantChatStatus {pid}: {retval, info: {to_id, own_id, peer_id, status, pending_items}}
#[post("/getDistantChatStatus")]
pub async fn rs_chats_get_distant_chat_status(params: web::Json<DistantChatPid>) -> Result<impl Responder> {
    let pid = params.pid.trim().to_lowercase();
    Ok(web::Json(match gxs_tunnel::distant_chats().into_iter().find(|c| c.id == pid) {
        Some(c) => serde_json::json!({ "retval": true, "info": {
            "to_id": c.to_id, "own_id": c.own_id, "peer_id": c.id, "status": c.status, "pending_items": c.pending } }),
        None => serde_json::json!({ "retval": false }),
    }))
}

// rsChats/closeDistantChatConnexion {pid}
#[post("/closeDistantChatConnexion")]
pub async fn rs_chats_close_distant_chat(params: web::Json<DistantChatPid>) -> Result<impl Responder> {
    let Some(tunnel) = tunnel_id(&params.pid) else { return Ok(web::Json(RetVal { retval: false })) };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let ok = gxs_tunnel::command(gxs_tunnel::TunnelCmd::CloseChat { tunnel, reply: tx }) && rx.await.unwrap_or(false);
    Ok(web::Json(RetVal { retval: ok }))
}

// rsChats/getDistantChats (rustyshare): all distant chats with their state
#[post("/getDistantChats")]
pub async fn rs_chats_get_distant_chats() -> Result<impl Responder> {
    Ok(web::Json(serde_json::json!({ "retval": true, "chats": gxs_tunnel::distant_chats() })))
}

// rsChats/forgetDistantChat {pid} (rustyshare): closes it and removes it from the list
#[post("/forgetDistantChat")]
pub async fn rs_chats_forget_distant_chat(params: web::Json<DistantChatPid>) -> Result<impl Responder> {
    let Some(tunnel) = tunnel_id(&params.pid) else { return Ok(web::Json(RetVal { retval: false })) };
    Ok(web::Json(RetVal { retval: gxs_tunnel::command(gxs_tunnel::TunnelCmd::Forget(tunnel)) }))
}

// rsChats/getDistantChatPermissionFlags, setDistantChatPermissionFlags {flags}:
// 0 everybody, 1 contacts only, 2 nobody (RS_DISTANT_CHAT_CONTACT_PERMISSION_FLAG_*)
#[post("/getDistantChatPermissionFlags")]
pub async fn rs_chats_get_distant_chat_permission() -> Result<impl Responder> {
    Ok(web::Json(RetVal { retval: gxs_tunnel::permission() }))
}
#[derive(serde::Deserialize)]
pub struct PermissionFlags {
    flags: u32,
}
#[post("/setDistantChatPermissionFlags")]
pub async fn rs_chats_set_distant_chat_permission(params: web::Json<PermissionFlags>) -> Result<impl Responder> {
    Ok(web::Json(RetVal { retval: gxs_tunnel::command(gxs_tunnel::TunnelCmd::SetPermission(params.flags)) }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsChats")
        .service(rs_chats_get_chat_lobby_list)
        .service(rs_chats_get_list_of_nearby_chat_lobbies)
        .service(rs_chats_get_chat_lobby_info)
        .service(rs_chats_send_chat)
        .service(rs_chats_join_visible_chat_lobby)
        .service(rs_chats_unsubscribe_chat_lobby)
        .service(rs_chats_get_lobby_participants)
        .service(rs_chats_get_chat_history)
        .service(rs_chats_get_custom_state_string)
        .service(rs_chats_get_own_custom_state_string)
        .service(rs_chats_set_custom_state_string)
        .service(rs_chats_invite_peer_to_lobby)
        .service(rs_chats_get_pending_chat_lobby_invites)
        .service(rs_chats_accept_lobby_invite)
        .service(rs_chats_deny_lobby_invite)
        .service(rs_chats_initiate_distant_chat)
        .service(rs_chats_get_distant_chat_status)
        .service(rs_chats_close_distant_chat)
        .service(rs_chats_get_distant_chats)
        .service(rs_chats_forget_distant_chat)
        .service(rs_chats_get_distant_chat_permission)
        .service(rs_chats_set_distant_chat_permission)
}
