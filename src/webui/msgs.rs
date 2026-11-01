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
    webui::RetVal,
};

// rsMsgs/getChatLobbyList
// /**
//  * @brief getChatLobbyList get ids of subscribed lobbies
//  * @jsonapi{development}
//  * @param[out] cl_list lobby list
//  */
//  virtual void getChatLobbyList(std::list<ChatLobbyId> &cl_list) = 0;
gen_webui_return_type!(GetChatLobbyList, cl_list, Vec<XInt64<u64>>);
#[post("/getChatLobbyList")]
pub async fn rs_msgs_get_chat_lobby_list(
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

// rsMsgs/getListOfNearbyChatLobbies
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
pub async fn rs_msgs_get_list_of_nearby_chat_lobbies(
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

// rsMsgs/getChatLobbyInfo
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
pub async fn rs_msgs_get_chat_lobby_info(
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

// rsmsgs/sendChat
// /*!
//  * Send a chat message.
//  * @param destination where to send the chat message
//  * @param msg the message
//  * @see ChatId
//  */
// virtual bool sendChat(ChatId destination, std::string msg) override ;
gen_webui_param_type!(MsgsSendChat, id: ChatId, msg: String);
#[post("/sendChat")]
pub async fn rs_msgs_send_chat(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<MsgsSendChat>,
) -> Result<impl Responder> {
    let id = params.0.id;
    let msg = params.0.msg;

    let lock = state.get_service_data().chat().cmd.read().await;
    match &*lock {
        Some(tx) => _ = tx.send(ChatCmd::SendMessage(id, msg)),
        None => return Ok(web::Json(RetVal { retval: false })),
    }

    Ok(web::Json(RetVal { retval: true }))
}

// rsMsgs/joinVisibleChatLobby
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
pub async fn rs_msgs_join_visible_chat_lobby(
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

// rsMsgs/unsubscribeChatLobby
// /**
//  * @brief unsubscribeChatLobby leave a chat lobby
//  * @jsonapi{development}
//  * @param[in] lobby_id lobby to leave
//  */
//  virtual void unsubscribeChatLobby(const ChatLobbyId &lobby_id) = 0;
gen_webui_param_type!(UnsubscribeChatLobby, lobby_id: ChatLobbyId);
#[post("/unsubscribeChatLobby")]
pub async fn rs_msgs_unsubscribe_chat_lobby(
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

// rsMsgs/getLobbyParticipants (rustyshare specific): participants with nicknames
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
pub async fn rs_msgs_get_lobby_participants(
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

// rsMsgs/getChatHistory (rustyshare specific): stored messages of all chats,
// {"retval": true, "chats": [{"room_id": "...", "peer_id": "...", "messages": [...]}]}
#[derive(serde::Serialize)]
pub struct ChatHistoryResult {
    retval: bool,
    chats: Vec<crate::history::HistoryChatOut>,
}
#[post("/getChatHistory")]
pub async fn rs_msgs_get_chat_history(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    Ok(web::Json(ChatHistoryResult {
        retval: true,
        chats: state.get_chat_history(),
    }))
}

// rsMsgs/getCustomStateString, rsMsgs/getOwnCustomStateString, rsMsgs/setCustomStateString
// (status messages, see presence.rs)
//  virtual std::string getCustomStateString(const RsPeerId& peer_id) = 0;
//  virtual std::string getOwnCustomStateString() = 0;
//  virtual void setCustomStateString(const std::string& status_string) = 0;
#[derive(serde::Deserialize)]
pub struct CustomStateParam {
    peer_id: String,
}
#[post("/getCustomStateString")]
pub async fn rs_msgs_get_custom_state_string(
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
pub async fn rs_msgs_get_own_custom_state_string(
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
pub async fn rs_msgs_set_custom_state_string(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetCustomStateParam>,
) -> Result<impl Responder> {
    state.set_own_status_message(&params.status_string).await;
    Ok(web::Json(RetVal { retval: true }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsMsgs")
        .service(rs_msgs_get_chat_lobby_list)
        .service(rs_msgs_get_list_of_nearby_chat_lobbies)
        .service(rs_msgs_get_chat_lobby_info)
        .service(rs_msgs_send_chat)
        .service(rs_msgs_join_visible_chat_lobby)
        .service(rs_msgs_unsubscribe_chat_lobby)
        .service(rs_msgs_get_lobby_participants)
        .service(rs_msgs_get_chat_history)
        .service(rs_msgs_get_custom_state_string)
        .service(rs_msgs_get_own_custom_state_string)
        .service(rs_msgs_set_custom_state_string)
}
