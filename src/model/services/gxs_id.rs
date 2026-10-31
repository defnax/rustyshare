use std::{sync::Arc, time::Duration};

use log::warn;
use retroshare_compat::{
    basics::{GxsGroupId, GxsId},
    gxs::sqlite::{database::StoredMsg, types::GxsGroup},
    tlv::tlv_keys::{TlvKeyFlags, TlvPrivateRSAKey, TlvPublicRSAKey},
};
use tokio::sync::oneshot;

use crate::gxs::{gxs_backend::{GxsItemsWrapper, GxsShared}};

use super::AppRequest;

pub struct GxsIdStore {
    shared: Arc<GxsShared>,
}

impl GxsIdStore {
    pub fn new(shared: Arc<GxsShared>) -> Self {
        Self { shared }
    }

    pub async fn get_group_meta_all(&self) -> Vec<GxsGroup> {
        match self
            .handle_request(GxsItemsWrapper::GxsGroupIdsAll, Duration::from_millis(3000))
            .await
        {
            Some(groups) => groups,
            None => {
                warn!("request for all ids timed out");
                vec![]
            }
        }
    }

    // TODO support multiple ?
    pub async fn get_group_meta(&self, group_id: &GxsGroupId) -> Option<GxsGroup> {
        match self
            .handle_request(
                GxsItemsWrapper::GxsGroupIds(vec![group_id.to_owned()]),
                Duration::from_millis(1000),
            )
            .await
        {
            Some(groups) => groups.into_iter().nth(0),
            None => None,
        }
    }

    /// Messages (posts) of a group.
    pub async fn get_messages(&self, group_id: &GxsGroupId) -> Vec<StoredMsg> {
        match self
            .raw_request(GxsItemsWrapper::MsgsOfGroup(group_id.to_owned()), Duration::from_millis(5000))
            .await
        {
            Some(GxsItemsWrapper::Msgs(msgs)) => msgs,
            _ => vec![],
        }
    }

    /// Subscribe to / unsubscribe from a group.
    pub async fn subscribe(&self, group_id: &GxsGroupId, subscribe: bool) -> bool {
        self.raw_request(
            GxsItemsWrapper::Subscribe(group_id.to_owned(), subscribe),
            Duration::from_millis(3000),
        )
        .await
        .is_some()
    }

    /// Marks messages as verified (1) or deletes them (-1).
    pub async fn set_message_status(&self, list: Vec<(String, i64)>) {
        if !list.is_empty() {
            self.raw_request(GxsItemsWrapper::MsgStatus(list), Duration::from_millis(3000))
                .await;
        }
    }

    async fn raw_request(&self, request: GxsItemsWrapper, timeout: Duration) -> Option<GxsItemsWrapper> {
        let (tx, rx) = oneshot::channel();
        self.shared.requests.add_request(AppRequest { ty: request, tx });
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(resp)) => Some(resp),
            _ => None,
        }
    }

    /// One group including its data.
    pub async fn get_group_with_data(&self, group_id: &GxsGroupId) -> Option<GxsGroup> {
        self.handle_request(
            GxsItemsWrapper::GxsGroupWithData(group_id.to_owned()),
            Duration::from_millis(2000),
        )
        .await
        .and_then(|groups| groups.into_iter().nth(0))
    }

    /// Stores a newly created own group (identity) permanently.
    pub async fn store_new_group(&self, group: GxsGroup) -> Option<GxsGroup> {
        self.handle_request(GxsItemsWrapper::GxsGroups(vec![group]), Duration::from_millis(5000))
            .await
            .and_then(|groups| groups.into_iter().nth(0))
    }

    async fn handle_request(
        &self,
        request: GxsItemsWrapper,
        timeout: Duration,
    ) -> Option<Vec<GxsGroup>> {
        let (tx, rx) = oneshot::channel();

        let req = AppRequest { ty: request, tx };

        // TODO this should be handled with a queue to avoid polling
        self.shared.requests.add_request(req);

        // TODO tune this!
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(GxsItemsWrapper::GxsGroups(groups))) => Some(groups),
            Ok(_) | Err(_) => None,
        }
    }

    pub async fn get_pub_keys_by_id(&self, group_id: &GxsId) -> Option<TlvPublicRSAKey> {
        let group_id = group_id.to_owned().into();
        let mut group = self.get_group_meta(&group_id).await?;

        // filter out the key we need (TODO consider DISTRIBUTE_PUBLISH)
        group
            .keys
            .public_keys
            .retain(|key| key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN));

        assert!(
            group.keys.public_keys.len() <= 1,
            "group.keys.public_keys.len() <= 1: {:?}",
            group.keys.public_keys
        );
        group.keys.public_keys.into_iter().nth(0)
    }

    pub async fn get_priv_keys_by_id(&self, group_id: &GxsId) -> Option<TlvPrivateRSAKey> {
        let group_id = group_id.to_owned().into();
        let mut group = self.get_group_meta(&group_id).await?;

        // filter out the key we need (TODO consider DISTRIBUTE_PUBLISH)
        group
            .keys
            .private_keys
            .retain(|key| key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN));

        assert!(
            group.keys.private_keys.len() <= 1,
            "group.keys.private_keys.len() <= 1: {:?}",
            group.keys.private_keys
        );
        group.keys.private_keys.into_iter().nth(0)
    }
}
