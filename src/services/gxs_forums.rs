//! GXS forums service (0x0215): forum groups (and later posts) synced through the
//! generic GXS backend, like identities.

use std::sync::Arc;

use std::panic::AssertUnwindSafe;

use async_trait::async_trait;
use futures::FutureExt;
use log::{trace, warn};
use retroshare_compat::{
    gxs::sqlite::database::GxsDatabase,
    services::{service_info::RsServiceInfo, SERVICE_GXS_FORUMS},
};
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::{
    gxs::{gxs_backend::{GxsBackend, GxsShared}, nxs::NxsTransactionController},
    low_level_parsing::Packet,
    model::{intercom::Intercom, DataCore},
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

pub struct GxsForums {
    rx: UnboundedReceiver<Intercom>,
    backend: GxsBackend<SERVICE_GXS_FORUMS>,
}

impl GxsForums {
    pub async fn new(
        core: &Arc<DataCore>,
        _core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,

        (db, shared): (GxsDatabase, Arc<GxsShared>),
    ) -> Self {
        let nxs = NxsTransactionController::new(shared.to_owned());
        let backend = GxsBackend::new(core.to_owned(), db, nxs, shared.to_owned());

        GxsForums { rx, backend }
    }

    async fn handle_incoming(&self, packet: Packet) {
        self.backend.handle_packet(packet).await;
    }
}

#[async_trait]
impl Service for GxsForums {
    fn get_id(&self) -> ServiceType {
        ServiceType::Forums
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "gxsforums")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");

                            match msg {
                                Intercom::Receive(packet) => {
                                    // a bug in one packet must not stop the whole service
                                    if let Err(err) = AssertUnwindSafe(self.handle_incoming(packet)).catch_unwind().await {
                                        log::error!("[gxs_forums] handling a packet panicked: {}, service keeps running", crate::log_internal::panic_text(err.as_ref()));
                                    }
                                }
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        }
                    }
                    res = AssertUnwindSafe(self.backend.run()).catch_unwind() => {
                        match res {
                            Ok(()) => {
                                log::error!("gxs backend stopped");
                                panic!();
                            }
                            // the panic hook logged where; keep the service alive,
                            // run() starts again in the next round of the loop
                            Err(err) => log::error!("[gxs_forums] gxs backend panicked: {}, service keeps running", crate::log_internal::panic_text(err.as_ref())),
                        }
                    }
                }
            }
        })
    }
}
