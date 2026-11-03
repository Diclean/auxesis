//! The local macOS notification channel, behind the [`Gateway`] trait.
//!
//! It is the router's fallback: when no remote channel is paired, briefs and
//! alerts still reach the owner on this Mac instead of being logged as
//! undelivered. It uses the existing local-notification egress row (C10), so
//! private mode still holds it.

use std::sync::Arc;

use async_trait::async_trait;
use aux_notify::{Notification, Notifier};
use kernel_core::privacy::{Destination, PathId};

use super::{
    ApprovalCard, Capabilities, ChatId, Gateway, GatewayError, InboundText, OutboundText, OwnerId,
};

/// Wraps the existing aux-notify sink.
pub struct LocalGateway {
    notifier: Arc<dyn Notifier>,
}

impl LocalGateway {
    /// A gateway over `notifier`.
    pub fn new(notifier: Arc<dyn Notifier>) -> Self {
        Self { notifier }
    }
}

#[async_trait]
impl Gateway for LocalGateway {
    fn id(&self) -> &'static str {
        "local"
    }

    fn egress_path(&self) -> PathId {
        PathId::C10
    }

    fn destination(&self) -> Destination {
        Destination::LocalDisplay
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            text: true,
            approvals: false,
            brief: true,
            read_receipts: false,
            calls: false,
        }
    }

    fn owner(&self) -> Option<OwnerId> {
        None
    }

    fn is_paired_owner(&self, _sender: OwnerId, _chat: ChatId) -> bool {
        false
    }

    async fn send(&self, outbound: &OutboundText) -> Result<(), GatewayError> {
        // The brief text is "title\nbody"; the first line is the headline.
        let (title, body) = match outbound.text().split_once('\n') {
            Some((title, body)) => (title.to_string(), body.to_string()),
            None => ("Auxesis".to_string(), outbound.text().to_string()),
        };
        self.notifier
            .notify(&Notification::new(title, body))
            .map_err(|_| GatewayError::Send(super::SendCause::Transport))
    }

    async fn deliver_approval(&self, _card: &ApprovalCard) -> Result<(), GatewayError> {
        // The local display has no buttons.
        Err(GatewayError::Disabled)
    }

    async fn deliver_brief(&self, brief: &OutboundText) -> Result<(), GatewayError> {
        self.send(brief).await
    }

    async fn next_inbound(&self) -> Option<InboundText> {
        None
    }
}
