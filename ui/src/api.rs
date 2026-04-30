use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::OnceLock};

#[cfg(feature = "use-node")]
use dioxus::prelude::{ReadableExt, Signal, WritableExt};
use freenet_aft_interface::{TokenAllocationSummary, TokenDelegateMessage};
use freenet_stdlib::client_api::{ClientError, ClientRequest, HostResponse};
use futures::SinkExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::DynError;
use crate::app::{ContractType, InboxController};

type ClientRequester = UnboundedSender<ClientRequest<'static>>;
type HostResponses = UnboundedReceiver<Result<HostResponse, ClientError>>;

pub(crate) type NodeResponses = UnboundedSender<AsyncActionResult>;

pub(crate) static WEB_API_SENDER: OnceLock<WebApiRequestClient> = OnceLock::new();

#[cfg(feature = "use-node")]
struct WebApi {
    requests: UnboundedReceiver<ClientRequest<'static>>,
    host_responses: HostResponses,
    client_errors: UnboundedReceiver<AsyncActionResult>,
    send_half: ClientRequester,
    error_sender: NodeResponses,
    api: freenet_stdlib::client_api::WebApi,
    connecting: Option<futures::channel::oneshot::Receiver<()>>,
}

#[cfg(not(feature = "use-node"))]
struct WebApi {}

impl WebApi {
    #[cfg(not(feature = "use-node"))]
    fn new() -> Result<Self, String> {
        Ok(Self {})
    }

    #[cfg(all(not(target_family = "wasm"), feature = "use-node"))]
    fn new() -> Result<Self, String> {
        unimplemented!()
    }

    #[cfg(all(target_family = "wasm", feature = "use-node"))]
    fn new() -> Result<Self, String> {
        use futures::SinkExt;
        // Derive the WebSocket URL from the current document origin so the
        // app talks to whichever gateway served it (production, local
        // sandbox, alt-port test node). The Freenet gateway shell rejects
        // `ws://localhost:7509` when served from `http://127.0.0.1:7509`
        // (origin equality check on `host`, not just port), so a hardcoded
        // host breaks the moment the user opens the page by IP instead of
        // by hostname (or vice versa).
        let location = web_sys::window()
            .ok_or_else(|| "no window".to_string())?
            .location();
        let host = location
            .host()
            .map_err(|e| format!("location.host: {e:?}"))?;
        let scheme = match location
            .protocol()
            .map_err(|e| format!("location.protocol: {e:?}"))?
            .as_str()
        {
            "https:" => "wss",
            _ => "ws",
        };
        let url = format!("{scheme}://{host}/v1/contract/command?encodingProtocol=native");
        let conn = web_sys::WebSocket::new(&url).unwrap();
        let (send_host_responses, host_responses) = futures::channel::mpsc::unbounded();
        let (send_half, requests) = futures::channel::mpsc::unbounded();
        let result_handler = move |result: Result<HostResponse, ClientError>| {
            let mut send_host_responses_clone = send_host_responses.clone();
            let _ = wasm_bindgen_futures::future_to_promise(async move {
                send_host_responses_clone
                    .send(result)
                    .await
                    .expect("channel open");
                Ok(wasm_bindgen::JsValue::NULL)
            });
        };
        let (tx, rx) = futures::channel::oneshot::channel();
        let onopen_handler = move || {
            let _ = tx.send(());
            crate::log::debug!("connected to websocket");
        };
        let api = freenet_stdlib::client_api::WebApi::start(
            conn,
            result_handler,
            |err| {
                crate::log::error(format!("host error: {err}"), None);
            },
            onopen_handler,
        );
        let (error_sender, client_errors) = futures::channel::mpsc::unbounded();

        Ok(Self {
            requests,
            host_responses,
            client_errors,
            send_half,
            error_sender,
            api,
            connecting: Some(rx),
        })
    }

    #[cfg(feature = "use-node")]
    fn sender_half(&self) -> WebApiRequestClient {
        WebApiRequestClient {
            sender: self.send_half.clone(),
            responses: self.error_sender.clone(),
        }
    }

    #[cfg(not(feature = "use-node"))]
    fn sender_half(&self) -> WebApiRequestClient {
        WebApiRequestClient
    }
}

#[cfg(feature = "use-node")]
#[derive(Clone, Debug)]
pub(crate) struct WebApiRequestClient {
    sender: ClientRequester,
    responses: NodeResponses,
}

#[cfg(not(feature = "use-node"))]
#[derive(Clone, Debug)]
pub(crate) struct WebApiRequestClient;

impl WebApiRequestClient {
    #[cfg(feature = "use-node")]
    pub async fn send(
        &mut self,
        request: freenet_stdlib::client_api::ClientRequest<'static>,
    ) -> Result<(), freenet_stdlib::client_api::Error> {
        self.sender
            .send(request)
            .await
            .map_err(|_| freenet_stdlib::client_api::Error::ChannelClosed)?;
        self.sender.flush().await.unwrap();
        Ok(())
    }

    #[cfg(not(feature = "use-node"))]
    pub async fn send(
        &mut self,
        request: freenet_stdlib::client_api::ClientRequest<'static>,
    ) -> Result<(), freenet_stdlib::client_api::Error> {
        tracing::debug!(?request, "emulated request");
        Ok(())
    }
}

#[cfg(feature = "use-node")]
impl From<WebApiRequestClient> for NodeResponses {
    fn from(val: WebApiRequestClient) -> Self {
        val.responses
    }
}

#[cfg(not(feature = "use-node"))]
impl From<WebApiRequestClient> for NodeResponses {
    fn from(_val: WebApiRequestClient) -> Self {
        unimplemented!()
    }
}

#[cfg(feature = "use-node")]
mod contract_api {
    use freenet_stdlib::{client_api::ContractRequest, prelude::*};

    use super::*;

    pub(super) async fn create_contract(
        client: &mut WebApiRequestClient,
        contract_code: &[u8],
        contract_state: impl Into<Vec<u8>>,
        params: &Parameters<'static>,
    ) -> Result<ContractKey, DynError> {
        let contract = ContractContainer::try_from((contract_code.to_vec(), params))?;
        let key = contract.key();
        crate::log::debug!("putting contract {key}");
        let state = contract_state.into().into();
        let request = ContractRequest::Put {
            contract,
            state,
            related_contracts: Default::default(),
            subscribe: false,
            blocking_subscribe: false,
        };
        client.send(request.into()).await?;
        Ok(key)
    }
}

#[cfg(feature = "use-node")]
mod delegate_api {
    use freenet_stdlib::{client_api::DelegateRequest, prelude::*};

    use super::*;

    pub(super) async fn create_delegate(
        client: &mut WebApiRequestClient,
        delegate_code_hash: &str,
        delegate_code: &[u8],
        params: &Parameters<'static>,
    ) -> Result<DelegateKey, DynError> {
        let key = DelegateKey::from_params(delegate_code_hash, params)?;
        let delegate = DelegateContainer::try_from((delegate_code.to_vec(), params))?;
        assert_eq!(&key, delegate.key());
        let request = ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
            delegate,
            cipher: DelegateRequest::DEFAULT_CIPHER,
            nonce: DelegateRequest::DEFAULT_NONCE,
        });
        client.send(request).await?;
        Ok(key)
    }
}

#[cfg(feature = "use-node")]
mod inbox_management {
    use std::sync::Arc;

    use freenet_stdlib::prelude::*;
    use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, signature::Keypair};

    use freenet_email_inbox::{InboxParams, InboxSettings};

    use super::*;

    const INBOX_CODE: &[u8] =
        include_bytes!("../../contracts/inbox/build/freenet/freenet_email_inbox");

    thread_local! {
        pub(super) static CREATED_INBOX: RefCell<Vec<(Rc<str>, ContractKey)>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) async fn create_contract(
        client: &mut WebApiRequestClient,
        ml_dsa_key: Arc<MlDsaSigningKey<MlDsa65>>,
    ) -> Result<ContractKey, DynError> {
        let vk = Keypair::verifying_key(ml_dsa_key.as_ref());
        let identity_key = vk.encode().to_vec();
        let params: Parameters = InboxParams {
            pub_key: crate::inbox::inbox_params_pub_key_bytes(&vk),
        }
        .try_into()?;
        let state = {
            let inbox = freenet_email_inbox::Inbox::new(
                ml_dsa_key.as_ref(),
                InboxSettings::default(),
                Vec::new(),
            );
            inbox.serialize()?
        };
        let contract_key =
            contract_api::create_contract(client, INBOX_CODE, state, &params).await?;
        super::identity_management::PENDING_CONFIRMATION.with(|pend| {
            let pend = &mut *pend.borrow_mut();
            let pend = pend.entry(identity_key).or_default();
            pend.inbox_key = Some(contract_key);
        });
        Ok(contract_key)
    }
}

#[cfg(feature = "use-node")]
mod token_record_management {
    use std::sync::Arc;

    use freenet_aft_interface::{TokenAllocationRecord, TokenDelegateParameters};
    use freenet_stdlib::prelude::*;
    use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, signature::Keypair};

    use super::*;

    const TOKEN_RECORD_CODE: &[u8] = include_bytes!(
        "../../modules/antiflood-tokens/contracts/token-allocation-record/build/freenet/freenet_token_allocation_record"
    );

    thread_local! {
        pub(super) static CREATED_AFT_RECORD: RefCell<Vec<(Rc<str>, ContractKey)>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) async fn create_contract(
        client: &mut WebApiRequestClient,
        ml_dsa_key: Arc<MlDsaSigningKey<MlDsa65>>,
    ) -> Result<ContractKey, DynError> {
        let vk = Keypair::verifying_key(ml_dsa_key.as_ref());
        let identity_key = vk.encode().to_vec();
        let params: Parameters = TokenDelegateParameters::new(&vk).try_into()?;
        let contract_key = contract_api::create_contract(
            client,
            TOKEN_RECORD_CODE,
            TokenAllocationRecord::default().serialized()?,
            &params,
        )
        .await?;
        super::identity_management::PENDING_CONFIRMATION.with(|pend| {
            let pend = &mut *pend.borrow_mut();
            let pend = pend.entry(identity_key).or_default();
            pend.aft_rec = Some(contract_key);
        });
        Ok(contract_key)
    }
}

#[cfg(feature = "use-node")]
mod token_generator_management {
    use std::sync::Arc;

    use freenet_aft_interface::DelegateParameters;
    use freenet_stdlib::prelude::DelegateKey;
    use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, signature::Keypair};

    use super::*;

    const TOKEN_GEN_CODE_HASH: &str = include_str!(
        "../../modules/antiflood-tokens/delegates/token-generator/build/token_generator_code_hash"
    );
    const TOKEN_GEN_CODE: &[u8] = include_bytes!(
        "../../modules/antiflood-tokens/delegates/token-generator/build/freenet/freenet_token_generator"
    );

    thread_local! {
        pub(super) static CREATED_AFT_GEN: RefCell<Vec<(Rc<str>, DelegateKey)>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) async fn create_delegate(
        client: &mut WebApiRequestClient,
        ml_dsa_key: Arc<MlDsaSigningKey<MlDsa65>>,
    ) -> Result<DelegateKey, DynError> {
        let vk = Keypair::verifying_key(ml_dsa_key.as_ref());
        let identity_key = vk.encode().to_vec();
        // DelegateParameters stores the 32-byte ML-DSA-65 seed; the signing
        // key is reconstructed from it inside the delegate on every invocation.
        let seed = {
            let seed_bytes = ml_dsa_key.as_ref().to_seed();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(seed_bytes.as_slice());
            arr
        };
        let params = DelegateParameters::new(seed).try_into()?;
        let delegate_key =
            delegate_api::create_delegate(client, TOKEN_GEN_CODE_HASH, TOKEN_GEN_CODE, &params)
                .await?;
        super::identity_management::PENDING_CONFIRMATION.with(|pend| {
            let pend = &mut *pend.borrow_mut();
            let pend = pend.entry(identity_key).or_default();
            pend.aft_gen = Some(delegate_key.clone());
        });
        Ok(delegate_key)
    }
}

#[cfg(feature = "use-node")]
mod identity_management {
    use std::rc::Rc;

    use ::identity_management::*;
    use freenet_stdlib::{client_api::DelegateRequest, prelude::*};
    use std::sync::Arc;

    use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey};
    use ml_kem::{DecapsulationKey, MlKem768};

    use crate::aft::AftRecords;
    use crate::app::Identity;
    use crate::app::login::StoredIdentityKeys;
    use crate::inbox::InboxModel;

    use super::*;

    const ID_MANAGER_CODE_HASH: &str =
        include_str!("../../modules/identity-management/build/identity_management_code_hash");
    const ID_MANAGER_CODE: &[u8] =
        include_bytes!("../../modules/identity-management/build/freenet/identity_management");
    const ID_MANAGER_KEY: &[u8] =
        include_bytes!("../../modules/identity-management/build/identity-manager-params");

    pub(super) async fn create_delegate(
        client: &mut WebApiRequestClient,
    ) -> Result<DelegateKey, DynError> {
        let params = IdentityParams::try_from(ID_MANAGER_KEY)?;
        let params = params.try_into()?;
        let key =
            delegate_api::create_delegate(client, ID_MANAGER_CODE_HASH, ID_MANAGER_CODE, &params)
                .await?;
        // `Init` is idempotent in the delegate (a no-op when state exists), so
        // calling it on every page load is safe and ensures the secret is
        // present before the first GetIdentities/CreateIdentity request.
        let request = DelegateRequest::ApplicationMessages {
            params: params.clone(),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(Vec::<u8>::try_from(&IdentityMsg::Init)?),
            )],
            key: key.clone(),
        };
        client.send(request.into()).await?;
        Ok(key)
    }

    pub(super) async fn load_aliases(
        client: &mut WebApiRequestClient,
    ) -> Result<DelegateKey, DynError> {
        let params = IdentityParams::try_from(ID_MANAGER_KEY)?;
        let params = Parameters::try_from(params)?;
        let key = DelegateKey::from_params(ID_MANAGER_CODE_HASH, &params)?;
        crate::log::debug!("loading aliases ({key})");
        // Request identities via ApplicationMessages (GetSecretRequest was removed in stdlib 0.3)
        let request = DelegateRequest::ApplicationMessages {
            params: params.clone(),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(Vec::<u8>::try_from(&IdentityMsg::GetIdentities)?),
            )],
            key: key.clone(),
        };
        client.send(request.into()).await?;
        Ok(key)
    }

    pub(super) async fn alias_creation(
        client: &mut WebApiRequestClient,
        identity_key: &[u8],
        inbox_to_id: &mut HashMap<ContractKey, Identity>,
        token_rec_to_id: &mut HashMap<ContractKey, Identity>,
        user: Signal<crate::app::User>,
    ) {
        let id = identity_management::PENDING_CONFIRMATION
            .with(|pend| pend.borrow_mut().remove(identity_key));
        let NewIdentity {
            alias,
            description,
            ml_dsa_key,
            ml_kem_dk,
            inbox_key,
            aft_rec,
            ..
        } = id.unwrap();

        let alias = alias.unwrap();
        let inbox_key = inbox_key.unwrap();
        let ml_dsa_key = ml_dsa_key.unwrap();
        let ml_kem_dk = ml_kem_dk.unwrap();

        // TODO: in reality we should wait to confirm the identity manager delegate has been properly updated
        // before adding the identity
        {
            // update alias state where appropriate
            let identity = Identity::set_alias(
                alias.clone(),
                description.clone(),
                ml_dsa_key.clone(),
                ml_kem_dk.clone(),
                inbox_key,
                user,
            );
            inbox_to_id.insert(inbox_key, identity.clone());
            token_rec_to_id.insert(aft_rec.unwrap(), identity);
        }

        // Send contract subscriptions after identity creation
        InboxModel::subscribe(&mut client.clone(), inbox_key)
            .await
            .unwrap();
        AftRecords::subscribe(&mut client.clone(), aft_rec.unwrap())
            .await
            .unwrap();

        match identity_management::create_alias_api_call(
            client,
            alias.clone(),
            description,
            ml_dsa_key,
            ml_kem_dk,
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                crate::log::error(
                    format!("{e}"),
                    Some(TryNodeAction::CreateIdentity(alias.to_string())),
                );
            }
        }
    }

    async fn create_alias_api_call(
        client: &mut WebApiRequestClient,
        alias: Rc<str>,
        description: String,
        ml_dsa_key: Arc<MlDsaSigningKey<MlDsa65>>,
        ml_kem_dk: DecapsulationKey<MlKem768>,
    ) -> Result<(), DynError> {
        crate::log::debug!("creating {alias}");
        let params = IdentityParams::try_from(ID_MANAGER_KEY)?;
        let params = params.try_into()?;
        let delegate_key = DelegateKey::from_params(ID_MANAGER_CODE_HASH, &params)?;
        // Serialise the keypair bundle (ML-DSA + ML-KEM seeds) into the opaque
        // `Vec<u8>` slot that the identity-management delegate stores.
        let stored = StoredIdentityKeys::new(&ml_dsa_key, &ml_kem_dk);
        let msg = IdentityMsg::CreateIdentity {
            alias: alias.to_string(),
            key: serde_json::to_vec(&stored)?,
            extra: Some(description),
        };
        let request = DelegateRequest::ApplicationMessages {
            params,
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(Vec::<u8>::try_from(&msg)?),
            )],
            key: delegate_key.clone(),
        };
        client.send(request.into()).await?;
        Ok(())
    }

    #[derive(Default)]
    pub(super) struct NewIdentity {
        pub alias: Option<Rc<str>>,
        pub description: String,
        pub ml_dsa_key: Option<Arc<MlDsaSigningKey<MlDsa65>>>,
        pub ml_kem_dk: Option<DecapsulationKey<MlKem768>>,
        pub created_inbox: bool,
        pub inbox_key: Option<ContractKey>,
        pub created_aft_rec: bool,
        pub aft_rec: Option<ContractKey>,
        pub created_aft_gen: bool,
        pub aft_gen: Option<DelegateKey>,
    }

    impl NewIdentity {
        pub fn created(&self) -> bool {
            self.created_inbox
                && self.created_aft_gen
                && self.created_aft_rec
                && self.alias.is_some()
                && self.ml_dsa_key.is_some()
        }
    }

    thread_local! {
        /// Keyed by the encoded ML-DSA-65 verifying key bytes (1952 bytes).
        /// That byte string is the per-identity stable correlator now that
        /// RSA is gone from the user-identity code path.
        pub(super) static PENDING_CONFIRMATION: RefCell<HashMap<Vec<u8>, NewIdentity>> = RefCell::new(HashMap::new());
    }
}

#[cfg(feature = "use-node")]
pub(crate) async fn node_comms(
    mut rx: UnboundedReceiver<crate::app::NodeAction>,
    inbox_controller: Signal<crate::app::InboxController>,
    login_controller: Signal<crate::app::LoginController>,
    user: Signal<crate::app::User>,
    // todo: refactor: instead of passing this arround,
    // where necessary we could be getting the fresh data via static methods calls to Inbox
    // and store the information there in thread locals
    mut inboxes: crate::app::InboxesData,
) {
    // todo don't unwrap inside this function, propagate errors to the UI somehow
    use freenet_email_inbox::Inbox as StoredInbox;
    use freenet_stdlib::{
        client_api::{ContractError, ContractResponse, DelegateError, ErrorKind, RequestError},
        prelude::*,
    };
    use futures::StreamExt;
    use std::sync::Arc;

    use crate::{
        aft::AftRecords,
        app::{Identity, InboxesData, NodeAction},
        inbox::InboxModel,
    };

    // Derive the encoded-VK correlator used as PENDING_CONFIRMATION's key
    // from a pending identity record. Expects `id.ml_dsa_key.is_some()`.
    fn identity_key_of(id: &identity_management::NewIdentity) -> Vec<u8> {
        use ml_dsa::signature::Keypair;
        id.ml_dsa_key
            .as_ref()
            .expect("pending identity must have ml_dsa_key before created() returns true")
            .as_ref()
            .verifying_key()
            .encode()
            .to_vec()
    }

    let mut inbox_contract_to_id = HashMap::new();
    let mut token_contract_to_id = HashMap::new();
    let mut api = WebApi::new()
        .map_err(|err| {
            crate::log::error(format!("error while connecting to node: {err}"), None);
            err
        })
        .expect("open connection");
    api.connecting.take().unwrap().await.unwrap();
    let mut req_sender = api.sender_half();
    {
        let contracts = user.read().identities.clone();
        crate::inbox::InboxModel::load_all(&mut req_sender, &contracts, &mut inbox_contract_to_id)
            .await;
        crate::aft::AftRecords::load_all(&mut req_sender, &contracts, &mut token_contract_to_id)
            .await;
    }
    // Register the identities delegate eagerly. Without this, the first
    // ApplicationMessages (load_aliases / alias_creation) hits a node that
    // has never seen this delegate, returns DelegateError::Missing, and
    // the recovery path that registers it after the fact loses the original
    // request — the user clicks "Create identity" and nothing happens.
    if let Err(e) = identity_management::create_delegate(&mut req_sender).await {
        crate::log::error(format!("identities delegate register failed: {e}"), None);
    }
    let identities_key = identity_management::load_aliases(&mut req_sender)
        .await
        .unwrap();
    WEB_API_SENDER.set(req_sender).unwrap();

    static IDENTITIES_KEY: OnceLock<DelegateKey> = OnceLock::new();
    IDENTITIES_KEY.set(identities_key.clone()).unwrap();

    async fn handle_action(
        req: NodeAction,
        api: &WebApi,
        inbox_to_id: &mut HashMap<ContractKey, Identity>,
        token_rec_to_id: &mut HashMap<ContractKey, Identity>,
        user: Signal<crate::app::User>,
    ) {
        let mut client = api.sender_half();
        match req {
            NodeAction::LoadMessages(identity) => {
                match InboxModel::load(&mut client, &identity).await {
                    Err(err) => {
                        node_response_error_handling(
                            client.into(),
                            Err(err),
                            TryNodeAction::LoadInbox,
                        )
                        .await;
                    }
                    Ok(key) => {
                        inbox_to_id.entry(key).or_insert(*identity);
                    }
                }
            }
            NodeAction::CreateIdentity {
                alias,
                ml_dsa_key,
                ml_kem_dk,
                description,
            } => {
                use ml_dsa::signature::Keypair;
                let identity_key = ml_dsa_key.as_ref().verifying_key().encode().to_vec();
                let created = identity_management::PENDING_CONFIRMATION.with(|pend| {
                    let pend = &mut *pend.borrow_mut();
                    let pend = pend.entry(identity_key.clone()).or_default();
                    crate::log::debug!("waiting for confirmation for identity {alias}");
                    pend.alias = Some(alias.clone());
                    pend.description = description.clone();
                    pend.ml_dsa_key = Some(ml_dsa_key.clone());
                    pend.ml_kem_dk = Some(*ml_kem_dk);
                    pend.created()
                });
                if created {
                    identity_management::alias_creation(
                        &mut client,
                        &identity_key,
                        inbox_to_id,
                        token_rec_to_id,
                        user,
                    )
                    .await;
                }
            }
            NodeAction::CreateContract {
                ml_dsa_key,
                contract_type,
                alias,
            } => match contract_type {
                ContractType::InboxContract => {
                    crate::log::debug!("creating inbox contract for {alias}");
                    match inbox_management::create_contract(&mut client, ml_dsa_key).await {
                        Ok(key) => {
                            inbox_management::CREATED_INBOX.with(|k| {
                                crate::log::debug!("waiting inbox contract for {alias}");
                                k.borrow_mut().push((alias, key));
                            });
                        }
                        Err(e) => crate::log::error(
                            format!("{e}"),
                            Some(TryNodeAction::CreateContract(contract_type)),
                        ),
                    }
                }
                ContractType::AFTContract => {
                    crate::log::debug!("creating AFT record contract for {alias}");
                    match token_record_management::create_contract(&mut client, ml_dsa_key).await {
                        Ok(key) => {
                            token_record_management::CREATED_AFT_RECORD.with(|k| {
                                crate::log::debug!("waiting AFT record contract for {alias}");
                                k.borrow_mut().push((alias, key));
                            });
                        }
                        Err(e) => crate::log::error(
                            format!("{e}"),
                            Some(TryNodeAction::CreateContract(contract_type)),
                        ),
                    }
                }
            },
            NodeAction::CreateDelegate { ml_dsa_key, alias } => {
                crate::log::debug!("creating AFT gen delegate for {alias}");
                match token_generator_management::create_delegate(&mut client, ml_dsa_key).await {
                    Ok(key) => {
                        token_generator_management::CREATED_AFT_GEN.with(|k| {
                            crate::log::debug!("waiting AFT gen delegate for {alias}");
                            k.borrow_mut().push((alias, key));
                        });
                    }
                    Err(e) => {
                        crate::log::error(format!("{e}"), Some(TryNodeAction::CreateDelegate))
                    }
                }
            }
        }
    }

    async fn handle_response(
        res: Result<HostResponse, ClientError>,
        inbox_to_id: &mut HashMap<ContractKey, Identity>,
        token_rec_to_id: &mut HashMap<ContractKey, Identity>,
        inboxes: &mut InboxesData,
        mut inbox_controller: dioxus::prelude::Signal<InboxController>,
        mut login_controller: dioxus::prelude::Signal<crate::app::LoginController>,
        user: Signal<crate::app::User>,
    ) {
        let mut client = WEB_API_SENDER.get().unwrap().clone();
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                match e.kind() {
                    ErrorKind::RequestError(e) => {
                        // FIXME: handle the different possible errors
                        match e {
                            RequestError::ContractError(ContractError::Update { key, .. }) => {
                                if token_rec_to_id.get(key).is_some() {
                                    // FIXME: in case this is for a token record which is PENDING_CONFIRMED_ASSIGNMENTS
                                    // we should reject that pending assignment
                                    let id = token_rec_to_id.get(key).unwrap();
                                    let alias = id.alias();
                                    crate::log::error(
                                        format!(
                                            "the message for {alias} (aft contract: {key}) wasn't delivered successfully, so may need to try again and/or notify the user"
                                        ),
                                        None,
                                    );
                                } else if inbox_to_id.get(key).is_some() {
                                    // FIXME: in case this is for an inbox contract we were trying to update, this means that
                                    // the message wasn't sent and should propgate that to the UI
                                    let id = inbox_to_id.get(key).unwrap();
                                    let alias = id.alias();
                                    crate::log::error(
                                        format!(
                                            "the message for {alias} (inbox contract: {key}) wasn't delievered succesffully, so may need to try again and/or notify the user"
                                        ),
                                        None,
                                    );
                                }
                            }
                            RequestError::ContractError(err) => {
                                crate::log::error(format!("FIXME: {err}"), None)
                            }
                            RequestError::DelegateError(DelegateError::Missing(key))
                                if key == IDENTITIES_KEY.get().unwrap() =>
                            {
                                if let Err(e) =
                                    identity_management::create_delegate(&mut client).await
                                {
                                    crate::log::error(format!("{e}"), None);
                                }
                            }
                            RequestError::DelegateError(error) => {
                                crate::log::error(
                                    format!("received delegate request error: {error}"),
                                    None,
                                );
                            }
                            RequestError::Disconnect => {
                                todo!("lost connection to node, should retry connecting")
                            }
                            _ => {}
                        }
                    }
                    ErrorKind::Unhandled { cause } => {
                        crate::log::error(format!("unhandled error, cause: {cause}"), None);
                    }
                    _ => {}
                }
                return;
            }
        };
        crate::log::debug!("got node response: {res}");
        match res {
            HostResponse::ContractResponse(ContractResponse::GetResponse {
                key, state, ..
            }) => {
                match inbox_to_id.remove(&key) {
                    Some(identity) => {
                        // is an inbox contract
                        let state: StoredInbox = serde_json::from_slice(state.as_ref()).unwrap();
                        let updated_model = InboxModel::from_state(
                            Arc::clone(&identity.ml_dsa_signing_key),
                            identity.ml_kem_dk.clone(),
                            state,
                            key,
                        )
                        .unwrap();
                        let loaded_models = inboxes.load();
                        if let Some(pos) = loaded_models.iter().position(|e| {
                            let x = e.borrow();
                            x.key == key
                        }) {
                            crate::log::debug!(
                                "loaded inbox {key} with {} messages",
                                updated_model.messages.len()
                            );
                            let mut current = (*loaded_models[pos]).borrow_mut();
                            *current = updated_model;
                        } else {
                            crate::log::debug!("loaded inbox {key}");
                            let mut with_new = (***loaded_models).to_vec();
                            std::mem::drop(loaded_models);
                            with_new.push(Rc::new(RefCell::new(updated_model)));
                            crate::log::debug!(
                                "loaded inboxes: {keys}",
                                keys = {
                                    with_new
                                        .iter()
                                        .map(|i| format!("{}", i.borrow().key))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                }
                            );
                            #[allow(clippy::arc_with_non_send_sync)] // see InboxesData definition
                            inboxes.store(Arc::new(with_new));
                            crate::inbox::InboxModel::set_contract_identity(key, identity.clone());
                        }
                        inbox_to_id.insert(key, identity);
                    }
                    _ => {
                        match token_rec_to_id.remove(&key) {
                            Some(identity) => {
                                // is a AFT record contract
                                if let Err(e) = AftRecords::set_identity_contract(
                                    identity.clone(),
                                    state.into(),
                                    &key,
                                ) {
                                    crate::log::error(
                                        format!("error setting an AFT record: {e}"),
                                        None,
                                    );
                                }
                                token_rec_to_id.insert(key, identity);
                            }
                            _ => {
                                unreachable!("tried to get wrong contract key: {key}")
                            }
                        }
                    }
                }
            }
            HostResponse::ContractResponse(ContractResponse::UpdateNotification {
                key,
                update,
            }) => {
                match inbox_to_id.remove(&key) {
                    Some(identity) => {
                        match update {
                            UpdateData::Delta(delta) => {
                                let delta: StoredInbox =
                                    serde_json::from_slice(delta.as_ref()).unwrap();
                                let updated_model = InboxModel::from_state(
                                    Arc::clone(&identity.ml_dsa_signing_key),
                                    identity.ml_kem_dk.clone(),
                                    delta,
                                    key,
                                )
                                .unwrap();
                                let loaded_models = inboxes.load();
                                let mut found = false;
                                for inbox in loaded_models.as_slice() {
                                    if inbox.clone().borrow().key == key {
                                        let mut inbox = (**inbox).borrow_mut();
                                        let controller = &mut *inbox_controller.write();
                                        controller.updated = true;
                                        inbox.merge(updated_model);
                                        crate::log::debug!(
                                            "updated inbox {key} with {} messages",
                                            inbox.messages.len()
                                        );
                                        found = true;
                                        break;
                                    }
                                }
                                assert!(found);
                                inbox_to_id.insert(key, identity);
                            }
                            UpdateData::State(state) => {
                                let delta: StoredInbox =
                                    serde_json::from_slice(state.as_ref()).unwrap();
                                let updated_model = InboxModel::from_state(
                                    Arc::clone(&identity.ml_dsa_signing_key),
                                    identity.ml_kem_dk.clone(),
                                    delta,
                                    key,
                                )
                                .unwrap();
                                let loaded_models = inboxes.load();
                                let mut found = false;
                                for inbox in loaded_models.as_slice() {
                                    if inbox.clone().borrow().key == key {
                                        let mut inbox = (**inbox).borrow_mut();
                                        let controller = &mut *inbox_controller.write();
                                        controller.updated = true;
                                        *inbox = updated_model;
                                        crate::log::debug!(
                                            "updated inbox {key} (whole state) with {} messages",
                                            inbox.messages.len()
                                        );
                                        found = true;
                                        break;
                                    }
                                }
                                assert!(found);
                                inbox_to_id.insert(key, identity);
                            }
                            // UpdateData::StateAndDelta { .. } => {
                            //     crate::log::error("recieved update state delta", None);
                            // }
                            _ => unreachable!(),
                        }
                    }
                    _ => {
                        match token_rec_to_id.remove(&key) {
                            Some(identity) => {
                                // is a AFT record contract
                                if let Err(e) = AftRecords::update_record(identity.clone(), update)
                                {
                                    crate::log::error(
                                        format!("error updating an AFT record from delta: {e}"),
                                        None,
                                    );
                                }
                                token_rec_to_id.insert(key, identity);
                            }
                            _ => {
                                unreachable!("tried to get wrong contract key: {key}")
                            }
                        }
                    }
                }
            }
            HostResponse::ContractResponse(ContractResponse::UpdateResponse { key, summary }) => {
                if let Some(identity) = token_rec_to_id.remove(&key) {
                    // The host's UpdateResponse `summary` field has, in
                    // practice, sometimes carried the full
                    // TokenAllocationRecord JSON (`{"tokens_by_tier":...}`)
                    // instead of the contract's TokenAllocationSummary
                    // (`{"Day1":[...]}`). Accept either: try Summary first,
                    // then fall back to deserializing as Record and
                    // summarizing locally. Bail with an error log instead
                    // of panicking — the AFT allocation has already
                    // committed at this point, the panic was just losing
                    // the post-commit hook.
                    let bytes = summary.as_ref();
                    let summary = match TokenAllocationSummary::try_from(summary.clone()) {
                        Ok(s) => Some(s),
                        Err(_) => match serde_json::from_slice::<freenet_aft_interface::TokenAllocationRecord>(bytes) {
                            Ok(record) => Some(record.summarize()),
                            Err(e) => {
                                crate::log::error(
                                    format!(
                                        "UpdateResponse summary deser failed as both Summary and Record: {e}"
                                    ),
                                    None,
                                );
                                None
                            }
                        },
                    };
                    if let Some(summary) = summary {
                        if let Err(e) =
                            AftRecords::confirm_allocation(&mut client, *key.id(), summary).await
                        {
                            crate::log::error(
                                format!("confirm_allocation failed: {e}"),
                                None,
                            );
                        }
                    }
                    token_rec_to_id.insert(key, identity.clone());
                }
            }
            HostResponse::ContractResponse(ContractResponse::PutResponse { key: contract_key }) => {
                let found = inbox_management::CREATED_INBOX.with(|keys| {
                    let pos = keys.borrow().iter().position(|(_, k)| k == &contract_key);
                    if let Some(pos) = pos {
                        let (alias, key) = keys.borrow_mut().remove(pos);
                        crate::log::debug!("inbox contract `{key}` for alias `{alias}` put");
                        return true;
                    }
                    false
                });
                if found {
                    let created = identity_management::PENDING_CONFIRMATION.with(|pend| {
                        if let Some(id) = pend
                            .borrow_mut()
                            .values_mut()
                            .find(|id| id.inbox_key.as_ref() == Some(&contract_key))
                        {
                            id.created_inbox = true;
                            id.created().then(|| identity_key_of(id))
                        } else {
                            None
                        }
                    });
                    if let Some(private_key) = created {
                        identity_management::alias_creation(
                            &mut client,
                            &private_key,
                            inbox_to_id,
                            token_rec_to_id,
                            user,
                        )
                        .await;
                    }
                    return;
                }
                let found = token_record_management::CREATED_AFT_RECORD.with(|keys| {
                    let pos = keys.borrow().iter().position(|(_, k)| k == &contract_key);
                    if let Some(pos) = pos {
                        let (alias, key) = keys.borrow_mut().remove(pos);
                        crate::log::debug!("AFT record `{key}` for alias `{alias}` put");
                        return true;
                    }
                    false
                });
                if found {
                    let created = identity_management::PENDING_CONFIRMATION.with(|pend| {
                        if let Some(id) = pend
                            .borrow_mut()
                            .values_mut()
                            .find(|id| id.aft_rec.as_ref() == Some(&contract_key))
                        {
                            id.created_aft_rec = true;
                            id.created().then(|| identity_key_of(id))
                        } else {
                            None
                        }
                    });
                    if let Some(private_key) = created {
                        identity_management::alias_creation(
                            &mut client,
                            &private_key,
                            inbox_to_id,
                            token_rec_to_id,
                            user,
                        )
                        .await;
                    }
                }
            }
            HostResponse::DelegateResponse { key, values } => {
                // Empty-values response on the identities delegate previously
                // re-issued `load_aliases`, but the node returns the same empty
                // result and the UI re-issues again — a tight loop hammering the
                // delegate executor. The identities reload path is dead until the
                // Phase 1 restore lands; for now, just ignore empty responses on
                // the identities key.
                if values.is_empty() && &key == IDENTITIES_KEY.get().unwrap() {
                    // no-op: see comment above
                } else if values.is_empty() {
                    let found = token_generator_management::CREATED_AFT_GEN.with(|keys| {
                        let pos = keys.borrow().iter().position(|(_, k)| k == &key);
                        if let Some(pos) = pos {
                            let (alias, key) = keys.borrow_mut().remove(pos);
                            crate::log::debug!("AFT gen delegate `{key}` for `{alias}` put");
                            return true;
                        }
                        false
                    });
                    if found {
                        let private_key = identity_management::PENDING_CONFIRMATION.with(|pend| {
                            if let Some(id) = pend
                                .borrow_mut()
                                .values_mut()
                                .find(|id| id.aft_gen.as_ref() == Some(&key))
                            {
                                id.created_aft_gen = true;
                                id.created().then(|| identity_key_of(id))
                            } else {
                                None
                            }
                        });
                        if let Some(key) = private_key {
                            identity_management::alias_creation(
                                &mut client,
                                &key,
                                inbox_to_id,
                                token_rec_to_id,
                                user,
                            )
                            .await;
                        }
                    }
                }
                let is_identities = &key == IDENTITIES_KEY.get().unwrap();
                for msg in values {
                    match msg {
                        freenet_stdlib::prelude::OutboundDelegateMsg::ApplicationMessage(msg) => {
                            // Identities-delegate response: payload is a serialized
                            // `IdentityManagement` (HashMap<alias, AliasInfo>). Restore
                            // it into the user's identity list so the login screen
                            // shows previously-created aliases. Without this branch
                            // the bytes get parsed as a `TokenDelegateMessage` and
                            // fail with a deser error.
                            if is_identities {
                                match ::identity_management::IdentityManagement::try_from(
                                    msg.payload.as_slice(),
                                ) {
                                    Ok(im) => {
                                        let new_ids = crate::app::Identity::set_aliases(im, user);
                                        // ALIASES is a thread_local Vec, not a
                                        // Dioxus signal — bump login_controller
                                        // so the Identities component re-renders.
                                        login_controller.write().updated = true;
                                        // Restore runtime wiring lost on reload:
                                        // INBOX_TO_ID + AFT-record subscriptions
                                        // (load_all does both), and AFT-gen
                                        // delegate registration on this session
                                        // (so assign_token finds it).
                                        if !new_ids.is_empty() {
                                            InboxModel::load_all(
                                                &mut client,
                                                &new_ids,
                                                inbox_to_id,
                                            )
                                            .await;
                                            AftRecords::load_all(
                                                &mut client,
                                                &new_ids,
                                                token_rec_to_id,
                                            )
                                            .await;
                                            for id in &new_ids {
                                                if let Err(e) =
                                                    token_generator_management::create_delegate(
                                                        &mut client,
                                                        Arc::clone(&id.ml_dsa_signing_key),
                                                    )
                                                    .await
                                                {
                                                    crate::log::error(
                                                        format!(
                                                            "AFT-gen re-register for `{}` failed: {e}",
                                                            id.alias()
                                                        ),
                                                        None,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        crate::log::error(
                                            format!("identities delegate response deser: {e}"),
                                            None,
                                        );
                                    }
                                }
                                continue;
                            }
                            let token = match TokenDelegateMessage::try_from(msg.payload.as_slice())
                            {
                                Ok(r) => r,
                                Err(e) => {
                                    crate::log::error(
                                        format!("error deserializing delegate msg: {e}"),
                                        None,
                                    );
                                    return;
                                }
                            };
                            match token {
                                TokenDelegateMessage::AllocatedToken { assignment, .. } => {
                                    let mut code_hash_bytes = [0u8; 32];
                                    bs58::decode(crate::aft::TOKEN_RECORD_CODE_HASH)
                                        .with_alphabet(bs58::Alphabet::BITCOIN)
                                        .onto(&mut code_hash_bytes)
                                        .unwrap();
                                    let code_hash =
                                        freenet_stdlib::prelude::CodeHash::new(code_hash_bytes);
                                    let token_contract_key = ContractKey::from_id_and_code(
                                        assignment.token_record,
                                        code_hash,
                                    );
                                    match token_rec_to_id.remove(&token_contract_key) {
                                        Some(identity) => {
                                            if let Err(e) = AftRecords::allocated_assignment(
                                                &mut client,
                                                assignment,
                                            )
                                            .await
                                            {
                                                // todo: if a collision occurs, the operation should be retried until there are no more tokens available
                                                crate::log::error(
                                                    format!(
                                                        "error registering the token assignment: {e}"
                                                    ),
                                                    None,
                                                );
                                            }
                                            token_rec_to_id.insert(token_contract_key, identity);
                                        }
                                        _ => {
                                            unreachable!("tried to get wrong contract key: {key}")
                                        }
                                    }
                                }
                                TokenDelegateMessage::Failure(reason) => {
                                    // FIXME: this may mean a pending message waiting for a token has failed, and need to notify that in the UI
                                    crate::log::error(
                                        format!("token assignment failure: {reason}"),
                                        Some(TryNodeAction::SendMessage),
                                    )
                                }
                                TokenDelegateMessage::RequestNewToken(_) => {
                                    // Delegate echoes the original request back to itself
                                    // (with updated context) while it's waiting on user
                                    // permission input. Not a UI-side action — ignore.
                                }
                            }
                        }
                        // NOTE: the original code had a second guarded
                        // `ApplicationMessage` arm here for the identities
                        // delegate response (gated on `&key == IDENTITIES_KEY`).
                        // It was unreachable because the arm above matches
                        // unconditionally. The identities path is currently
                        // dead — restoring it is tracked as Phase 1 work.
                        other => {
                            crate::log::error(
                                format!("received wrong delegate msg: {other:?}"),
                                None,
                            );
                        }
                    }
                }
            }
            HostResponse::Ok => {}
            other => {
                crate::log::error(format!("message not handled: {other:?}"), None);
            }
        }
    }

    loop {
        futures::select! {
            r = api.host_responses.next() => {
                let Some(res) = r else { panic!("async action ch closed") };
                handle_response(
                    res,
                    &mut inbox_contract_to_id,
                    &mut token_contract_to_id,
                    &mut inboxes,
                    inbox_controller,
                    login_controller,
                    user
                )
                .await;
            }
            req = rx.next() => {
                let Some(req) = req else { panic!("async action ch closed") };
                handle_action(req, &api, &mut inbox_contract_to_id, &mut token_contract_to_id, user).await;
            }
            req = api.requests.next() => {
                let Some(req) = req else { panic!("request ch closed") };
                crate::log::debug!("sending request to API: {req}");
                api.api.send(req).await.unwrap();
            }
            error = api.client_errors.next() => {
                match error {
                    Some(Err((msg, action))) => crate::log::error(format!("{msg}"), Some(action)),
                    Some(Ok(_)) => {}
                    None => panic!("error ch closed"),
                }
            }
        }
    }
}

pub(crate) type AsyncActionResult = Result<(), (DynError, TryNodeAction)>;

pub(crate) async fn node_response_error_handling(
    mut error_channel: NodeResponses,
    res: Result<(), DynError>,
    action: TryNodeAction,
) {
    // todo: all errors should be handled properly and propagated to the UI if fitting
    if let Err(error) = res {
        crate::log::error(format!("{error}"), Some(action.clone()));
        error_channel
            .send(Err((error, action)))
            .await
            .expect("error channel closed");
    } else {
        error_channel
            .send(Ok(()))
            .await
            .expect("error channel closed");
    }
}

#[derive(Clone, Debug)]
pub(crate) enum TryNodeAction {
    LoadInbox,
    LoadTokenRecord,
    SendMessage,
    RemoveMessages,
    GetAlias,
    CreateIdentity(String),
    CreateContract(ContractType),
    CreateDelegate,
}

impl std::fmt::Display for TryNodeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TryNodeAction::LoadInbox => write!(f, "loading messages"),
            TryNodeAction::LoadTokenRecord => write!(f, "loading token record"),
            TryNodeAction::SendMessage => write!(f, "sending message"),
            TryNodeAction::RemoveMessages => write!(f, "removing messages"),
            TryNodeAction::GetAlias => write!(f, "get alias"),
            TryNodeAction::CreateIdentity(alias) => write!(f, "create alias {alias}"),
            TryNodeAction::CreateContract(contract_type) => {
                write!(f, "creating contract {contract_type}")
            }
            TryNodeAction::CreateDelegate => {
                write!(f, "creating AFT delegate")
            }
        }
    }
}
