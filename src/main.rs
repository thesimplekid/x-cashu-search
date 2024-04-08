//!

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{debug_handler, Json, Router};
use cashu_sdk::client::{self};
use cashu_sdk::nuts::{P2PKConditions, Token};
use cashu_sdk::url::UncheckedUrl;
use cashu_sdk::wallet::localstore::{self};
use cashu_sdk::wallet::Wallet;
use cashu_sdk::Amount;
use nostr_sdk::{Client, Keys, PublicKey, Url};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::warn;

mod config;

fn app(state: ApiState) -> Router {
    Router::new()
        .route("/info", get(get_info))
        .route("/search", get(get_search))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());

    // get config file name from args
    let config_file_arg = "./config.toml".to_string();

    let settings = config::Settings::new(&Some(config_file_arg));

    let spending_conditions = P2PKConditions {
        locktime: None,
        pubkeys: vec![cashu_sdk::nuts::PublicKey::from_str(&settings.pubkey)
            .unwrap()
            .try_into()
            .unwrap()],
        refund_keys: None,
        num_sigs: None,
        sig_flag: cashu_sdk::nuts::SigFlag::default(),
    };

    let info = Info {
        trusted_mints: settings.trusted_mints,
        sats_per_search: settings.sats_per_search,
        pubkey: PublicKey::from_hex(settings.pubkey).unwrap(),
        acceptable_p2pk_conditions: spending_conditions,
    };

    let settings = Settings {
        relays: settings.relays.into_iter().collect(),
        auth_token: settings.auth_token,
    };

    let client = client::minreq_client::HttpClient {};

    let localstore = localstore::MemoryLocalStore::default();

    let wallet = Wallet::new(Arc::new(client), Arc::new(localstore), None).await;

    // TODO: get gets for trusted mints
    let my_keys = Keys::generate();
    let client = Client::new(my_keys);

    client.add_relays(settings.relays.clone()).await.unwrap();

    let state = ApiState {
        info,
        wallet: Arc::new(Mutex::new(wallet)),
        client,
        settings,
    };
    axum::serve(listener, app(state)).await.unwrap();
}

async fn get_info(State(state): State<ApiState>) -> Result<Json<Info>, StatusCode> {
    Ok(Json(state.info))
}

#[debug_handler]
async fn get_search(
    headers: HeaderMap,
    q: Query<String>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    let x_cashu = headers
        .get("X-Cashu")
        .ok_or(StatusCode::PAYMENT_REQUIRED)?
        .to_str()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token = Token::from_str(x_cashu).unwrap();

    let amount: Amount = token
        .token
        .iter()
        .map(|m| m.proofs.iter().map(|p| p.amount).sum::<Amount>())
        .sum();

    if amount.lt(&state.info.sats_per_search) {
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    let token_mints: HashSet<&UncheckedUrl> = token.token.iter().map(|m| &m.mint).collect();

    if !token_mints
        .iter()
        .all(|tm| state.info.trusted_mints.contains(tm))
    {
        // All proofs must be from trusted mints
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    let wallet = state.wallet.lock().await;

    wallet
        .verify_token_p2pk(&token, state.info.acceptable_p2pk_conditions)
        .map_err(|_| {
            warn!("P2PK verification failed");
            StatusCode::PAYMENT_REQUIRED
        })?;

    wallet.verify_token_dleq(&token).await.map_err(|_| {
        warn!("DLEQ verification failed");
        StatusCode::PAYMENT_REQUIRED
    })?;

    state
        .client
        .send_direct_msg(state.info.pubkey, token.to_string(), None)
        .await
        .map_err(|_| {
            warn!("Could not send token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let response = minreq::get("https://kagi.com/api/v0/search")
        .with_header(
            "Authorization",
            format!("Bot {}", state.settings.auth_token),
        )
        // TODO: Check q is still URL encoded
        .with_param("q", q.0)
        .send()
        .unwrap()
        .json::<SearchResponse>()
        .unwrap();

    Ok(Json(response.data))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Info {
    trusted_mints: HashSet<UncheckedUrl>,
    acceptable_p2pk_conditions: P2PKConditions,
    sats_per_search: Amount,
    pubkey: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    relays: Vec<Url>,
    auth_token: String,
}

#[derive(Clone)]
struct ApiState {
    info: Info,
    wallet: Arc<Mutex<Wallet>>,
    client: Client,
    settings: Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SearchResponse {
    meta: Meta,
    data: Vec<SearchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    id: String,
    node: String,
    ms: String,
    api_balance: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SearchResult {
    t: u8,
    rank: u64,
    url: String,
    title: String,
    snippet: Option<String>,
    published: Option<String>,
    image: Option<Image>,
    list: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Image {
    url: String,
    height: u64,
    width: u64,
}
