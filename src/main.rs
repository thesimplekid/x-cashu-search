//!

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_ORIGIN, AUTHORIZATION, CONTENT_TYPE,
};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use cdk::nuts::{Conditions, PublicKey as CashuPublicKey, SpendingConditions, Token};
use cdk::url::UncheckedUrl;
use cdk::util::unix_time;
use cdk::wallet::Wallet;
use cdk::{Amount, Mnemonic};
use cdk_redb::RedbWalletDatabase;
use nostr_sdk::{Client, Keys, PublicKey, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::warn;

mod config;

fn app(state: ApiState) -> Router {
    Router::new()
        .route("/info", get(get_info))
        .route("/search", get(get_search))
        .layer(CorsLayer::very_permissive().allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderName::from_str("X-Cashu").unwrap(),
        ]))
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
    let config_file_arg = "/etc/x_cashu_search/config.toml".to_string();

    let settings = config::Settings::new(&Some(config_file_arg));

    let pubkey = CashuPublicKey::from_str(&settings.pubkey).unwrap();
    let spending_conditions = SpendingConditions::new_p2pk(pubkey, Conditions::default());

    let info = Info {
        trusted_mints: settings.trusted_mints,
        sats_per_search: settings.sats_per_search,
        pubkey: PublicKey::from(pubkey.x_only_public_key()),
        acceptable_p2pk_conditions: spending_conditions,
    };

    let seed = Mnemonic::from_str(&settings.mnemonic)
        .unwrap()
        .to_seed_normalized("");

    let settings = Settings {
        relays: settings.relays.into_iter().collect(),
        kagi_auth_token: settings.kagi_auth_token,
        brave_auth_token: settings.brave_auth_token,
    };

    let localstore = RedbWalletDatabase::new("./redb").unwrap();

    let wallet = Wallet::new(Arc::new(localstore), &seed);

    let my_keys = Keys::generate();
    let client = Client::new(my_keys);

    client.add_relays(settings.relays.clone()).await.unwrap();

    client.connect().await;

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

async fn get_search(
    headers: HeaderMap,
    q: Query<Params>,
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

    let time = unix_time();

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

    tracing::info!("Time to verify: {}", unix_time() - time);

    let time = unix_time();
    let client = state.client;

    tokio::spawn(async move {
        client
            .send_direct_msg(state.info.pubkey, token.to_string(), None)
            .await
            .map_err(|err| {
                warn!("Could not send token: {}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })
            .unwrap();
    });

    tracing::info!("Send: {}", unix_time() - time);

    let time = unix_time();
    let response = minreq::get("https://kagi.com/api/v0/search")
        .with_header(
            "Authorization",
            format!("Bot {}", state.settings.kagi_auth_token),
        )
        // TODO: Check q is still URL encoded
        .with_param("q", q.q.clone())
        .send()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("Kagi time: {}", unix_time() - time);
    let time = unix_time();
    let json_response = response
        .json::<Value>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let results: KagiSearchResponse =
        serde_json::from_value(json_response).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tracing::info!(
        "fetched response: {} from {}",
        results.meta.ms,
        results.meta.node
    );

    let search_results: Vec<KagiSearchResult> = results
        .data
        .into_iter()
        .flat_map(|s| match s {
            KagiSearchObject::SearchResult(sr) => Some(sr),
            KagiSearchObject::RelatedSearches(_) => None,
        })
        .collect();
    let results: Vec<SearchResult> = search_results
        .into_iter()
        .flat_map(|r| r.try_into())
        .collect();

    tracing::info!("Json time: {}", unix_time() - time);
    Ok(Json(results))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Params {
    q: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Info {
    trusted_mints: HashSet<UncheckedUrl>,
    acceptable_p2pk_conditions: SpendingConditions,
    sats_per_search: Amount,
    pubkey: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    relays: Vec<Url>,
    kagi_auth_token: String,
    brave_auth_token: String,
}

#[derive(Clone)]
struct ApiState {
    info: Info,
    wallet: Arc<Mutex<Wallet>>,
    client: Client,
    settings: Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KagiSearchResponse {
    meta: Meta,
    data: Vec<KagiSearchObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    id: String,
    node: String,
    ms: u64,
    api_balance: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SearchResult {
    url: String,
    title: String,
    description: Option<String>,
    age: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum KagiSearchObject {
    SearchResult(KagiSearchResult),
    RelatedSearches(KagiRelatedSearches),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct KagiSearchResult {
    t: u8,
    rank: Option<u64>,
    url: String,
    title: String,
    snippet: Option<String>,
    published: Option<String>,
    image: Option<Image>,
    list: Option<Vec<String>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct Image {
    url: String,
    height: u64,
    width: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct KagiRelatedSearches {
    t: u8,
    list: Vec<String>,
}

impl From<KagiSearchResult> for SearchResult {
    fn from(kagi: KagiSearchResult) -> SearchResult {
        SearchResult {
            url: kagi.url,
            title: kagi.title,
            description: kagi.snippet,
            age: kagi.published,
        }
    }
}

/*
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BraveSearchResult {
    title: String,
    url: String,
    is_source_local: bool,
    is_source_both: bool,
    description: String,
    page_age: String,
    language: String,
    family_friendly: bool,
    age: String,
}

impl From<BraveSearchResult> for SearchResult {
    fn from(brave: BraveSearchResult) -> SearchResult {
        SearchResult {
            url: brave.url,
            title: brave.title,
            description: Some(brave.description),
            age: Some(brave.age),
        }
    }
}
*/
