//!

use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_ORIGIN, AUTHORIZATION, CONTENT_TYPE,
};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use cdk::mint_url::MintUrl;
use cdk::nuts::{PublicKey as CashuPublicKey, SpendingConditions, Token, TokenV4};
use cdk::util::unix_time;
use cdk::wallet::Wallet;
use cdk::Amount;
use cdk_sqlite::WalletSqliteDatabase;
use nostr_sdk::bip39::Mnemonic;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

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
async fn main() -> anyhow::Result<()> {
    let default_filter = "debug";

    let sqlx_filter = "sqlx=warn";

    let env_filter = EnvFilter::new(format!("{},{}", default_filter, sqlx_filter));

    // Parse input
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    tracing::info!("listening on {}", listener.local_addr()?);

    // get config file name from args
    let config_file_arg = "./config.toml".to_string();

    let settings = config::Settings::new(&Some(config_file_arg));

    tracing::debug!("{:?}", settings);

    let pubkey = CashuPublicKey::from_str(&settings.pubkey)?;

    let mint = settings.mint;

    let info = Info {
        mint: mint.clone(),
        sats_per_search: 50.into(),
        pubkey,
    };

    let seed = Mnemonic::from_str(&settings.mnemonic)?.to_seed_normalized("");

    let api_settings = Settings {
        kagi_auth_token: settings.kagi_auth_token,
        brave_auth_token: settings.brave_auth_token,
        mint_url: mint.clone(),
        pubkey,
    };

    let localstore =
        WalletSqliteDatabase::new(&PathBuf::from_str("./wallet.sqlite").unwrap()).await?;

    localstore.migrate().await;

    let wallet = Wallet::new(
        &mint.to_string(),
        cdk::nuts::CurrencyUnit::Sat,
        Arc::new(localstore),
        &seed,
        None,
    )?;

    let proofs = wallet.get_proofs().await?;

    let ys: HashSet<CashuPublicKey> = proofs.iter().flat_map(|p| p.y()).collect();

    let state = ApiState {
        info,
        wallet: Arc::new(Mutex::new(wallet)),
        settings: api_settings,
        seen_ys: Arc::new(Mutex::new(ys)),
    };

    tracing::info!("Starting axum server");
    axum::serve(listener, app(state)).await?;

    Ok(())
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

    let token: TokenV4 = TokenV4::from_str(x_cashu).unwrap();

    let token_amount = token.value().unwrap();

    let token_mint = token.mint_url.clone();

    if token_mint != state.settings.mint_url || token_amount != 1.into() {
        // All proofs must be from trusted mints
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    let proof = token.proofs();
    let proof = proof
        .get(&state.settings.mint_url)
        .unwrap()
        .first()
        .unwrap();

    let mut seen_ys = state.seen_ys.lock().await;

    let time = unix_time();

    let wallet = state.wallet.lock().await;

    let token = Token::TokenV4(token);

    wallet
        .verify_token_p2pk(
            &token,
            SpendingConditions::P2PKConditions {
                data: state.settings.pubkey,
                conditions: None,
            },
        )
        .map_err(|_| {
            tracing::warn!("P2PK verification failed");
            StatusCode::PAYMENT_REQUIRED
        })?;

    // TODO: Cashu ts doesnt support DLEQ
    // wallet.verify_token_dleq(&token).await.map_err(|_| {
    //     warn!("DLEQ verification failed");
    //     StatusCode::PAYMENT_REQUIRED
    // })?;

    let proof_y = proof.y().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let proof_keys = proof.keyset_id;

    let _wallet_keys = wallet.get_keyset_keys(proof_keys).await.map_err(|err| {
        tracing::error!("Could not get wallet keys: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !seen_ys.insert(proof_y) {
        tracing::warn!("Token already seen");
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    tracing::info!("Time to verify: {}", unix_time() - time);

    let time = unix_time();

    tracing::info!("Send: {}", unix_time() - time);

    let time = unix_time();
    let response = minreq::get("https://kagi.com/api/v0/search")
        .with_header(
            "Authorization",
            format!("Bot {}", state.settings.kagi_auth_token),
        )
        .with_param("q", q.q.clone())
        .send()
        .map_err(|err| {
            tracing::error!("Failed to make kagi request: {}", err);
            seen_ys.remove(&proof_y);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Kagi time: {}", unix_time() - time);
    let time = unix_time();
    let json_response = response
        .json::<Value>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let results: KagiSearchResponse = serde_json::from_value(json_response).map_err(|_| {
        tracing::error!("Invalid response from kagi");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
    mint: MintUrl,
    pubkey: CashuPublicKey,
    sats_per_search: Amount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    kagi_auth_token: String,
    brave_auth_token: String,
    mint_url: MintUrl,
    pubkey: CashuPublicKey,
}

#[derive(Clone)]
struct ApiState {
    info: Info,
    wallet: Arc<Mutex<Wallet>>,
    settings: Settings,
    seen_ys: Arc<Mutex<HashSet<CashuPublicKey>>>,
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
