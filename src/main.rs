//!

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::anyhow;
use axum::extract::{Query, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_ORIGIN, AUTHORIZATION, CONTENT_TYPE,
};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use cdk::amount::SplitTarget;
use cdk::mint_url::MintUrl;
use cdk::nuts::{
    Proofs, PublicKey as CashuPublicKey, SecretKey, SpendingConditions, Token, TokenV4,
};
use cdk::util::unix_time;
use cdk::wallet::Wallet;
use cdk_redb::WalletRedbDatabase;
use clap::Parser;
use db::Db;
use nostr_sdk::bip39::Mnemonic;
use nostr_sdk::{Client, Keys, PublicKey};
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

use crate::cli::CLIArgs;

mod cli;
mod config;
mod db;

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

    let args = CLIArgs::parse();

    let work_dir = match args.work_dir {
        Some(w) => w,
        None => work_dir()?,
    };

    // get config file name from args
    let config_file_arg = match args.config {
        Some(c) => c,
        None => work_dir.join("config.toml"),
    };

    let settings = config::Settings::new(&Some(config_file_arg.to_string_lossy().to_string()));

    tracing::debug!("{:?}", settings);

    let cashu_secret_key = SecretKey::from_hex(settings.cashu_private_key)?;

    let mint = settings.mint;

    let info = Info {
        mint: mint.clone(),
        pubkey: cashu_secret_key.public_key(),
    };

    let seed = Mnemonic::from_str(&settings.mnemonic)?.to_seed_normalized("");

    let api_settings = Settings {
        kagi_auth_token: settings.kagi_auth_token,
        brave_auth_token: settings.brave_auth_token,
        mint_url: mint.clone(),
        cashu_secret_key,
        nostr_pubkey: PublicKey::from_str(&settings.nostr_notification)?,
        nostr_relays: settings.nostr_relays,
    };

    let db_path = work_dir.join("wallet.redb");

    let localstore = WalletRedbDatabase::new(&db_path)?;

    let wallet = Wallet::new(
        &mint.to_string(),
        cdk::nuts::CurrencyUnit::Sat,
        Arc::new(localstore),
        &seed,
        None,
    )?;

    let app_db = work_dir.join("x-search.redb");

    let db = Db::new(app_db)?;

    let state = ApiState {
        info,
        wallet: Arc::new(Mutex::new(wallet)),
        settings: api_settings,
        db: Arc::new(db),
        unclaimed_proofs: Arc::new(RwLock::new(Vec::new())),
        reqwest_client: ReqwestClient::new(),
    };

    tracing::info!("Starting axum server");
    let bind_addr = format!("{}:{}", settings.listen_addr, settings.listen_port);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("listening on {}", listener.local_addr()?);
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

    let proofs = token.proofs();
    let proof = proofs.first().ok_or(StatusCode::PAYMENT_REQUIRED)?;

    let time = unix_time();

    let wallet = state.wallet.lock().await;

    let token = Token::TokenV4(token);

    wallet
        .verify_token_p2pk(
            &token,
            SpendingConditions::P2PKConditions {
                data: state.settings.cashu_secret_key.public_key(),
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

    let proof_keys = proof.keyset_id;

    let _wallet_keys = wallet.get_keyset_keys(proof_keys).await.map_err(|err| {
        tracing::error!("Could not get wallet keys: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    drop(wallet);

    if state
        .db
        .add_unclaimed_proof(proof)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        tracing::warn!("Token already seen");
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    tracing::info!("Time to verify: {}", unix_time() - time);

    let time = unix_time();

    tracing::info!("Send: {}", unix_time() - time);

    let unclaimed_count = state.unclaimed_proofs.read().await.len();

    if unclaimed_count >= 50 {
        let wallet_clone = Arc::clone(&state.wallet);
        let unclaimed_proofs_clone = Arc::clone(&state.unclaimed_proofs);
        let secret_key_clone = state.settings.cashu_secret_key;
        let notification_pubkey = state.settings.nostr_pubkey;
        let nostr_relays = state.settings.nostr_relays.clone();

        tokio::spawn(async move {
            let mut proofs = unclaimed_proofs_clone.write().await;

            let count_to_swap = if proofs.len() > 50 { 50 } else { proofs.len() };

            let inputs_proofs = proofs.drain(..count_to_swap).collect();

            let amount = {
                let wallet = wallet_clone.lock().await;
                match wallet
                    .receive_proofs(
                        inputs_proofs,
                        SplitTarget::Value(1.into()),
                        &[secret_key_clone],
                        &[],
                    )
                    .await
                {
                    Ok(amount) => {
                        tracing::info!("Swapped {}", amount);
                        Some(amount)
                    }
                    Err(err) => {
                        tracing::error!("Could not swap proofs: {}", err);
                        None
                    }
                }
            };

            if let Some(amount) = amount {
                let my_keys = Keys::generate();
                let client = Client::new(my_keys);
                let msg = format!("Athenut just redeamed: {} search tokens", amount);

                for relay in nostr_relays {
                    if let Err(err) = client.add_write_relay(&relay).await {
                        tracing::error!("Could not add relay {}: {}", relay, err);
                    }
                }

                client.connect().await;

                if let Err(err) = client
                    .send_private_msg(notification_pubkey, msg, None)
                    .await
                {
                    tracing::error!("Could not send nostr notification: {}", err);
                }
            }
        });
    }

    let time = unix_time();
    let response = state
        .reqwest_client
        .get("https://kagi.com/api/v0/search")
        .header(
            AUTHORIZATION,
            format!("Bot {}", state.settings.kagi_auth_token),
        )
        .query(&[("q", q.q.clone())])
        .send()
        .await
        .map_err(|err| {
            tracing::error!("Failed to make kagi request: {}", err);
            state.db.remove_proof(proof).ok();
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Kagi time: {}", unix_time() - time);
    let time = unix_time();
    let json_response = response
        .json::<Value>()
        .await
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    kagi_auth_token: String,
    brave_auth_token: String,
    mint_url: MintUrl,
    cashu_secret_key: SecretKey,
    nostr_pubkey: PublicKey,
    nostr_relays: Vec<String>,
}

#[derive(Clone)]
struct ApiState {
    info: Info,
    wallet: Arc<Mutex<Wallet>>,
    settings: Settings,
    db: Arc<Db>,
    unclaimed_proofs: Arc<RwLock<Proofs>>,
    reqwest_client: ReqwestClient,
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
fn work_dir() -> anyhow::Result<PathBuf> {
    let home_dir = home::home_dir().ok_or(anyhow!("Unknown home dir"))?;

    Ok(home_dir.join(".x-cashu-backend"))
}
