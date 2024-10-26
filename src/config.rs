use std::str::FromStr;

use cdk::mint_url::MintUrl;
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub listen_addr: String,
    pub listen_port: u16,
    pub cashu_private_key: String,
    pub mnemonic: String,
    pub mint: MintUrl,
    pub kagi_auth_token: String,
    pub brave_auth_token: String,
    pub nostr_notification: String,
    pub nostr_relays: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            cashu_private_key: String::new(),
            mnemonic: String::new(),
            mint: MintUrl::from_str("https:://fake.thesimplekid.dev").unwrap(),
            kagi_auth_token: String::new(),
            brave_auth_token: String::new(),
            nostr_notification: String::new(),
            nostr_relays: Vec::new(),
        }
    }
}

impl Settings {
    #[must_use]
    pub fn new(config_file_name: &Option<String>) -> Self {
        let default_settings = Self::default();
        // attempt to construct settings with file
        let from_file = Self::new_from_default(&default_settings, config_file_name);
        match from_file {
            Ok(f) => f,
            Err(_e) => default_settings,
        }
    }

    fn new_from_default(
        default: &Settings,
        config_file_name: &Option<String>,
    ) -> Result<Self, ConfigError> {
        let mut default_config_file_name = dirs::config_dir()
            .ok_or(ConfigError::NotFound("Config Path".to_string()))?
            .join("cashu-rs-mint");

        default_config_file_name.push("config.toml");
        let config: String = match config_file_name {
            Some(value) => value.clone(),
            None => default_config_file_name.to_string_lossy().to_string(),
        };

        println!("{}", config);
        let builder = Config::builder();
        let config: Config = builder
            // use defaults
            .add_source(Config::try_from(default)?)
            // override with file contents
            .add_source(File::with_name(&config))
            .build()?;
        let settings: Settings = config.clone().try_deserialize().unwrap();

        println!("{:?}", config);

        Ok(settings)
    }
}
