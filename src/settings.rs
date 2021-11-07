use std::env;
use serde::{Serialize, Deserialize};
use config::{ConfigError, Config, File, Environment};
use std::collections::HashMap;
// use config::{Config, ConfigError, Environment, File};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Server{
    pub ip_address : String,
    pub server_port :u16,
    pub access_ports : Vec<u16>,
    pub interface_name :String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Auth{
    pub pre_shared_key :String,
    pub pre_shared_iv : String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Local{
    pub local_port :u16,
    pub identifier :String,
    pub ip_address :String,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Client{
    pub client_id :String,
    pub client_name :String,
    pub pre_shared_key :String,
    pub pre_shared_iv :String,
}




#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings{
    pub server : Server,
    // pub auth :Auth,
    // pub local : Local,
    pub clients :HashMap<String, Client>,
}


const CONFIG_FILE_PATH: &str = "/root/privateaccess/privaccess/src/conf.toml";


impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let mut s = Config::default();

        // Start off by merging in the "default" configuration file
        s.merge(File::with_name(CONFIG_FILE_PATH))?;
        // println!("{:?}", s);

        // // Add in the current environment file
        // // Default to 'development' env
        // // Note that this file is _optional_
        // let env = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        // s.merge(File::with_name(&format!("config/{}", env)).required(false))?;

        // // Add in a local configuration file
        // // This file shouldn't be checked in to git
        // s.merge(File::with_name("config/local").required(false))?;

        // // Add in settings from the environment (with a prefix of APP)
        // // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        // s.merge(Environment::with_prefix("app"))?;

        // // You may also programmatically change settings
        // s.set("database.url", "postgres://")?;

        // Now that we're done, let's access our configuration
        // println!("debug: {:?}", s.get_bool("debug"));
        // println!("Server: {:?}", s.get::<String>("server.ip_address"));

        // You can deserialize (and thus freeze) the entire configuration as
        s.try_into()
        // Ok(s)
    }
}
