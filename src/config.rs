fn get_env_var(var_name: &str) -> String {
    std::env::var(var_name).unwrap_or_else(|_| panic!("{} must be set", var_name))
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub client_origin: String,

    pub access_token_private_key: String,
    pub access_token_public_key: String,
    pub access_token_expires_in: String,
    pub access_token_max_age: i64,

    pub refresh_token_private_key: String,
    pub refresh_token_public_key: String,
    pub refresh_token_expires_in: String,
    pub refresh_token_max_age: i64,
}

impl Config {
    pub fn init() -> Config {
        let database_url = get_env_var("DATABASE_URL");
        let redis_url = get_env_var("REDIS_URL");
        let client_origin = get_env_var("CLIENT_ORIGIN");

        let access_token_private_key = get_env_var("ACCESS_TOKEN_PRIVATE_KEY");
        let access_token_public_key = get_env_var("ACCESS_TOKEN_PUBLIC_KEY");
        let access_token_expires_in = get_env_var("ACCESS_TOKEN_EXPIRED_IN");
        let access_token_max_age = get_env_var("ACCESS_TOKEN_MAXAGE");

        let refresh_token_private_key = get_env_var("REFRESH_TOKEN_PRIVATE_KEY");
        let refresh_token_public_key = get_env_var("REFRESH_TOKEN_PUBLIC_KEY");
        let refresh_token_expires_in = get_env_var("REFRESH_TOKEN_EXPIRED_IN");
        let refresh_token_max_age = get_env_var("REFRESH_TOKEN_MAXAGE");

        Config {
            database_url,
            redis_url,
            client_origin,
            access_token_private_key,
            access_token_public_key,
            refresh_token_private_key,
            refresh_token_public_key,
            access_token_expires_in,
            refresh_token_expires_in,
            access_token_max_age: access_token_max_age.parse::<i64>().unwrap(),
            refresh_token_max_age: refresh_token_max_age.parse::<i64>().unwrap(),
        }
    }
}
