use clap::Parser;
use enum_dispatch::enum_dispatch;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{
    decode, encode, get_current_timestamp, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

use crate::CmdExector;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    #[command(about = "Sign a JWT")]
    Sign(JwtSignOpts),
    #[command(about = "Verify a JWT")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(short, long)]
    pub sub: String,
    #[arg(short, long)]
    pub aud: String,
    #[arg(short, long, value_parser = parse_jwt_exp)]
    pub exp: u64,
}

fn parse_jwt_exp(exp: &str) -> Result<u64, anyhow::Error> {
    let quantity = exp[..exp.len() - 1].parse::<u64>()?;
    let unit = exp.chars().last().unwrap();
    let duration_in_seconds = match unit.to_ascii_lowercase() {
        's' => Ok(quantity),
        'm' => Ok(quantity * 60),
        'h' => Ok(quantity * 60 * 60),
        'd' => Ok(quantity * 60 * 60 * 24),
        _ => Err(anyhow::anyhow!(
            "Invalid unit, use s, m, h, or d as the last character to represent the unit of time"
        )),
    }?;

    Ok(get_current_timestamp() + duration_in_seconds)
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    aud: String,
    exp: u64,
}

const KEY: &[u8] = b"secret";

impl CmdExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let claims = Claims {
            sub: self.sub,
            aud: self.aud,
            exp: self.exp,
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(KEY))?;
        println!("{}", token);
        Ok(())
    }
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["sub", "aud", "exp"]);
        // just verify the format
        validation.validate_aud = false;
        validation.validate_exp = false;

        let result =
            match decode::<Claims>(&self.token, &DecodingKey::from_secret(KEY), &validation) {
                Ok(_) => "✓ JWT verified",
                Err(err) => {
                    println!("{:?}", err);
                    match *err.kind() {
                        ErrorKind::InvalidToken => "⚠ Invalid token",
                        _ => "⚠ Unknown error",
                    }
                }
            };
        println!("{}", result);
        Ok(())
    }
}
