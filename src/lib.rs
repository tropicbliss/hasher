pub mod hashing;

use serde::{Deserialize, Serialize};
use worker::*;

#[derive(Deserialize)]
pub struct HashInput {
    password: String,
}

#[derive(Serialize)]
pub struct HashOutput {
    hash: String,
}

#[derive(Deserialize)]
pub struct VerifyInput {
    hash: String,
    password: String,
}

#[derive(Serialize)]
pub struct VerifyOutput {
    is_valid: bool,
}

#[event(fetch)]
async fn fetch(mut req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    match req.method() {
        Method::Get if req.path() == "/" => {
            let mut headers = Headers::new();
            headers.append("cache-control", "public, max-age=43200")?;
            Response::from_html(include_str!("instructions.html"))
                .map(|res| res.with_headers(headers))
        }
        Method::Post if req.path() == "/hash" => {
            let input: HashInput = req.json().await?;
            let result = hashing::hash(&input.password).unwrap();
            Response::from_json(&HashOutput { hash: result })
        }
        Method::Post if req.path() == "/verify" => {
            let input: VerifyInput = req.json().await?;
            let result = hashing::verify(&input.hash, &input.password).unwrap();
            Response::from_json(&VerifyOutput { is_valid: result })
        }
        _ => Response::error("Resource not found", 404),
    }
}
