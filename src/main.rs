use actix_web::Error;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    middleware::Logger,
    web, App, HttpResponse, HttpServer, Responder,
};
use actix_web_lab::middleware::from_fn;
use actix_web_lab::middleware::Next;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::EnvFilter;

// JWT claim
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Middleware to authenticate JWT
async fn jwt_auth(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let token = &req.headers().get("Authorization").and_then(|hv| {
        hv.to_str()
            .ok()
            .and_then(|s| s.split_once(' ').map(|x| x.1))
    });

    tracing::info!("Token: {:?}", token);
    let validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    match token {
        Some(token) => {
            let token_data = decode::<Claims>(
                token,
                &DecodingKey::from_rsa_pem(include_bytes!("../public.pem")).unwrap(),
                &validation,
            );
            tracing::info!("token_data: {:?}", token_data);

            match token_data {
                Ok(_) => next.call(req).await,
                Err(e) => Err(actix_web::error::ErrorUnauthorized(format!(
                    "Invalid token {:?}",
                    e
                ))),
            }
        }
        None => Err(actix_web::error::ErrorUnauthorized("No token found")),
    }
}

async fn protected() -> impl Responder {
    HttpResponse::Ok().body("Hello world - authenticated")
}

async fn unprotected() -> impl Responder {
    HttpResponse::Ok().body("Hello world - open")
}

// Function to generate JWT token
async fn generate_token() -> impl Responder {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        + 60 * 60; // 1 hour validity

    let claims = Claims {
        sub: "user_id".to_owned(),
        exp: expiration as usize,
    };

    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(include_bytes!("../private.pem")).unwrap(),
    )
    .unwrap();

    HttpResponse::Ok().body(token)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(
                web::resource("/protected")
                    .wrap(from_fn(jwt_auth))
                    .route(web::get().to(protected)),
            )
            .service(web::resource("/unprotected").route(web::get().to(unprotected)))
            .service(web::resource("/generate_token").route(web::get().to(generate_token)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
