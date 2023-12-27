use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json, body::Body,
};

use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{model::User, token, AppState};
use redis::AsyncCommands;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTAuthMiddleware {
    pub user: User,
    pub access_token_uuid: uuid::Uuid,
}

pub async fn auth(
    cookie_jar: CookieJar,
    State(data): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let access_token = cookie_jar
        .get("access_token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_owned())
                    } else {
                        None
                    }
                })
        });

    let access_token = access_token.ok_or_else(|| {
        let error_response = ErrorResponse {
            status: "fail",
            message: "You are not logged in, please provide token".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    let access_token_details =
        match token::verify_jwt_token(data.env.access_token_public_key.to_owned(), &access_token) {
            Ok(token_details) => token_details,
            Err(e) => {
                let error_response = ErrorResponse {
                    status: "fail",
                    message: format!("{:?}", e),
                };
                return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
            }
        };

    let access_token_uuid = uuid::Uuid::parse_str(&access_token_details.token_uuid.to_string())
        .map_err(|_| {
            let error_response = ErrorResponse {
                status: "fail",
                message: "Invalid token".to_string(),
            };
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;

    let mut redis_client = data
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "error",
                message: format!("Redis error: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let redis_token_user_id = redis_client
        .get::<_, String>(access_token_uuid.clone().to_string())
        .await
        .map_err(|_| {
            let error_response = ErrorResponse {
                status: "error",
                message: "Token is invalid or session has expired".to_string(),
            };
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;

    let user_id_uuid = uuid::Uuid::parse_str(&redis_token_user_id).map_err(|_| {
        let error_response = ErrorResponse {
            status: "fail",
            message: "Token is invalid or session has expired".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id_uuid)
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "fail",
                message: format!("Error fetching user from database: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let user = user.ok_or_else(|| {
        let error_response = ErrorResponse {
            status: "fail",
            message: "The user belonging to this token no longer exists".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    req.extensions_mut().insert(JWTAuthMiddleware {
        user,
        access_token_uuid,
    });
    Ok(next.run(req).await)
}
