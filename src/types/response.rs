use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorCode {
    NotFound,
    BadRequest,
    InternalServer,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorRespone {
    pub code: ErrorCode,
    pub msg: String,
}
