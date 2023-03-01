use actix_cors::Cors;
use actix_web::{
    delete,
    error::{ErrorBadRequest, ErrorInternalServerError, ErrorNotFound},
    get, post, put, web, App, Error, HttpResponse, HttpServer,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::pg::PgConnection;
use diesel::{
    prelude::*,
    r2d2::{self, ConnectionManager},
};
use dotenvy::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use std::env;
use uuid::Uuid;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

mod db;
mod types;

use crate::types::response::{ErrorCode, ErrorRespone, TokenResponse};
use db::models::{LoginUser, NewUser, User, UserClaim};
use db::schema::users::dsl::*;

#[get("/users")]
async fn get_users(db_pool: web::Data<DbPool>) -> Result<HttpResponse, Error> {
    let fetched_users = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        users.load::<User>(&mut conn)
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(fetched_users))
}

#[get("/users/{id}")]
async fn get_user_by_id(
    db_pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
) -> Result<HttpResponse, Error> {
    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        users
            .filter(id.eq(user_id.to_owned()))
            .first::<User>(&mut conn)
            .optional()
    })
    .await?;

    if result.is_err() {
        return Err(ErrorInternalServerError("Internal Server Error"));
    }

    let user = result.unwrap();
    if user.is_none() {
        return Err(ErrorNotFound("User not found"));
    }
    Ok(HttpResponse::Ok().json(user))
}

#[post("/users/signup")]
async fn create_new_user(
    db_pool: web::Data<DbPool>,
    new_user_form: web::Json<NewUser>,
) -> Result<HttpResponse, Error> {
    // get cloned email address
    let email_form = new_user_form.email.clone();

    // Create hash password
    let hashed_password =
        hash(new_user_form.password.clone(), DEFAULT_COST).map_err(ErrorInternalServerError)?;
    let hashed_user = NewUser {
        password: hashed_password,
        ..new_user_form.into_inner()
    };

    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");

        // Check if email exist
        let result = users
            .filter(email.eq(email_form))
            .first::<User>(&mut conn)
            .optional();

        if result.is_err() {
            return Err(ErrorRespone {
                code: ErrorCode::InternalServer,
                msg: "Internal Server Error".to_string(),
            });
        }
        if result.unwrap().is_some() {
            return Err(ErrorRespone {
                code: ErrorCode::BadRequest,
                msg: "Email already taken".to_string(),
            });
        }

        // Insert new user
        let result = diesel::insert_into(users)
            .values(hashed_user)
            .get_result::<User>(&mut conn);

        if let Ok(user) = result {
            Ok(user)
        } else {
            Err(ErrorRespone {
                code: ErrorCode::InternalServer,
                msg: "Internal Server Error while insert user".to_string(),
            })
        }
    })
    .await?;

    if let Err(err) = result {
        match err.code {
            ErrorCode::BadRequest => return Err(ErrorBadRequest(err.msg)),
            ErrorCode::NotFound => return Err(ErrorNotFound(err.msg)),
            ErrorCode::InternalServer => return Err(ErrorInternalServerError(err.msg)),
        }
    }
    let new_user = result.unwrap();

    // Create JWT token
    let expiration = chrono::Utc::now() + chrono::Duration::minutes(30);
    let user_claim = UserClaim {
        exp: expiration.timestamp(),
        id: new_user.id,
        name: new_user.name,
        email: new_user.email,
    };
    dotenv().ok();
    let jwt_key = env::var("JWT_SECRET").expect("JWT Key must be set");

    let token = encode(
        &Header::default(),
        &user_claim,
        &EncodingKey::from_secret(jwt_key.as_ref()),
    )
    .map_err(ErrorInternalServerError)?;

    let res = TokenResponse { token };

    Ok(HttpResponse::Ok().json(res))
}

#[post("/users/login")]
async fn login(
    db_pool: web::Data<DbPool>,
    credentials: web::Json<LoginUser>,
) -> Result<HttpResponse, Error> {
    let plain_password = credentials.password.clone();
    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        users
            .filter(email.eq(credentials.email.to_owned()))
            .first::<User>(&mut conn)
            .optional()
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    let user = match result {
        Some(user) => user,
        None => return Err(ErrorBadRequest("Invalid credentials")),
    };

    let is_valid_password =
        verify(plain_password, &user.password).map_err(ErrorInternalServerError)?;

    if !is_valid_password {
        return Err(ErrorBadRequest("Invalid Password"));
    }

    let expiration = chrono::Utc::now() + chrono::Duration::minutes(30);
    let user_claim = UserClaim {
        exp: expiration.timestamp(),
        id: user.id,
        name: user.name,
        email: user.email,
    };
    dotenv().ok();
    let jwt_key = env::var("JWT_SECRET").map_err(ErrorInternalServerError)?;

    let token = encode(
        &Header::default(),
        &user_claim,
        &EncodingKey::from_secret(jwt_key.as_ref()),
    )
    .map_err(ErrorInternalServerError)?;

    let response = TokenResponse { token };

    Ok(HttpResponse::Ok().json(response))
}

#[put("/users/update/{id}")]
async fn update_user(
    db_pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
    user_form: web::Json<NewUser>,
) -> Result<HttpResponse, Error> {
    let count = web::block(move || {
        let mut conn = db_pool.get().expect("Failed to connect to the database");
        diesel::update(users.filter(id.eq(user_id.to_owned())))
            .set((
                name.eq(user_form.name.to_owned()),
                email.eq(user_form.email.to_owned()),
            ))
            .execute(&mut conn)
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    if count == 0 {
        Err(ErrorNotFound("User not exist"))
    } else {
        Ok(HttpResponse::Ok().body("Deleted user"))
    }
}

#[delete("/users/delete/{id}")]
async fn delete_user(
    db_pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
) -> Result<HttpResponse, Error> {
    let count = web::block(move || {
        let mut conn = db_pool.get().expect("Failed to connect to the database");
        diesel::delete(users.filter(id.eq(user_id.to_owned()))).execute(&mut conn)
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    if count == 0 {
        Err(ErrorNotFound("User not exist"))
    } else {
        Ok(HttpResponse::Ok().body("Deleted user"))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(get_users)
            .service(get_user_by_id)
            .service(create_new_user)
            .service(update_user)
            .service(delete_user)
            .service(login)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
