use actix_web::{
    delete, error::ErrorInternalServerError, get, post, put, web, App, Error, HttpResponse,
    HttpServer,
};
use diesel::pg::PgConnection;
use diesel::{
    prelude::*,
    r2d2::{self, ConnectionManager},
};
use dotenvy::dotenv;
use std::env;
use uuid::Uuid;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

mod db;

use db::models::{NewUser, User};
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
    let user = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        users
            .filter(id.eq(user_id.to_owned()))
            .first::<User>(&mut conn)
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(user))
}

#[post("/users/create")]
async fn create_new_user(
    db_pool: web::Data<DbPool>,
    new_user_form: web::Json<NewUser>,
) -> Result<HttpResponse, Error> {
    let new_user = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        diesel::insert_into(users)
            .values(new_user_form.into_inner())
            .get_result::<User>(&mut conn)
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(new_user))
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
        Ok(HttpResponse::NotFound().body("User not exist"))
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
        Ok(HttpResponse::NotFound().body("User not exist"))
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
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(get_users)
            .service(get_user_by_id)
            .service(create_new_user)
            .service(update_user)
            .service(delete_user)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
