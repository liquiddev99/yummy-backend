use actix_web::{delete, get, post, put, web, App, HttpResponse, HttpServer, Responder};
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
async fn get_users(db_pool: web::Data<DbPool>) -> impl Responder {
    let mut conn = db_pool
        .get()
        .expect("Failed to get a connection from the pool");
    let results = users.load::<User>(&mut conn).unwrap_or_default();
    HttpResponse::Ok().json(results)
}

#[get("/users/{id}")]
async fn get_user_by_id(db_pool: web::Data<DbPool>, user_id: web::Path<Uuid>) -> impl Responder {
    let mut conn = db_pool
        .get()
        .expect("Failed to get a connection from the pool");
    let result = users
        .filter(id.eq(user_id.to_owned()))
        .first::<User>(&mut conn);

    match result {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(err) => HttpResponse::NotFound().body(err.to_string()),
    }
}

#[post("/users/create")]
async fn create_new_user(db_pool: web::Data<DbPool>, new_user: web::Json<NewUser>) -> HttpResponse {
    let mut conn = db_pool
        .get()
        .expect("Failed to get a connection from the pool");
    diesel::insert_into(users)
        .values(&*new_user)
        .execute(&mut conn)
        .expect("Error");
    HttpResponse::Ok().json(new_user)
}

#[put("/users/update/{id}")]
async fn update_user(
    db_pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
    user_form: web::Json<NewUser>,
) -> HttpResponse {
    web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        diesel::update(users.filter(id.eq(user_id.to_owned())))
            .set((
                name.eq(user_form.name.to_owned()),
                email.eq(user_form.email.to_owned()),
            ))
            .execute(&mut conn)
            .expect("Error");
    })
    .await
    .expect("Error");
    HttpResponse::Ok().body("Updated user")
}

#[delete("/users/delete/{id}")]
async fn delete_user(db_pool: web::Data<DbPool>, user_id: web::Path<Uuid>) -> HttpResponse {
    let mut conn = db_pool
        .get()
        .expect("Failed to get a connection from the pool");
    let result = diesel::delete(users.filter(id.eq(user_id.to_owned()))).execute(&mut conn);

    match result {
        Ok(count) => {
            if count != 0 {
                HttpResponse::Ok().body("Deleted user")
            } else {
                HttpResponse::NotFound().body("User not exists")
            }
        }
        Err(err) => HttpResponse::NotFound().body(err.to_string()),
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
