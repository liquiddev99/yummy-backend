use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
use dotenvy::dotenv;
use std::env;

mod db;
mod routes;
mod types;

use routes::users::{
    delete_user, get_profile, get_user_by_id, get_users, login, logout, signup, update_user,
};

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
            .supports_credentials()
            .max_age(3600);
        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(get_users)
            .service(get_user_by_id)
            .service(signup)
            .service(update_user)
            .service(delete_user)
            .service(login)
            .service(logout)
            .service(get_profile)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
