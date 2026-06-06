use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, post},
};
use tower_http::services::ServeDir;

use crate::{
    controllers::{acl, auth, dashboard, health, setup, waf},
    middleware::authentication::require_admin,
    state::AppState,
};

pub fn create(state: AppState) -> Router {
    let protected_routes = Router::new()
        .route("/kraken_ui/auth/painel_admin", get(dashboard::get))
        .route("/kraken_ui/auth/dashboard", get(dashboard::get))
        .route("/kraken_ui/auth/api/dashboard", get(dashboard::api))
        .route("/kraken_ui/auth/insert_user", get(acl::insert_user))
        .route(
            "/kraken_ui/auth/insert_user_action",
            post(acl::insert_user_action),
        )
        .route("/kraken_ui/auth/delete_user", get(acl::delete_user))
        .route(
            "/kraken_ui/auth/delete_user_action",
            post(acl::delete_user_action),
        )
        .route(
            "/kraken_ui/auth/edit_user",
            get(acl::edit_user).post(acl::edit_user_lookup),
        )
        .route(
            "/kraken_ui/auth/update_user_action",
            post(acl::update_user_action),
        )
        .route("/kraken_ui/auth/show_user_table", get(acl::show_user_table))
        .route("/kraken_ui/auth/api/operators", get(acl::api_operators))
        .route("/kraken_ui/auth/show_attacks", get(waf::show_attacks))
        .route("/kraken_ui/auth/api/attacks", get(waf::api_attacks))
        .route("/kraken_ui/auth/update_password", get(acl::update_password))
        .route(
            "/kraken_ui/auth/update_password_action",
            post(acl::update_password_action),
        )
        .route("/kraken_ui/auth/logout", post(auth::logout))
        .route_layer(middleware::from_fn(require_admin));

    Router::new()
        .route("/", get(|| async { Redirect::to("/kraken_ui/login") }))
        .route("/login", get(|| async { Redirect::to("/kraken_ui/login") }))
        .route(
            "/dashboard",
            get(|| async { Redirect::to("/kraken_ui/auth/painel_admin") }),
        )
        .route("/kraken_ui/login", get(auth::login_page))
        .route("/kraken_ui/test_login", post(auth::login_submit))
        .route("/kraken_ui/auth/first_time", post(setup::first_time))
        .route("/health", get(health::get))
        .nest_service("/static", ServeDir::new("src/view/static"))
        .merge(protected_routes)
        .with_state(state)
}
