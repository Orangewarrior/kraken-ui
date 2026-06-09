use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, post},
};
use tower_http::services::ServeDir;

use crate::{
    controllers::{acl, auth, dashboard, health, mfa, setup, waf},
    middleware::authentication::{require_admin, require_attack_viewer, require_operator},
    state::AppState,
};

pub fn create(state: AppState) -> Router {
    // Routes only an administrator may reach: the full ACL management surface.
    let admin_routes = Router::new()
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
        .route_layer(middleware::from_fn(require_admin));

    // Day-to-day console routes shared by administrators and operators. The
    // sidebar drops the ACL section for operators, but the dashboard, attacks
    // table and self-service password change are identical.
    let operator_routes = Router::new()
        .route("/kraken_ui/auth/admin_panel", get(dashboard::get))
        .route("/kraken_ui/auth/dashboard", get(dashboard::get))
        .route("/kraken_ui/auth/api/dashboard", get(dashboard::api))
        .route("/kraken_ui/auth/show_attacks", get(waf::show_attacks))
        .route("/kraken_ui/auth/api/attacks", get(waf::api_attacks))
        .route("/kraken_ui/auth/update_password", get(acl::update_password))
        .route(
            "/kraken_ui/auth/update_password_action",
            post(acl::update_password_action),
        )
        // Self-service two-factor management, open to admins and operators alike.
        .route("/kraken_ui/auth/mfa", get(mfa::mfa_overview))
        .route("/kraken_ui/auth/mfa_enroll", post(mfa::mfa_enroll))
        .route("/kraken_ui/auth/mfa_confirm", post(mfa::mfa_confirm))
        .route("/kraken_ui/auth/mfa_disable", post(mfa::mfa_disable))
        .route("/kraken_ui/auth/mfa_regenerate", post(mfa::mfa_regenerate))
        .route("/kraken_ui/auth/logout", post(auth::logout))
        .route_layer(middleware::from_fn(require_operator));

    // The single-attack detail view is also available to auditors.
    let attack_view_routes = Router::new()
        .route(
            "/kraken_ui/auth/view_waf_request/",
            get(waf::view_waf_request),
        )
        .route_layer(middleware::from_fn(require_attack_viewer));

    Router::new()
        .route("/", get(|| async { Redirect::to("/kraken_ui/login") }))
        .route("/login", get(|| async { Redirect::to("/kraken_ui/login") }))
        .route(
            "/dashboard",
            get(|| async { Redirect::to("/kraken_ui/auth/admin_panel") }),
        )
        .route("/kraken_ui/login", get(auth::login_page))
        .route("/kraken_ui/test_login", post(auth::login_submit))
        // The two-factor challenge sits between a correct password and a full
        // session; it authorises itself from the pending marker on the session.
        .route(
            "/kraken_ui/auth/mfa_challenge",
            get(auth::mfa_challenge_page),
        )
        .route("/kraken_ui/auth/mfa_verify", post(auth::mfa_verify))
        .route("/kraken_ui/auth/first_time", post(setup::first_time))
        .route("/health", get(health::get))
        .nest_service("/static", ServeDir::new("src/view/static"))
        .merge(admin_routes)
        .merge(operator_routes)
        .merge(attack_view_routes)
        .with_state(state)
}
