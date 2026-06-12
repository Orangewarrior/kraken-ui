#![forbid(unsafe_code)]

pub mod app;
pub mod config;
pub mod controllers;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
mod secrets;
pub mod security;
pub mod services;
pub mod state;
pub mod view;

pub use app::AppFactory;
