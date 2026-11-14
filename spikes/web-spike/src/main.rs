//! T3 spike: Axum serving a Tailwind-styled page with a locally vendored ECharts chart.
//! Everything is embedded; the page makes zero external requests. Bound to localhost only.

use axum::{Router, http::header, response::IntoResponse, routing::get};

const INDEX: &str = include_str!("../static/index.html");
const CSS: &str = include_str!("../static/app.css");
const ECHARTS: &str = include_str!("../vendor/echarts.min.js");

async fn index() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], INDEX)
}
async fn css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css")], CSS)
}
async fn echarts() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/javascript")], ECHARTS)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(index))
        .route("/app.css", get(css))
        .route("/echarts.min.js", get(echarts));
    // 8099: 8080 is commonly taken on dev machines (it was here). Product port is configurable.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8099").await.unwrap();
    println!("listening on http://127.0.0.1:8099");
    axum::serve(listener, app).await.unwrap();
}
