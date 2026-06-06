# KrakenWaf local image assets

All PNG files in this directory are local static assets intended to be served by Axum `ServeDir` or a normal static web server. They are compatible with this CSP:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
```

Do not load images from remote CDNs in production unless you intentionally loosen the CSP.
