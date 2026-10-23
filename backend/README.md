# TLScope backend

## Local development

Run the local HTTP server from this directory:

```bash
go run ./cmd/server -port 8080
```

The React development server proxies `/api` requests to this server.

## Vercel

Vercel runs `cmd/server/main.go` as its managed Go backend. The executable
uses Vercel's `PORT` automatically and listens on `0.0.0.0` in production;
local development remains bound to `127.0.0.1:8080`.

Set this production environment variable in Vercel:

```text
TLSCOPE_ALLOWED_ORIGINS=https://tlscope.dhrubajit.dev
```
