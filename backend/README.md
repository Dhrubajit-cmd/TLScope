# TLScope backend

## Local development

Run the local HTTP server from this directory:

```bash
go run ./cmd/tlscope -port 8080
```

The React development server proxies `/api` requests to this server.

## Vercel

Vercel serves `api/index.go` as a Go Function. Do not add a `main.go` file to
this directory: a root-level executable makes Vercel treat the project as a
long-running Go server instead of a serverless API.

Set this production environment variable in Vercel:

```text
TLSCOPE_ALLOWED_ORIGINS=https://tlscope.dhrubajit.dev
```
