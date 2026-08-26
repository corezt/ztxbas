# ZTXBAS Node/TypeScript quickstart

End-to-end demo: enroll → challenge → JWT verify, using the Node SDK.

## Prereqs

- A running ZTXBAS server.
- Application id + HMAC secret. Create one from the admin console
  (**Applications → New application**) or via CLI:
  `docker exec <container> ztxbas app create <name>`.
- Node 18 or newer.
- CoreZT authenticator installed on your phone.

## Run

```bash
export ZTXBAS_URL=https://ztxbas.example.com
export ZTXBAS_APP_ID=app_xxx
export ZTXBAS_SECRET=hex...
export ZTXBAS_USER_EMAIL=alice@example.com
export ZTXBAS_ORIGIN=https://app.example.com

npm install
npm start
```

On first run, complete the mobile enrollment before the challenge times
out. Subsequent runs push the challenge immediately.

## What it does

Same flow as the Go quickstart — see [quickstart.ts](quickstart.ts) for
the annotated version.
