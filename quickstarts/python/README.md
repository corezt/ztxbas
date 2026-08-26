# ZTXBAS Python quickstart

End-to-end demo: enroll → challenge → JWT verify, using the Python SDK.

## Prereqs

- A running ZTXBAS server.
- Application id + HMAC secret. Create one from the admin console
  (**Applications → New application**) or via CLI:
  `docker exec <container> ztxbas app create <name>`.
- Python 3.9 or newer.
- CoreZT authenticator installed on your phone.

## Run

```bash
export ZTXBAS_URL=https://ztxbas.example.com
export ZTXBAS_APP_ID=app_xxx
export ZTXBAS_SECRET=hex...
export ZTXBAS_USER_EMAIL=alice@example.com
export ZTXBAS_ORIGIN=https://app.example.com

# From this directory, using the sibling SDK in the monorepo:
pip install -e ../../sdk-python

# Or, once published:
# pip install -r requirements.txt

python quickstart.py
```

On first run, complete the mobile enrollment before the challenge times
out. Subsequent runs push the challenge immediately.

## What it does

Same flow as the Go and Node quickstarts — see
[quickstart.py](quickstart.py) for the annotated version.
