# Deployment

MailRecon is local-first by default, but the development frontend can be configured to call a separately served API with `VITE_API_URL`.

## Local development

The default frontend API URL is:

```text
http://127.0.0.1:8000/api
```

The backend default CSP permits both `127.0.0.1:8000` and `localhost:8000` for `connect-src`.

## Separate frontend/API deployment

When the frontend is built with a non-local `VITE_API_URL`, configure the backend's CSP allowlist to include the API origin(s):

```text
MAILRECON_CSP_CONNECT_SRC=https://api.example.com
```

Multiple explicit origins may be separated by spaces:

```text
MAILRECON_CSP_CONNECT_SRC=https://api.example.com https://api2.example.com
```

Do not use `*` for `MAILRECON_CSP_CONNECT_SRC`. The setting is inserted only into the CSP `connect-src` directive; the existing script, frame, form, image, and default-origin restrictions remain in place.

`VITE_API_URL` and `MAILRECON_CSP_CONNECT_SRC` are deployment settings for the same API topology: the frontend build determines where browser requests go, while the backend determines which API origins the browser is permitted to contact.
