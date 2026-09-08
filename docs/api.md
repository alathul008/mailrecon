# API

FastAPI generates OpenAPI documentation automatically at `/docs`.

Create an investigation:

```http
POST /api/investigations
Content-Type: application/json

{"email":"target@example.com","privacy_mode":true}
```

Poll `GET /api/investigations/{id}` until `status` is `completed` or `failed`.
