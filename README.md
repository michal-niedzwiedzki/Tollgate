# Tollgate

## Mock upstream

`examples/mock_upstream.py` is a stdlib-only HTTP server used as a deterministic paid upstream by
every later test and by the demo. It listens on `http://127.0.0.1:9000` and serves:

- `GET /ok` — `200 {"result":"ok"}`
- `GET /slow` — sleeps 5s, then `200`
- `GET /fail` — `500`
- `GET /echo` — `200`, echoing the received headers and query

Start it with:

```
python3 examples/mock_upstream.py
```

With the gateway and the mock upstream both running, `scripts/seed_providers.sh` registers three
providers pointing at it: `mock-ok`, `mock-slow` (`timeout_ms: 1000`), and `mock-fail`.
