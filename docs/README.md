# Game Server Documentation

This project is a Python FastAPI-based **CTF attack/defense game server** with:
- a public scoreboard + flag submission interface
- a localhost-only admin panel
- periodic service health scanning with score penalties
- per-team/per-service flag generation and validation

## Quick start

### Requirements
- Python 3.12+ recommended
- Python dependencies in `requirements.txt`

```bash
pip install -r requirements.txt
python main.py
```

Public UI/API: `http://0.0.0.0:5000`  
Admin UI/API: `http://127.0.0.1:5001`

## Optional HTTPS

```bash
python generate_ssl_cert.py
python main.py --ssl-cert cert.pem --ssl-key key.pem
```

## Runtime architecture

1. `main.py` loads teams from `teams.json`, initializes logs, and starts both FastAPI apps.
2. `web_server.py` serves:
   - public scoreboard and submission endpoints
   - admin controls and team-management endpoints
3. `scanner.py` runs scheduled direct TCP connect checks while game status is `running`.
4. `game_state.py` stores thread-safe game state, scoring, scan history, and flag history, backed by SQLite persistence.
5. `newflagvalidator.py` generates active flags and validates submissions.
   Active flags are persisted in SQLite and also cached in memory.
6. `event_logger.py` writes service and flag events to log files.

## Game flow

- Admin starts game (`POST /api/control/start`) from admin app.
- Scanner checks expected ports for each team.
- Missing services apply penalties after consecutive failures.
- Services call `POST /api/generate_flag` to rotate their own flags.
- Attackers submit captured flags to `POST /api/submit_flag` with their token.

## Configuration knobs (CLI)

`main.py` options:
- `--host` (default `0.0.0.0`)
- `--port` (default `5000`)
- `--admin-port` (default `5001`)
- `--scan-interval` (default `10`)
- `--penalty` (default `10`)
- `--flag-points` (default `50`)
- `--flag-stolen-penalty` (default `25`)
- `--enable-udp` (deprecated, ignored)
- `--ssl-cert`, `--ssl-key`
- `--debug`

## Additional docs

- API details: [`docs/api-documentation.md`](./api-documentation.md)
- File-by-file reference: [`docs/file-reference.md`](./file-reference.md)
