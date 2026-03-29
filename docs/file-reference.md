# File Reference

## Root files

- `.gitignore`  
  Ignores Python cache and generated TLS key/cert files.

- `requirements.txt`  
  Python dependency list (`APScheduler` currently pinned).

- `shell.nix`  
  Nix dev shell with Python + FastAPI/Uvicorn/APScheduler and tools (`git`, `openssl`).

- `main.py`  
  Application entrypoint; parses CLI args, loads teams, initializes logs, and launches public+admin servers.

- `web_server.py`  
  Two FastAPI apps:
  - public scoreboard + submission UI/API
  - admin control panel + team management APIs

- `game_state.py`  
  Thread-safe shared game model (`GameState`, `Team`, `GameStatus`) with scoring/history persistence to SQLite.

- `scanner.py`  
  Background APScheduler job using direct TCP connect checks to scan expected service ports and apply penalties.

- `newflagvalidator.py`  
  Flag lifecycle logic:
  - generate per-team/per-service active flags
  - validate submissions by team token
  - block self-capture and duplicate submissions

- `event_logger.py`  
  File-based event logging (`service_events.log`, `flag_events.log`).

- `generate_ssl_cert.py`  
  Utility script for creating self-signed `cert.pem`/`key.pem`.

- `teams.json`  
  Team seed data loaded at startup (name, IP, token, expected ports, and state fields).

- `game_state.json`  
  Snapshot-style game state JSON (teams, status, histories).

- `service_events.log`  
  Service penalty event log generated/reset by server startup.

- `flag_events.log`  
  Flag submission event log generated/reset by server startup.

## docs/

- `docs/README.md`  
  Project overview, quick start, architecture, and operations summary.

- `docs/api-documentation.md`  
  HTTP endpoint reference for public/admin APIs and payloads.

- `docs/file-reference.md`  
  This file.
