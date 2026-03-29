# API Documentation

Base URLs:
- Public API/UI: `http://<server>:5000` (or HTTPS when configured)
- Admin API/UI: `http://127.0.0.1:5001`

All API endpoints return JSON.

## Public endpoints

### `GET /api/scoreboard`
Returns scoreboard data and basic game info. Public response strips team tokens.

### `GET /api/events`
Returns recent **valid** flag capture events only (timestamp, attacker, victim, points).

### `POST /api/generate_flag`
Generate/rotate the active flag for a team service.

Security behavior:
- Caller IP must match a registered team IP.
- Request `team` must match the team bound to that caller IP.

Request body:
```json
{
  "team": "sohail",
  "service": "web-server"
}
```

Success:
```json
{
  "success": true,
  "flag": "FLAG{sohail_web-server_<random>}",
  "message": "Flag generated successfully"
}
```

Failure examples:
- 403: IP not registered or team/IP mismatch
- 400: missing fields or unknown team

### `POST /api/submit_flag`
Submit a captured flag.

Request body:
```json
{
  "flag": "FLAG{...}",
  "token": "token-teamname-..."
}
```

Behavior:
- Game must be `running`.
- Token maps to attacker team.
- Self-capture is blocked.
- Duplicate flag submissions by same team are blocked.

Success:
```json
{
  "success": true,
  "message": "Valid flag! Captured <victim>'s <service> service",
  "points": 50
}
```

Failure:
```json
{
  "success": false,
  "message": "<reason>",
  "points": 0
}
```

## Admin endpoints

### `GET /api/scoreboard`
Full scoreboard including team tokens and scanner status.

### `POST /api/control/<action>`
Control game lifecycle.

`<action>` values:
- `start` -> status `running`, scanner starts
- `pause` -> status `paused`
- `stop` -> status `finished`, scanner stops
- `reset` -> resets team state/scores

### `POST /api/teams`
Add a team.

Request body:
```json
{
  "name": "teamname",
  "ip": "192.168.1.50",
  "expected_tcp_ports": [22, 80, 443]
}
```

Server auto-generates the team token.

### `DELETE /api/teams/<team_name>`
Delete a team by name.

### `POST /api/teams/<team_name>/pause_scan`
Pause scanner checks for one team.

### `POST /api/teams/<team_name>/resume_scan`
Resume scanner checks for one team.

## HTTPS notes

When using self-signed certs:
- `curl`: add `-k`
- Python `requests`: set `verify=False`
