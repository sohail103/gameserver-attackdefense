"""
web_server.py

FastAPI web servers for CTF game interface.
- Public server: Scoreboard and flag submission (accessible to teams)
- Admin server: Game controls (localhost only)
"""

import logging
import secrets
from threading import Thread

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment

from game_state import game_state, GameStatus, Team
from scanner import scanner
from newflagvalidator import flag_validator

logger = logging.getLogger("web_server")

# Create two separate FastAPI apps
public_app = FastAPI(title="CTF Public API")
admin_app = FastAPI(title="CTF Admin API")
template_env = Environment(autoescape=True)


# ===== PUBLIC SCOREBOARD TEMPLATE ===== #
PUBLIC_SCOREBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CTF Scoreboard</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            margin: 0;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { text-align: center; color: #00ff00; text-shadow: 0 0 10px #00ff00; }
        .status {
            text-align: center;
            padding: 10px;
            margin: 20px 0;
            border: 2px solid #00ff00;
            background: #001a00;
        }
        .status.running { border-color: #00ff00; color: #00ff00; }
        .status.waiting { border-color: #ffaa00; color: #ffaa00; }
        .status.paused { border-color: #ff0000; color: #ff0000; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 0 20px rgba(0,255,0,0.2);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #00ff00;
        }
        th {
            background: #003300;
            color: #00ff00;
            font-weight: bold;
        }
        tr:nth-child(even) { background: #001100; }
        tr:hover { background: #002200; }
        .rank { font-weight: bold; font-size: 1.2em; }
        .score { font-weight: bold; color: #00ff00; }
        .info { 
            text-align: center; 
            margin: 10px 0;
            color: #888;
        }
        .flag-form {
            max-width: 600px;
            margin: 30px auto;
            padding: 20px;
            border: 2px solid #00ff00;
            background: #001a00;
        }
        .flag-form h2 {
            margin-top: 0;
            color: #00ff00;
        }
        .form-group {
            margin: 15px 0;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #00ff00;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 10px;
            background: #003300;
            border: 1px solid #00ff00;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            box-sizing: border-box;
        }
        button {
            background: #003300;
            color: #00ff00;
            border: 2px solid #00ff00;
            padding: 10px 20px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            width: 100%;
        }
        button:hover {
            background: #00ff00;
            color: #000000;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border: 2px solid;
            display: none;
        }
        .message.success {
            border-color: #00ff00;
            background: #001a00;
            color: #00ff00;
        }
        .message.error {
            border-color: #ff0000;
            background: #1a0000;
            color: #ff0000;
        }
        .event-log {
            max-width: 600px;
            margin: 30px auto;
            padding: 20px;
            border: 2px solid #00ff00;
            background: #001a00;
        }
        .event-log h2 {
            margin-top: 0;
            color: #00ff00;
        }
        .event-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .event-item {
            padding: 8px 0;
            border-bottom: 1px solid #003300;
            color: #00cc00;
        }
        .event-item:last-child {
            border-bottom: none;
        }
        .event-time {
            color: #888;
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚔️ CTF ATTACK/DEFENSE SCOREBOARD ⚔️</h1>
        
        <div class="status {{ game_info.status }}">
            <strong>Game Status:</strong> {{ game_info.status.upper() }}
            {% if game_info.start_time %}
            | Started: {{ game_info.start_time | timestamp }}
            {% endif %}
        </div>

        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Team</th>
                    <th>IP Address</th>
                    <th>Score</th>
                    <th>Flags</th>
                    <th>Services Down</th>
                    <th>Last Scan</th>
                </tr>
            </thead>
            <tbody>
                {% for team in scoreboard %}
                <tr>
                    <td class="rank">#{{ team.rank }}</td>
                    <td>{{ team.name }}</td>
                    <td>{{ team.ip }}</td>
                    <td class="score">{{ team.score }}</td>
                    <td>{{ team.flags_captured }}</td>
                    <td>{{ team.services_down }}</td>
                    <td>{% if team.last_scan %}{{ team.last_scan | timestamp }}{% else %}Never{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div class="flag-form">
            <h2>🚩 Submit Flag</h2>
            <div id="message" class="message"></div>
            <form id="flagForm">
                <div class="form-group">
                    <label for="team">Your Team:</label>
                    <select id="team" name="team" required>
                        <option value="">-- Select Team --</option>
                        {% for team in scoreboard %}
                        <option value="{{ team.name }}">{{ team.name }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                    <label for="token">Your Secret Token:</label>
                    <input type="text" id="token" name="token" placeholder="token-teamname-..." required>
                </div>
                <div class="form-group">
                    <label for="flag">Flag:</label>
                    <input type="text" id="flag" name="flag" placeholder="FLAG{...}" required>
                </div>
                <button type="submit">Submit Flag</button>
            </form>
        </div>

        <div class="event-log">
            <h2>📢 Event Log</h2>
            <ul id="eventList" class="event-list">
                <!-- Events will be dynamically inserted here -->
            </ul>
        </div>

        <div class="info">
            Scans: {{ game_info.scan_count }} | 
            Flags Submitted: {{ game_info.flag_submissions }}
        </div>
    </div>

    <script>
        document.getElementById('flagForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const team = document.getElementById('team').value;
            const token = document.getElementById('token').value;
            const flag = document.getElementById('flag').value;
            const messageDiv = document.getElementById('message');
            
            fetch('/api/submit_flag', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ team: team, token: token, flag: flag })
            })
            .then(r => r.json())
            .then(data => {
                messageDiv.textContent = data.message + (data.points ? ' (+' + data.points + ' points)' : '');
                messageDiv.className = 'message ' + (data.success ? 'success' : 'error');
                messageDiv.style.display = 'block';
                
                if (data.success) {
                    document.getElementById('flag').value = '';
                    setTimeout(() => location.reload(), 2000);
                }
            })
            .catch(err => {
                messageDiv.textContent = 'Error: ' + err;
                messageDiv.className = 'message error';
                messageDiv.style.display = 'block';
            });
        });
    </script>
    <script>
        function formatTime(unixTimestamp) {
            const date = new Date(unixTimestamp * 1000);
            const hours = date.getHours().toString().padStart(2, '0');
            const minutes = date.getMinutes().toString().padStart(2, '0');
            const seconds = date.getSeconds().toString().padStart(2, '0');
            return `${hours}:${minutes}:${seconds}`;
        }

        function updateEventLog() {
            const eventList = document.getElementById('eventList');
            fetch('/api/events')
                .then(r => r.json())
                .then(events => {
                    eventList.innerHTML = ''; // Clear old events
                    if (events.length === 0) {
                        eventList.innerHTML = '<li class="event-item">No events yet.</li>';
                        return;
                    }
                    events.forEach(event => {
                        const item = document.createElement('li');
                        item.className = 'event-item';
                        item.innerHTML = `
                            <span class="event-time">[${formatTime(event.timestamp)}]</span>
                            <strong>${event.attacker}</strong> captured <strong>${event.victim}</strong>'s flag!
                            <span class="score">(+${event.points})</span>
                        `;
                        eventList.appendChild(item);
                    });
                })
                .catch(err => {
                    console.error("Error fetching events:", err);
                    eventList.innerHTML = '<li class="event-item error">Could not load events.</li>';
                });
        }

        // Update on page load and then every 10 seconds
        updateEventLog();
        setInterval(updateEventLog, 10000);
    </script>
</body>
</html>
"""


# ===== ADMIN CONTROL TEMPLATE ===== #
ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CTF Admin Panel</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #ff6600;
            margin: 0;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { text-align: center; color: #ff6600; text-shadow: 0 0 10px #ff6600; }
        .warning {
            text-align: center;
            padding: 15px;
            margin: 20px 0;
            border: 2px solid #ff0000;
            background: #1a0000;
            color: #ff6600;
            font-weight: bold;
        }
        .status {
            text-align: center;
            padding: 10px;
            margin: 20px 0;
            border: 2px solid #ff6600;
            background: #1a0a00;
        }
        .status.running { border-color: #00ff00; color: #00ff00; }
        .status.waiting { border-color: #ffaa00; color: #ffaa00; }
        .status.paused { border-color: #ff0000; color: #ff0000; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 0 20px rgba(255,102,0,0.2);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ff6600;
        }
        th {
            background: #331100;
            color: #ff6600;
            font-weight: bold;
        }
        tr:nth-child(even) { background: #110500; }
        tr:hover { background: #221100; }
        .rank { font-weight: bold; font-size: 1.2em; }
        .score { font-weight: bold; color: #ff6600; }
        .controls {
            text-align: center;
            margin: 30px 0;
        }
        button {
            background: #331100;
            color: #ff6600;
            border: 2px solid #ff6600;
            padding: 10px 20px;
            margin: 0 5px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        button:hover {
            background: #ff6600;
            color: #000000;
        }
        .info { 
            text-align: center; 
            margin: 10px 0;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 CTF ADMIN PANEL 🔒</h1>
        
        <div class="warning">
            ⚠️ ADMIN ONLY - This interface is for game organizers ⚠️
        </div>
        
        <div class="status {{ game_info.status }}">
            <strong>Game Status:</strong> {{ game_info.status.upper() }}
            {% if game_info.start_time %}
            | Started: {{ game_info.start_time | timestamp }}
            {% endif %}
        </div>

        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Team</th>
                    <th>IP Address</th>
                    <th>Token</th>
                    <th>Score</th>
                    <th>Flags</th>
                    <th>Services Down</th>
                    <th>Last Scan</th>
                </tr>
            </thead>
            <tbody>
                {% for team in scoreboard %}
                <tr>
                    <td class="rank">#{{ team.rank }}</td>
                    <td>{{ team.name }}</td>
                    <td>{{ team.ip }}</td>
                    <td>{{ team.token }}</td>
                    <td class="score">{{ team.score }}</td>
                    <td>{{ team.flags_captured }}</td>
                    <td>{{ team.services_down }}</td>
                    <td>{% if team.last_scan %}{{ team.last_scan | timestamp }}{% else %}Never{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div class="controls">
            <button onclick="controlGame('start')">▶️ Start Game</button>
            <button onclick="controlGame('pause')">⏸️ Pause Game</button>
            <button onclick="controlGame('stop')">⏹️ Stop Game</button>
            <button onclick="controlGame('reset')">🔄 Reset Game</button>
            <button onclick="location.reload()">🔄 Refresh</button>
        </div>

        <div class="info">
            Scanner: {{ 'ACTIVE' if scanner_running else 'STOPPED' }} | 
            Scans: {{ game_info.scan_count }} | 
            Flags Submitted: {{ game_info.flag_submissions }}
        </div>

        <div class="team-management">
            <h2>Team Management</h2>
            <form id="addTeamForm">
                <input type="text" id="teamName" placeholder="Team Name" required>
                <input type="text" id="teamIP" placeholder="IP Address" required>
                <input type="text" id="teamPorts" placeholder="Ports (comma-separated)" required>
                <button type="submit">Add Team</button>
            </form>
            <table id="teamsTable">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP</th>
                        <th>Ports</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for team in scoreboard %}
                    <tr>
                        <td>{{ team.name }}</td>
                        <td>{{ team.ip }}</td>
                        <td>{{ team.expected_tcp_ports | join(', ') }}</td>
                        <td>
                            <button onclick="deleteTeam('{{ team.name }}')">Delete</button>
                            <button onclick="toggleScan('{{ team.name }}', {{ 'true' if team.scanning_paused else 'false' }})">
                                {{ 'Resume Scan' if team.scanning_paused else 'Pause Scan' }}
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function controlGame(action) {
            if (action === 'reset') {
                if (!confirm('Are you sure you want to reset the entire game state? This cannot be undone.')) {
                    return;
                }
            }
            fetch('/api/control/' + action, { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    alert(data.message);
                    location.reload();
                })
                .catch(err => alert('Error: ' + err));
        }

        function deleteTeam(teamName) {
            if (!confirm('Are you sure you want to delete ' + teamName + '?')) return;
            fetch('/api/teams/' + teamName, { method: 'DELETE' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(err => alert('Error: ' + err));
        }

        function toggleScan(teamName, isPaused) {
            const action = isPaused ? 'resume_scan' : 'pause_scan';
            fetch('/api/teams/' + teamName + '/' + action, { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(err => alert('Error: ' + err));
        }

        document.getElementById('addTeamForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const name = document.getElementById('teamName').value;
            const ip = document.getElementById('teamIP').value;
            const ports = document.getElementById('teamPorts').value.split(',').map(p => parseInt(p.trim()));
            
            fetch('/api/teams', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, ip, expected_tcp_ports: ports })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(err => alert('Error: ' + err));
        });
    </script>
</body>
</html>
"""


def timestamp_filter(ts):
    if ts is None:
        return "N/A"
    import datetime

    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S")


template_env.filters["timestamp"] = timestamp_filter


def render_inline_template(template_text: str, **context) -> HTMLResponse:
    template = template_env.from_string(template_text)
    return HTMLResponse(template.render(**context))


# ===== PUBLIC ENDPOINTS ===== #
@public_app.get("/", response_class=HTMLResponse)
async def public_index():
    scoreboard = game_state.get_scoreboard()
    game_info = game_state.get_game_info()

    return render_inline_template(
        PUBLIC_SCOREBOARD_TEMPLATE,
        scoreboard=scoreboard,
        game_info=game_info,
    )


@public_app.get("/api/scoreboard")
async def public_api_scoreboard():
    scoreboard = game_state.get_scoreboard()
    for team in scoreboard:
        team.pop("token", None)

    return {
        "scoreboard": scoreboard,
        "game_info": {
            "status": game_state.get_status().value,
            "start_time": game_state.get_game_info()["start_time"],
        },
    }


@public_app.get("/api/events")
async def public_api_events():
    events = game_state.get_recent_events()
    sanitized_events = [
        {
            "timestamp": event["timestamp"],
            "attacker": event["attacker"],
            "victim": event["victim"],
            "points": event["points"],
        }
        for event in events
    ]
    return sanitized_events


@public_app.post("/api/generate_flag")
async def public_generate_flag(request: Request):
    ip_addr = request.client.host if request.client else ""
    if ip_addr == "::1":
        ip_addr = "127.0.0.1"

    requesting_team = None
    for team in game_state.get_all_teams().values():
        if team.ip == ip_addr:
            requesting_team = team
            break

    if not requesting_team:
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "flag": "",
                "message": "Your IP is not registered to a team.",
            },
        )

    try:
        data = await request.json()
    except Exception:
        data = None

    if not data or "team" not in data or "service" not in data:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "flag": "",
                "message": "Missing 'team' or 'service' field",
            },
        )

    team_name = data["team"]
    service_name = data["service"]

    if requesting_team.name != team_name:
        logger.warning(
            "IP %s for team %s tried to generate a flag for team %s",
            ip_addr,
            requesting_team.name,
            team_name,
        )
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "flag": "",
                "message": "You can only generate flags for your own team.",
            },
        )

    success, flag, message = flag_validator.generate_flag(team_name, service_name)

    if not success:
        return JSONResponse(
            status_code=400,
            content={"success": False, "flag": "", "message": message},
        )

    return {"success": True, "flag": flag, "message": message}


@public_app.post("/api/submit_flag")
async def public_submit_flag(request: Request):
    try:
        data = await request.json()
        if not data:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Invalid JSON data"},
            )
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Invalid JSON format"},
        )

    if "flag" not in data or "token" not in data:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Missing 'flag' or 'token' field"},
        )

    flag = data["flag"]
    token = data["token"]

    if game_state.get_status() != GameStatus.RUNNING:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Game is not running"},
        )

    is_valid, message, points = flag_validator.validate_submission(token, flag)

    return {"success": is_valid, "message": message, "points": points}


# ===== ADMIN ENDPOINTS ===== #
@admin_app.get("/", response_class=HTMLResponse)
async def admin_index():
    scoreboard = game_state.get_scoreboard()
    game_info = game_state.get_game_info()
    scanner_running = scanner.is_running()

    return render_inline_template(
        ADMIN_TEMPLATE,
        scoreboard=scoreboard,
        game_info=game_info,
        scanner_running=scanner_running,
    )


@admin_app.get("/api/scoreboard")
async def admin_api_scoreboard():
    return {
        "scoreboard": game_state.get_scoreboard(),
        "game_info": game_state.get_game_info(),
        "scanner_running": scanner.is_running(),
    }


@admin_app.post("/api/control/{action}")
async def admin_control_game(action: str):
    if action == "start":
        game_state.set_status(GameStatus.RUNNING)
        if not scanner.is_running():
            scanner.start()
        return {"success": True, "message": "Game started!"}

    if action == "pause":
        game_state.set_status(GameStatus.PAUSED)
        return {"success": True, "message": "Game paused"}

    if action == "stop":
        game_state.set_status(GameStatus.FINISHED)
        scanner.stop()
        return {"success": True, "message": "Game stopped"}

    if action == "reset":
        game_state.reset_game_state()
        flag_validator.clear_active_flags()
        return {"success": True, "message": "Game state has been reset."}

    return JSONResponse(
        status_code=400, content={"success": False, "message": "Unknown action"}
    )


@admin_app.post("/api/teams")
async def admin_add_team(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = None

    if (
        not data
        or "name" not in data
        or "ip" not in data
        or "expected_tcp_ports" not in data
    ):
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Missing required fields"},
        )

    try:
        expected_ports = [int(port) for port in data["expected_tcp_ports"]]
    except (TypeError, ValueError):
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "expected_tcp_ports must be a list of integers",
            },
        )

    try:
        team = Team(
            name=data["name"],
            ip=data["ip"],
            token=f"token-{data['name']}-{secrets.token_hex(8)}",
            expected_tcp_ports=expected_ports,
        )
        game_state.add_team(team)
        return {"success": True, "message": "Team added successfully"}
    except ValueError as e:
        return JSONResponse(
            status_code=400, content={"success": False, "message": str(e)}
        )


@admin_app.delete("/api/teams/{team_name}")
async def admin_delete_team(team_name: str):
    try:
        flag_validator.remove_team_flags(team_name)
        game_state.delete_team(team_name)
        return {"success": True, "message": "Team deleted successfully"}
    except ValueError as e:
        return JSONResponse(
            status_code=400, content={"success": False, "message": str(e)}
        )


@admin_app.post("/api/teams/{team_name}/{action}")
async def admin_team_action(team_name: str, action: str):
    try:
        if action == "pause_scan":
            game_state.update_team(team_name, {"scanning_paused": True})
            return {"success": True, "message": "Scanning paused for " + team_name}
        if action == "resume_scan":
            game_state.update_team(team_name, {"scanning_paused": False})
            return {"success": True, "message": "Scanning resumed for " + team_name}

        return JSONResponse(
            status_code=400, content={"success": False, "message": "Unknown action"}
        )
    except ValueError as e:
        return JSONResponse(
            status_code=400, content={"success": False, "message": str(e)}
        )


def run_public_server(host="0.0.0.0", port=5000, ssl_cert=None, ssl_key=None):
    certfile = ssl_cert if ssl_cert and ssl_key else None
    keyfile = ssl_key if ssl_cert and ssl_key else None
    if certfile and keyfile:
        logger.info("Using SSL: cert=%s key=%s", certfile, keyfile)

    logger.info("Starting PUBLIC server on %s:%d", host, port)
    uvicorn.run(
        public_app,
        host=host,
        port=port,
        log_level="info",
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
    )


def run_admin_server(host="127.0.0.1", port=5001):
    logger.info("Starting ADMIN server on %s:%d (localhost only)", host, port)
    uvicorn.run(admin_app, host=host, port=port, log_level="info")


def run_both_servers(
    public_host="0.0.0.0",
    public_port=5000,
    admin_host="127.0.0.1",
    admin_port=5001,
    ssl_cert=None,
    ssl_key=None,
):
    """Run both public and admin servers in separate threads"""

    public_thread = Thread(
        target=run_public_server,
        args=(public_host, public_port, ssl_cert, ssl_key),
        daemon=True,
        name="public-server",
    )
    public_thread.start()

    run_admin_server(admin_host, admin_port)
