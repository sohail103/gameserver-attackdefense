"""
game_state.py

Shared state for the CTF game server.
Thread-safe management of teams, scores, and game status.
State is persisted to SQLite so scores and logs survive restarts.
"""

import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class GameStatus(Enum):
    WAITING = "waiting"
    RUNNING = "running"
    PAUSED = "paused"
    FINISHED = "finished"


@dataclass
class Team:
    name: str
    ip: str
    token: str
    expected_tcp_ports: List[int]
    expected_udp_ports: List[int] = field(default_factory=list)
    score: int = 1000
    flags_captured: int = 0
    services_down: List[int] = field(default_factory=list)
    consecutive_failures: Dict[int, int] = field(default_factory=dict)
    last_scan: Optional[float] = None
    scanning_paused: bool = False


class GameState:
    def __init__(self):
        self._lock = threading.Lock()
        self._teams: Dict[str, Team] = {}
        self._status = GameStatus.WAITING
        self._game_start_time: Optional[float] = None
        self._scan_history: List[Dict] = []
        self._flag_history: List[Dict] = []
        self._db_path = "game_state.db"

        self.penalty_per_port = 10
        self.flag_points = 50
        self.flag_stolen_penalty = 25
        self.scan_interval = 10
        self.enable_udp = False

        self._initialize_db()
        self._load_from_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_db(self):
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS teams (
                    name TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    token TEXT NOT NULL,
                    expected_tcp_ports TEXT NOT NULL,
                    expected_udp_ports TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    flags_captured INTEGER NOT NULL,
                    services_down TEXT NOT NULL,
                    consecutive_failures TEXT NOT NULL,
                    last_scan REAL,
                    scanning_paused INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS game_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    team TEXT NOT NULL,
                    missing_ports TEXT NOT NULL,
                    penalty INTEGER NOT NULL,
                    score INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS flag_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    attacker TEXT NOT NULL,
                    victim TEXT NOT NULL,
                    flag TEXT NOT NULL,
                    points INTEGER NOT NULL,
                    valid INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS active_flags (
                    team_name TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    flag TEXT NOT NULL UNIQUE,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(team_name, service_name)
                );
                """
            )

    def _serialize_team(self, team: Team) -> tuple:
        return (
            team.name,
            team.ip,
            team.token,
            json.dumps(team.expected_tcp_ports),
            json.dumps(team.expected_udp_ports),
            team.score,
            team.flags_captured,
            json.dumps(team.services_down),
            json.dumps(team.consecutive_failures),
            team.last_scan,
            1 if team.scanning_paused else 0,
        )

    def _upsert_team(self, conn: sqlite3.Connection, team: Team):
        conn.execute(
            """
            INSERT INTO teams(
                name, ip, token, expected_tcp_ports, expected_udp_ports,
                score, flags_captured, services_down, consecutive_failures,
                last_scan, scanning_paused
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                ip=excluded.ip,
                token=excluded.token,
                expected_tcp_ports=excluded.expected_tcp_ports,
                expected_udp_ports=excluded.expected_udp_ports,
                score=excluded.score,
                flags_captured=excluded.flags_captured,
                services_down=excluded.services_down,
                consecutive_failures=excluded.consecutive_failures,
                last_scan=excluded.last_scan,
                scanning_paused=excluded.scanning_paused
            """,
            self._serialize_team(team),
        )

    def _save_meta(self, conn: sqlite3.Connection):
        conn.execute(
            "INSERT INTO game_meta(key, value) VALUES('status', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (self._status.value,),
        )
        conn.execute(
            "INSERT INTO game_meta(key, value) VALUES('start_time', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("" if self._game_start_time is None else str(self._game_start_time),),
        )

    def _load_from_db(self):
        with self._connect() as conn:
            team_rows = conn.execute("SELECT * FROM teams").fetchall()
            self._teams = {}
            for row in team_rows:
                self._teams[row["name"]] = Team(
                    name=row["name"],
                    ip=row["ip"],
                    token=row["token"],
                    expected_tcp_ports=json.loads(row["expected_tcp_ports"]),
                    expected_udp_ports=json.loads(row["expected_udp_ports"]),
                    score=row["score"],
                    flags_captured=row["flags_captured"],
                    services_down=json.loads(row["services_down"]),
                    consecutive_failures={
                        int(k): int(v)
                        for k, v in json.loads(row["consecutive_failures"]).items()
                    },
                    last_scan=row["last_scan"],
                    scanning_paused=bool(row["scanning_paused"]),
                )

            meta = {
                row["key"]: row["value"]
                for row in conn.execute("SELECT key, value FROM game_meta").fetchall()
            }
            status_value = meta.get("status", GameStatus.WAITING.value)
            self._status = GameStatus(status_value)
            start_time = meta.get("start_time", "")
            self._game_start_time = float(start_time) if start_time else None

            self._scan_history = []
            for row in conn.execute(
                "SELECT timestamp, team, missing_ports, penalty, score FROM scan_history ORDER BY id ASC"
            ):
                self._scan_history.append(
                    {
                        "timestamp": row["timestamp"],
                        "team": row["team"],
                        "missing_ports": json.loads(row["missing_ports"]),
                        "penalty": row["penalty"],
                        "score": row["score"],
                    }
                )

            self._flag_history = []
            for row in conn.execute(
                "SELECT timestamp, attacker, victim, flag, points, valid FROM flag_history ORDER BY id ASC"
            ):
                self._flag_history.append(
                    {
                        "timestamp": row["timestamp"],
                        "attacker": row["attacker"],
                        "victim": row["victim"],
                        "flag": row["flag"],
                        "points": row["points"],
                        "valid": bool(row["valid"]),
                    }
                )

    def get_team(self, name: str) -> Optional[Team]:
        with self._lock:
            return self._teams.get(name)

    def get_all_teams(self) -> Dict[str, Team]:
        with self._lock:
            return dict(self._teams)

    def update_team_score(self, team_name: str, delta: int):
        with self._lock:
            if team_name in self._teams:
                team = self._teams[team_name]
                team.score = max(0, team.score + delta)
                with self._connect() as conn:
                    self._upsert_team(conn, team)

    def record_scan_result(
        self, team_name: str, missing_ports: List[int], penalty: int
    ):
        with self._lock:
            if team_name not in self._teams:
                return

            team = self._teams[team_name]
            now = time.time()
            team.services_down = missing_ports
            team.last_scan = now
            team.score = max(0, team.score - penalty)

            event = {
                "timestamp": now,
                "team": team_name,
                "missing_ports": missing_ports,
                "penalty": penalty,
                "score": team.score,
            }
            self._scan_history.append(event)

            with self._connect() as conn:
                self._upsert_team(conn, team)
                conn.execute(
                    "INSERT INTO scan_history(timestamp, team, missing_ports, penalty, score) VALUES(?, ?, ?, ?, ?)",
                    (now, team_name, json.dumps(missing_ports), penalty, team.score),
                )

    def record_flag_submission(
        self, attacker: Team, victim: Team, flag: str, points: int, valid: bool
    ):
        with self._lock:
            now = time.time()
            event = {
                "timestamp": now,
                "attacker": attacker.name,
                "victim": victim.name,
                "flag": flag,
                "points": points,
                "valid": valid,
            }
            self._flag_history.append(event)

            if valid:
                attacker.score += points
                attacker.flags_captured += 1
                victim.score = max(0, victim.score - self.flag_stolen_penalty)

            with self._connect() as conn:
                if valid:
                    self._upsert_team(conn, attacker)
                    self._upsert_team(conn, victim)
                conn.execute(
                    "INSERT INTO flag_history(timestamp, attacker, victim, flag, points, valid) VALUES(?, ?, ?, ?, ?, ?)",
                    (now, attacker.name, victim.name, flag, points, 1 if valid else 0),
                )

    def get_status(self) -> GameStatus:
        with self._lock:
            return self._status

    def set_status(self, status: GameStatus):
        with self._lock:
            self._status = status
            if status == GameStatus.RUNNING and self._game_start_time is None:
                self._game_start_time = time.time()
            with self._connect() as conn:
                self._save_meta(conn)

    def get_scoreboard(self) -> List[Dict]:
        with self._lock:
            teams = sorted(self._teams.values(), key=lambda t: t.score, reverse=True)
            return [
                {
                    "rank": i + 1,
                    "name": t.name,
                    "ip": t.ip,
                    "token": t.token,
                    "score": t.score,
                    "flags_captured": t.flags_captured,
                    "services_down": len(t.services_down),
                    "last_scan": t.last_scan,
                    "scanning_paused": t.scanning_paused,
                    "expected_tcp_ports": t.expected_tcp_ports,
                }
                for i, t in enumerate(teams)
            ]

    def get_game_info(self) -> Dict:
        with self._lock:
            return {
                "status": self._status.value,
                "start_time": self._game_start_time,
                "team_count": len(self._teams),
                "scan_count": len(self._scan_history),
                "flag_submissions": len(self._flag_history),
            }

    def get_recent_events(self, limit: int = 15) -> List[Dict]:
        with self._lock:
            valid_submissions = [
                event for event in self._flag_history if event["valid"]
            ]
            return valid_submissions[-limit:][::-1]

    def upsert_active_flag(
        self, team_name: str, service_name: str, flag: str, created_at: float
    ):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO active_flags(team_name, service_name, flag, created_at)
                    VALUES(?, ?, ?, ?)
                    ON CONFLICT(team_name, service_name) DO UPDATE SET
                        flag=excluded.flag,
                        created_at=excluded.created_at
                    """,
                    (team_name, service_name, flag, created_at),
                )

    def remove_active_flag(self, flag: str):
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM active_flags WHERE flag = ?", (flag,))

    def remove_team_active_flags(self, team_name: str):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM active_flags WHERE team_name = ?", (team_name,)
                )

    def clear_active_flags(self):
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM active_flags")

    def get_persisted_active_flags(self) -> List[Dict]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT team_name, service_name, flag, created_at FROM active_flags"
                ).fetchall()
                return [
                    {
                        "team_name": row["team_name"],
                        "service_name": row["service_name"],
                        "flag": row["flag"],
                        "created_at": row["created_at"],
                    }
                    for row in rows
                ]

    def load_teams_from_json(self, file_path: str = "teams.json"):
        with self._lock:
            if self._teams:
                return

        try:
            with open(file_path, "r") as f:
                teams_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return

        loaded_teams: Dict[str, Team] = {}
        for team_data in teams_data:
            if "ports" in team_data:
                team_data["expected_tcp_ports"] = team_data.pop("ports")
            if "token" not in team_data:
                team_data["token"] = f"token-{team_data['name']}-{secrets.token_hex(8)}"
            loaded_teams[team_data["name"]] = Team(**team_data)

        with self._lock:
            if self._teams:
                return
            self._teams = loaded_teams
            with self._connect() as conn:
                for team in self._teams.values():
                    self._upsert_team(conn, team)
                self._save_meta(conn)

    def save_teams_to_json(self, file_path: str = "teams.json"):
        with self._lock:
            teams_data = []
            for team in self._teams.values():
                teams_data.append(
                    {
                        "name": team.name,
                        "ip": team.ip,
                        "token": team.token,
                        "expected_tcp_ports": team.expected_tcp_ports,
                        "expected_udp_ports": team.expected_udp_ports,
                        "score": team.score,
                        "flags_captured": team.flags_captured,
                        "services_down": team.services_down,
                        "consecutive_failures": team.consecutive_failures,
                        "last_scan": team.last_scan,
                        "scanning_paused": team.scanning_paused,
                    }
                )
        with open(file_path, "w") as f:
            json.dump(teams_data, f, indent=4)

    def add_team(self, team: Team):
        with self._lock:
            if team.name in self._teams:
                raise ValueError(f"Team '{team.name}' already exists.")
            self._teams[team.name] = team
            with self._connect() as conn:
                self._upsert_team(conn, team)

    def update_team(self, team_name: str, updates: Dict):
        with self._lock:
            if team_name not in self._teams:
                raise ValueError(f"Team '{team_name}' not found.")
            team = self._teams[team_name]
            for key, value in updates.items():
                if hasattr(team, key):
                    setattr(team, key, value)
            with self._connect() as conn:
                self._upsert_team(conn, team)

    def delete_team(self, team_name: str):
        with self._lock:
            if team_name not in self._teams:
                raise ValueError(f"Team '{team_name}' not found.")
            del self._teams[team_name]
            with self._connect() as conn:
                conn.execute("DELETE FROM teams WHERE name = ?", (team_name,))
                conn.execute(
                    "DELETE FROM active_flags WHERE team_name = ?", (team_name,)
                )

    def reset_game_state(self):
        with self._lock:
            for team in self._teams.values():
                team.score = 1000
                team.flags_captured = 0
                team.scanning_paused = False
                team.last_scan = None
                team.services_down = []
                team.consecutive_failures = {}

            self._scan_history = []
            self._flag_history = []
            self._status = GameStatus.WAITING
            self._game_start_time = None

            with self._connect() as conn:
                for team in self._teams.values():
                    self._upsert_team(conn, team)
                conn.execute("DELETE FROM scan_history")
                conn.execute("DELETE FROM flag_history")
                conn.execute("DELETE FROM active_flags")
                self._save_meta(conn)


game_state = GameState()
