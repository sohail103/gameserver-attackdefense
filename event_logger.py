"""
event_logger.py

Handles logging of game events to files for analysis.
Files are overwritten each time the server starts.
"""

import datetime
import os

SERVICE_LOG_FILE = "service_events.log"
FLAG_LOG_FILE = "flag_events.log"


def initialize_logs():
    session_marker = (
        f"\n=== Server session started at {datetime.datetime.now().isoformat()} ===\n"
    )
    try:
        service_exists = os.path.exists(SERVICE_LOG_FILE)
        flag_exists = os.path.exists(FLAG_LOG_FILE)

        with open(SERVICE_LOG_FILE, "a") as f:
            if not service_exists:
                f.write("Service events log initialized\n")
            f.write(session_marker)

        with open(FLAG_LOG_FILE, "a") as f:
            if not flag_exists:
                f.write("Flag submission log initialized\n")
            f.write(session_marker)
    except IOError as e:
        print(f"Error initializing log files: {e}")


def log_service_down(team_name: str, service_name: str, points_lost: int, reason: str):
    """Logs when a team loses points for a service being down."""
    try:
        with open(SERVICE_LOG_FILE, "a") as f:
            timestamp = datetime.datetime.now().isoformat()
            f.write(
                f"[{timestamp}] SERVICE_DOWN | Team: {team_name} | Service: {service_name} | "
                f"Points Lost: {points_lost} | Reason: {reason}\n"
            )
    except IOError as e:
        print(f"Error writing to service log: {e}")


def log_flag_submission(
    attacker_ip: str, attacker_team: str, flag: str, message: str, is_valid: bool
):
    """Logs a flag submission attempt."""
    try:
        with open(FLAG_LOG_FILE, "a") as f:
            timestamp = datetime.datetime.now().isoformat()
            status = "VALID" if is_valid else "INVALID"
            team_info = f"Team: {attacker_team}" if attacker_team else "Team: Unknown"
            f.write(
                f"[{timestamp}] {status} | Attacker IP: {attacker_ip} | {team_info} | "
                f"Flag: '{flag}' | Message: {message}\n"
            )
    except IOError as e:
        print(f"Error writing to flag log: {e}")
