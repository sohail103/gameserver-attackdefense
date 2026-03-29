"""
flag_validator.py

Flag generation and validation logic for CTF submissions.
Each service on each team has one active flag at a time.
"""

import logging
import secrets
import threading
import time
from typing import Dict, Set, Tuple

from event_logger import log_flag_submission
from game_state import game_state

logger = logging.getLogger("flag_validator")


class FlagValidator:
    """Manages flag generation and validation"""

    def __init__(self):
        self._lock = threading.Lock()
        self._active_flags: Dict[tuple, tuple] = {}
        self._flag_lookup: Dict[str, tuple] = {}
        self._submissions: Dict[str, Set[str]] = {}
        self._load_active_flags_from_db()

    def _load_active_flags_from_db(self):
        persisted_flags = game_state.get_persisted_active_flags()
        with self._lock:
            self._active_flags.clear()
            self._flag_lookup.clear()

            for row in persisted_flags:
                team_name = row["team_name"]
                service_name = row["service_name"]
                flag = row["flag"]
                created_at = int(row["created_at"])

                if not game_state.get_team(team_name):
                    game_state.remove_active_flag(flag)
                    continue

                key = (team_name, service_name)
                self._active_flags[key] = (flag, created_at)
                self._flag_lookup[flag] = key

        if persisted_flags:
            logger.info("Loaded %d active flags from database", len(self._active_flags))

    def generate_flag(self, team_name: str, service_name: str) -> Tuple[bool, str, str]:
        """Generate a unique flag for a team's service."""
        if not game_state.get_team(team_name):
            logger.warning("Flag generation requested for unknown team: %s", team_name)
            return False, "", "Unknown team"

        random_data = secrets.token_hex(16)
        timestamp = int(time.time())
        flag = f"FLAG{{{team_name}_{service_name}_{random_data}}}"
        key = (team_name, service_name)

        with self._lock:
            if key in self._active_flags:
                old_flag = self._active_flags[key][0]
                if old_flag in self._flag_lookup:
                    del self._flag_lookup[old_flag]
                logger.info("Replaced flag for %s/%s", team_name, service_name)

            self._active_flags[key] = (flag, timestamp)
            self._flag_lookup[flag] = (team_name, service_name)

        game_state.upsert_active_flag(team_name, service_name, flag, timestamp)

        logger.info(
            "Generated flag for team=%s service=%s: %s", team_name, service_name, flag
        )
        return True, flag, "Flag generated successfully"

    def validate_submission(
        self, attacker_token: str, flag: str
    ) -> Tuple[bool, str, int]:
        """
        Validate a flag submission.

        Args:
            attacker_token: Secret token of the team submitting the flag.
            flag: The flag string they captured.

        Returns:
            (is_valid, message, points_awarded)
        """
        # Map token to team
        attacker_team = None
        for team in game_state.get_all_teams().values():
            if team.token == attacker_token:
                attacker_team = team
                break

        if not attacker_team:
            message = "Invalid team token"
            logger.warning(
                "Invalid token '%s' used to submit flag '%s'", attacker_token, flag
            )
            log_flag_submission(attacker_token, None, flag, message, is_valid=False)
            return False, message, 0

        with self._lock:
            lookup_value = self._flag_lookup.get(flag)

        if not lookup_value:
            message = "Invalid or expired flag"
            logger.info(
                "Invalid flag submitted by %s (%s): %s",
                attacker_team.name,
                attacker_team.ip,
                flag,
            )
            log_flag_submission(
                attacker_team.ip, attacker_team.name, flag, message, is_valid=False
            )
            return False, message, 0

        victim_team_name, service_name = lookup_value
        victim_team = game_state.get_team(victim_team_name)
        if victim_team is None:
            game_state.remove_active_flag(flag)
            with self._lock:
                self._flag_lookup.pop(flag, None)
                self._active_flags.pop((victim_team_name, service_name), None)
            message = "Invalid or expired flag"
            log_flag_submission(
                attacker_team.ip, attacker_team.name, flag, message, is_valid=False
            )
            return False, message, 0

        # Prevent self-submission
        if attacker_team == victim_team:
            message = "Cannot submit your own flag"
            logger.info(
                "Team %s (%s) tried to submit their own flag",
                attacker_team.name,
                attacker_team.ip,
            )
            log_flag_submission(
                attacker_team.ip, attacker_team.name, flag, message, is_valid=False
            )
            return False, message, 0

        # Prevent duplicate submissions by the same team
        with self._lock:
            if attacker_team.name not in self._submissions:
                self._submissions[attacker_team.name] = set()

            if flag in self._submissions[attacker_team.name]:
                message = "You have already submitted this flag"
                logger.info(
                    "Duplicate flag submission blocked: team %s tried %s again",
                    attacker_team.name,
                    flag,
                )
                log_flag_submission(
                    attacker_team.ip, attacker_team.name, flag, message, is_valid=False
                )
                return False, message, 0

            self._submissions[attacker_team.name].add(flag)

        points = game_state.flag_points
        game_state.record_flag_submission(
            attacker=attacker_team,
            victim=victim_team,
            flag=flag,
            points=points,
            valid=True,
        )

        logger.info(
            "Valid flag submitted: %s (%s) captured %s's %s service (+%d points)",
            attacker_team.name,
            attacker_team.ip,
            victim_team.name,
            service_name,
            points,
        )

        message = f"Valid flag! Captured {victim_team.name}'s {service_name} service"
        log_flag_submission(
            attacker_team.ip, attacker_team.name, flag, message, is_valid=True
        )
        return True, message, points

    def get_active_flag_count(self) -> int:
        with self._lock:
            return len(self._active_flags)

    def get_team_flags(self, team_name: str) -> Dict[str, str]:
        with self._lock:
            result = {}
            for (t_name, service), (flag, _) in self._active_flags.items():
                if t_name == team_name:
                    result[service] = flag
            return result

    def clear_active_flags(self):
        with self._lock:
            self._active_flags.clear()
            self._flag_lookup.clear()
        game_state.clear_active_flags()

    def remove_team_flags(self, team_name: str):
        removed_flags = []
        with self._lock:
            for key, (flag, _) in list(self._active_flags.items()):
                if key[0] == team_name:
                    removed_flags.append(flag)
                    del self._active_flags[key]
                    self._flag_lookup.pop(flag, None)

        if removed_flags:
            game_state.remove_team_active_flags(team_name)

    def cleanup_old_flags(self, max_age_seconds: int = 3600):
        current_time = time.time()
        to_remove = []

        with self._lock:
            for key, (flag, timestamp) in self._active_flags.items():
                if current_time - timestamp > max_age_seconds:
                    to_remove.append((key, flag))

            for key, flag in to_remove:
                del self._active_flags[key]
                if flag in self._flag_lookup:
                    del self._flag_lookup[flag]

        for _, flag in to_remove:
            game_state.remove_active_flag(flag)

        if to_remove:
            logger.info("Cleaned up %d old flags", len(to_remove))


# Global flag validator instance
flag_validator = FlagValidator()
