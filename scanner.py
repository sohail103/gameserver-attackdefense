"""
scanner.py

Service availability scanner using direct TCP connect checks.
Runs in background thread when game is active.
"""

import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from apscheduler.schedulers.background import BackgroundScheduler
from typing import Dict, List

from game_state import game_state, GameStatus
from event_logger import log_service_down

logger = logging.getLogger("scanner")

TCP_CONNECT_TIMEOUT = 1.5


class ServiceScanner:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self._running = False
        self._lock = threading.Lock()

    def start(self):
        with self._lock:
            if self._running:
                logger.warning("Scanner already running")
                return

            self.scheduler = BackgroundScheduler()
            self.scheduler.add_job(
                self._scan_all_teams, "interval", seconds=game_state.scan_interval
            )
            self.scheduler.start()
            self._running = True
            logger.info("Scanner started (interval=%ds)", game_state.scan_interval)

    def stop(self):
        with self._lock:
            if not self._running:
                return

            self.scheduler.shutdown(wait=False)
            self._running = False
            logger.info("Scanner stopped")

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def _scan_all_teams(self):
        if game_state.get_status() != GameStatus.RUNNING:
            logger.debug("Game not running, skipping scan")
            return

        logger.debug("Starting scheduled scan of all teams")
        teams = game_state.get_all_teams()

        with ThreadPoolExecutor(max_workers=min(16, max(2, len(teams)))) as ex:
            futures = {
                ex.submit(self._check_team, name, team): name
                for name, team in teams.items()
            }
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    logger.exception("Exception scanning team %s: %s", futures[fut], e)

    def _check_team(self, team_name: str, team):
        if team.scanning_paused:
            logger.info("Scanning is paused for team %s, skipping", team_name)
            return

        tcp_results = self._check_tcp_ports(team.ip, team.expected_tcp_ports)
        udp_results = {}

        missing_tcp = [p for p, state in tcp_results.items() if state != "open"]
        missing_udp = [p for p, state in udp_results.items() if state != "open"]

        penalty = 0
        all_expected_ports = team.expected_tcp_ports + team.expected_udp_ports

        for port in all_expected_ports:
            if port in missing_tcp or port in missing_udp:
                team.consecutive_failures[port] = (
                    team.consecutive_failures.get(port, 0) + 1
                )
                if team.consecutive_failures[port] > 1:
                    penalty += game_state.penalty_per_port
                    log_service_down(
                        team_name,
                        f"TCP/{port}"
                        if port in team.expected_tcp_ports
                        else f"UDP/{port}",
                        game_state.penalty_per_port,
                        f"Port consecutively down (failures: {team.consecutive_failures[port]})",
                    )
            else:
                if team.consecutive_failures.get(port, 0) > 0:
                    logger.info(f"Service {port} for team {team_name} is back up.")
                team.consecutive_failures[port] = 0

        all_missing = missing_tcp + missing_udp

        game_state.record_scan_result(team_name, all_missing, penalty)

        logger.info(
            "Scanned %s (%s): missing_tcp=%s missing_udp=%s penalty=%d",
            team_name,
            team.ip,
            missing_tcp,
            missing_udp,
            penalty,
        )

    def _check_tcp_ports(self, ip: str, ports: List[int]) -> Dict[int, str]:
        if not ports:
            return {}

        results: Dict[int, str] = {}
        with ThreadPoolExecutor(max_workers=min(64, max(1, len(ports)))) as ex:
            futures = {
                ex.submit(self._probe_tcp_port, ip, port): port for port in ports
            }
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    results[port] = "open" if is_open else "closed"
                except Exception:
                    results[port] = "unknown"

        return results

    def _probe_tcp_port(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=TCP_CONNECT_TIMEOUT):
                return True
        except OSError:
            return False


# Global scanner instance
scanner = ServiceScanner()
