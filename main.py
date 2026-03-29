#!/usr/bin/env python3
"""
main.py

Main entry point for CTF Attack/Defense game server.
Orchestrates all components.
"""

import logging
import argparse

from game_state import game_state
from web_server import run_both_servers
from event_logger import initialize_logs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


logger = logging.getLogger("main")


def setup_teams():
    """Initialize teams from teams.json"""
    game_state.load_teams_from_json()


def main():
    parser = argparse.ArgumentParser(description="CTF Attack/Defense Game Server")
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind web server (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port for public web server (default: 5000)",
    )
    parser.add_argument(
        "--admin-port",
        type=int,
        default=5001,
        help="Port for admin interface (default: 5001)",
    )
    parser.add_argument(
        "--scan-interval",
        type=int,
        default=10,
        help="Service scan interval in seconds (default: 10)",
    )
    parser.add_argument(
        "--penalty",
        type=int,
        default=10,
        help="Penalty points per missing service (default: 10)",
    )
    parser.add_argument(
        "--flag-points",
        type=int,
        default=50,
        help="Points awarded for valid flag (default: 50)",
    )
    parser.add_argument(
        "--flag-stolen-penalty",
        type=int,
        default=25,
        help="Penalty points for team that gets a flag stolen (default: 25)",
    )
    parser.add_argument(
        "--enable-udp",
        action="store_true",
        help="Deprecated: UDP scanning is disabled in TCP probe mode",
    )
    parser.add_argument(
        "--ssl-cert",
        type=str,
        help="Path to SSL certificate file for HTTPS (e.g., cert.pem)",
    )
    parser.add_argument(
        "--ssl-key",
        type=str,
        help="Path to SSL private key file for HTTPS (e.g., key.pem)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    # Configure game state
    game_state.scan_interval = args.scan_interval
    game_state.penalty_per_port = args.penalty
    game_state.flag_points = args.flag_points
    game_state.flag_stolen_penalty = args.flag_stolen_penalty
    game_state.enable_udp = False

    if args.enable_udp:
        logger.warning("--enable-udp is ignored: scanner now uses TCP probes only")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("CTF Attack/Defense Game Server")
    logger.info("=" * 60)
    logger.info("Configuration:")
    logger.info(
        "  Public Server: http://%s:%d (accessible to teams)", args.host, args.port
    )
    logger.info("  Admin Server: http://127.0.0.1:%d (localhost only)", args.admin_port)
    logger.info("  Scan Interval: %d seconds", args.scan_interval)
    logger.info("  Penalty per port: %d points", args.penalty)
    logger.info("  Flag capture points: %d points", args.flag_points)
    logger.info("  Flag stolen penalty: %d points", args.flag_stolen_penalty)
    logger.info("  UDP scanning: %s", "enabled" if args.enable_udp else "disabled")
    logger.info("=" * 60)

    # Initialize log files
    initialize_logs()

    # Setup teams
    setup_teams()
    logger.info("Loaded %d teams", len(game_state.get_all_teams()))

    # Print instructions
    print("\n" + "=" * 60)
    print("🎮 CTF Game Server Ready!")
    print("=" * 60)
    print(f"📊 PUBLIC Scoreboard (teams): http://{args.host}:{args.port}")
    print(f"🔒 ADMIN Panel (organizers): http://127.0.0.1:{args.admin_port}")
    print(f"")
    print(f"Teams can:")
    print(f"  - View scoreboard")
    print(f"  - Submit flags via web form or API")
    print(f"")
    print(f"Admins can:")
    print(f"  - Start/pause/stop the game")
    print(f"  - View full details including IPs")
    print(f"")
    print(f"🏁 Flag submission API:")
    print(f"   curl -X POST http://{args.host}:{args.port}/api/submit_flag \\")
    print('        -H "Content-Type: application/json" \\')
    print('        -d \'{"token": "token-team-alpha-...", "flag": "FLAG{...}"}\'')
    print("=" * 60)
    print("\nPress Ctrl+C to stop the server\n")

    # Run web servers (blocks)
    try:
        run_both_servers(
            public_host=args.host,
            public_port=args.port,
            admin_host="127.0.0.1",
            admin_port=args.admin_port,
            ssl_cert=args.ssl_cert,
            ssl_key=args.ssl_key,
        )
    except KeyboardInterrupt:
        logger.info("\nShutdown requested by user")
    finally:
        # Cleanup
        from scanner import scanner

        if scanner.is_running():
            scanner.stop()
        logger.info("Server stopped")


if __name__ == "__main__":
    main()
