"""Entry point for the standalone FIDO MDS updater process."""
from __future__ import annotations

import logging
import signal
from typing import Optional

from .mds_updater import DailyMdsUpdater


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def main() -> None:
    _configure_logging()
    updater = DailyMdsUpdater()

    def _signal_handler(signum: int, _frame: Optional[object]) -> None:
        logging.getLogger("updater.mds").info("Received signal %s. Stopping updater…", signum)
        updater.request_stop()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        updater.run_forever()
    except KeyboardInterrupt:
        updater.request_stop()


if __name__ == "__main__":  # pragma: no cover - convenience entry point.
    main()
