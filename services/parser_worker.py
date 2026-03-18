"""
Folder-based ingestion worker.

Watches EMAIL_DROP_DIR for incoming .eml/.msg/.txt and publishes NewEmailEvent.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

from configs.settings import settings
from services.email_parser import EmailParserService
from services.logging_service import setup_logging, get_service_logger

logger = get_service_logger("parser_worker")


def _supported(path: Path, parser: EmailParserService) -> bool:
    return parser.supports_extension(path.suffix.lower())


def run() -> None:
    setup_logging(settings.log_dir, settings.app_log_level, settings.log_format)
    parser = EmailParserService()

    drop_dir = Path(settings.email_drop_dir)
    processed_dir = drop_dir / "processed"
    failed_dir = drop_dir / "failed"
    drop_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)
    failed_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Parser worker started", drop_dir=str(drop_dir))
    while True:
        candidates = [
            path for path in drop_dir.iterdir() if path.is_file() and _supported(path, parser)
        ]
        for file_path in candidates:
            try:
                event = parser.parse_and_publish(file_path)
                logger.info(
                    "Parsed and published",
                    source_file=str(file_path),
                    analysis_id=event["analysis_id"],
                )
                shutil.move(str(file_path), str(processed_dir / file_path.name))
            except Exception as exc:
                logger.exception("Failed to parse email", file=str(file_path), error=str(exc))
                shutil.move(str(file_path), str(failed_dir / file_path.name))

        time.sleep(max(1, settings.parser_poll_seconds))


if __name__ == "__main__":
    run()
