"""
Email parsing service for extracting headers, body, URLs, and attachments.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

from configs.settings import settings
from services.logging_service import get_service_logger
from services.messaging_service import RabbitMQClient

logger = get_service_logger("email_parser")

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


class EmailParserService:
    """Parse raw email files and publish NewEmailEvent messages."""

    def __init__(self):
        self.attachments_dir = Path(settings.attachment_volume_dir)
        self.attachments_dir.mkdir(parents=True, exist_ok=True)
        self.messaging = RabbitMQClient()

    def parse_file(self, file_path: str | Path) -> dict[str, Any]:
        with open(file_path, "rb") as source:
            raw_bytes = source.read()

        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        analysis_id = str(uuid.uuid4())

        headers = self._extract_headers(message)
        body_plain, body_html = self._extract_body_parts(message)
        urls = self._extract_urls(body_plain, body_html)
        attachments = self._extract_attachments(message, analysis_id)

        payload = {
            "event_type": "NewEmailEvent",
            "analysis_id": analysis_id,
            "source_file": str(file_path),
            "headers": headers,
            "body": {
                "plain": body_plain,
                "html": body_html,
            },
            "urls": urls,
            "attachments": attachments,
            "iocs": {
                "domains": self._extract_domains(urls),
                "ips": self._extract_ips(body_plain + "\n" + body_html),
                "hashes": [item["sha256"] for item in attachments],
            },
        }
        return payload

    def parse_and_publish(self, file_path: str | Path) -> dict[str, Any]:
        payload = self.parse_file(file_path)
        self.messaging.connect()
        self.messaging.publish_new_email(payload)
        self.messaging.close()
        logger.info("Published NewEmailEvent", analysis_id=payload["analysis_id"])
        return payload

    def _extract_headers(self, message) -> dict[str, Any]:
        sender_raw = message.get("From", "")
        recipients_raw = message.get_all("To", []) + message.get_all("Cc", [])
        sender_addr = getaddresses([sender_raw])
        recipient_addrs = getaddresses(recipients_raw)

        return {
            "from": sender_raw,
            "sender": sender_addr[0][1] if sender_addr else "",
            "reply_to": message.get("Reply-To"),
            "to": [entry[1] for entry in recipient_addrs if entry[1]],
            "subject": message.get("Subject", ""),
            "message_id": message.get("Message-ID"),
            "received": message.get_all("Received", []),
            "authentication_results": message.get("Authentication-Results", ""),
            "raw": {key: value for key, value in message.items()},
        }

    def _extract_body_parts(self, message) -> tuple[str, str]:
        plain_chunks: list[str] = []
        html_chunks: list[str] = []

        if message.is_multipart():
            for part in message.walk():
                content_disposition = (part.get_content_disposition() or "").lower()
                if content_disposition == "attachment":
                    continue
                content_type = part.get_content_type().lower()
                payload = self._safe_decode_part(part)
                if not payload:
                    continue
                if content_type == "text/plain":
                    plain_chunks.append(payload)
                elif content_type == "text/html":
                    html_chunks.append(payload)
        else:
            payload = self._safe_decode_part(message)
            content_type = message.get_content_type().lower()
            if content_type == "text/html":
                html_chunks.append(payload)
            else:
                plain_chunks.append(payload)

        return "\n".join(plain_chunks).strip(), "\n".join(html_chunks).strip()

    def _safe_decode_part(self, part) -> str:
        content = part.get_payload(decode=True)
        if content is None:
            try:
                return str(part.get_payload())
            except Exception:
                return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return content.decode(charset, errors="replace")
        except Exception:
            return content.decode("utf-8", errors="replace")

    def _extract_urls(self, plain: str, html: str) -> list[str]:
        extracted = set(URL_REGEX.findall(plain or ""))
        extracted.update(URL_REGEX.findall(html or ""))

        if html:
            soup = BeautifulSoup(html, "html.parser")
            for anchor in soup.find_all(["a", "button"]):
                href = anchor.get("href") or anchor.get("data-href") or anchor.get("onclick")
                if href:
                    extracted.update(URL_REGEX.findall(href))

        return sorted(extracted)

    def _extract_attachments(self, message, analysis_id: str) -> list[dict[str, Any]]:
        saved: list[dict[str, Any]] = []
        for part in message.walk():
            if part.get_content_disposition() != "attachment":
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue

            attachment_uuid = str(uuid.uuid4())
            filename = part.get_filename() or f"attachment-{attachment_uuid}.bin"
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
            target_name = f"{analysis_id}_{attachment_uuid}_{safe_name}"
            target_path = self.attachments_dir / target_name
            with open(target_path, "wb") as output:
                output.write(payload)

            sha256 = hashlib.sha256(payload).hexdigest()
            saved.append(
                {
                    "attachment_id": attachment_uuid,
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "sha256": sha256,
                    "path": str(target_path),
                }
            )
        return saved

    def _extract_domains(self, urls: list[str]) -> list[str]:
        domains = set()
        for url in urls:
            match = re.match(r"https?://([^/:?#]+)", url, flags=re.IGNORECASE)
            if match:
                domains.add(match.group(1).lower())
        return sorted(domains)

    def _extract_ips(self, content: str) -> list[str]:
        return sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)))
