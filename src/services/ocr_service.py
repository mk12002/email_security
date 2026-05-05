"""OCR extraction service for image and PDF attachments.

Uses the free OCR.space API to extract text from image/PDF email attachments,
then scans the extracted text for hidden URLs and QR code payloads that bypass
traditional content scanners.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

import requests

from email_security.src.configs.settings import settings
from email_security.src.services.logging_service import get_service_logger

logger = get_service_logger("ocr_service")

# Extensions eligible for OCR processing
OCR_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".gif", ".webp"}
OCR_DOCUMENT_EXTENSIONS = {".pdf"}
OCR_ELIGIBLE_EXTENSIONS = OCR_IMAGE_EXTENSIONS | OCR_DOCUMENT_EXTENSIONS

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)


def is_ocr_eligible(filename: str) -> bool:
    """Check if a file extension is eligible for OCR processing."""
    return Path(filename).suffix.lower() in OCR_ELIGIBLE_EXTENSIONS


def extract_text_from_file(file_path: Path) -> dict[str, Any]:
    """Extract text from an image or PDF file using OCR.space API.

    Returns a dict with keys:
        - success: bool
        - extracted_text: str (raw text from OCR)
        - discovered_urls: list[str] (URLs found in extracted text)
        - error: str | None
    """
    result: dict[str, Any] = {
        "success": False,
        "extracted_text": "",
        "discovered_urls": [],
        "error": None,
    }

    if not settings.enable_ocr_extraction:
        result["error"] = "OCR extraction is disabled"
        return result

    api_key = settings.ocr_space_api_key
    if not api_key:
        result["error"] = "OCR_SPACE_API_KEY not configured"
        return result

    if not file_path.exists() or not file_path.is_file():
        result["error"] = f"File not found: {file_path}"
        return result

    # Check file size limit
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    if file_size_mb > settings.ocr_max_file_size_mb:
        result["error"] = f"File too large ({file_size_mb:.1f}MB > {settings.ocr_max_file_size_mb}MB limit)"
        return result

    try:
        suffix = file_path.suffix.lower()
        is_pdf = suffix in OCR_DOCUMENT_EXTENSIONS

        # Read file and encode as base64
        raw_bytes = file_path.read_bytes()
        b64_data = base64.b64encode(raw_bytes).decode("ascii")

        if is_pdf:
            file_type = "PDF"
            data_uri = f"data:application/pdf;base64,{b64_data}"
        else:
            mime_map = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".bmp": "image/bmp",
                ".tiff": "image/tiff",
                ".tif": "image/tiff",
                ".gif": "image/gif",
                ".webp": "image/webp",
            }
            mime = mime_map.get(suffix, "image/png")
            file_type = "Image"
            data_uri = f"data:{mime};base64,{b64_data}"

        payload = {
            "apikey": api_key,
            "base64Image": data_uri,
            "language": "eng",
            "isOverlayRequired": False,
            "detectOrientation": True,
            "scale": True,
            "OCREngine": 2,  # Engine 2 is better for dense text
        }
        if is_pdf:
            payload["isTable"] = True

        logger.info(
            "Sending file to OCR.space",
            file=str(file_path),
            file_type=file_type,
            size_mb=f"{file_size_mb:.2f}",
        )

        response = requests.post(
            settings.ocr_space_api_url,
            data=payload,
            timeout=settings.ocr_timeout_seconds,
        )
        response.raise_for_status()

        api_result = response.json()

        if api_result.get("IsErroredOnProcessing", False):
            error_msg = api_result.get("ErrorMessage", ["Unknown OCR error"])
            result["error"] = str(error_msg)
            logger.warning("OCR API returned error", error=str(error_msg))
            return result

        parsed_results = api_result.get("ParsedResults", [])
        if not parsed_results:
            result["error"] = "No text extracted"
            return result

        # Combine text from all parsed pages
        extracted_text = "\n".join(
            pr.get("ParsedText", "") for pr in parsed_results
        ).strip()

        result["success"] = True
        result["extracted_text"] = extracted_text

        # Scan for hidden URLs in extracted text
        urls = URL_PATTERN.findall(extracted_text)
        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_urls: list[str] = []
        for url in urls:
            # Strip trailing punctuation that regex might capture
            url = url.rstrip(".,;:!?)")
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)

        result["discovered_urls"] = unique_urls

        logger.info(
            "OCR extraction completed",
            file=str(file_path),
            text_length=len(extracted_text),
            urls_found=len(unique_urls),
        )

    except requests.Timeout:
        result["error"] = "OCR API request timed out"
        logger.warning("OCR API timeout", file=str(file_path))
    except requests.RequestException as exc:
        result["error"] = f"OCR API request failed: {exc}"
        logger.warning("OCR API request error", file=str(file_path), error=str(exc))
    except Exception as exc:
        result["error"] = f"OCR processing failed: {exc}"
        logger.exception("Unexpected OCR error", file=str(file_path))

    return result


def extract_urls_from_attachments(attachments: list[dict[str, Any]]) -> list[str]:
    """Scan eligible attachments for hidden URLs via OCR.

    Args:
        attachments: List of attachment dicts with 'path' and 'filename' keys.

    Returns:
        List of discovered URLs from OCR text extraction.
    """
    if not settings.enable_ocr_extraction:
        return []

    all_urls: list[str] = []

    for attachment in attachments:
        filename = attachment.get("filename", "")
        path_str = attachment.get("path", "")

        if not is_ocr_eligible(filename):
            continue

        file_path = Path(path_str)
        if not file_path.exists():
            logger.debug("Skipping OCR for missing file", filename=filename, path=path_str)
            continue

        result = extract_text_from_file(file_path)

        if result["success"] and result["discovered_urls"]:
            logger.info(
                "OCR discovered hidden URLs in attachment",
                filename=filename,
                url_count=len(result["discovered_urls"]),
            )
            all_urls.extend(result["discovered_urls"])

        if result.get("error"):
            logger.debug(
                "OCR extraction issue",
                filename=filename,
                error=result["error"],
            )

    return all_urls
