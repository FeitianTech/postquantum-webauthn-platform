"""Startup-driven logging and email delivery for WebAuthn device registrations."""
from __future__ import annotations

import base64
import errno
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - fallback for very old Python
    from backports.zoneinfo import ZoneInfo  # type: ignore

__all__ = ["record_registration_event"]


BEIJING_TZ = ZoneInfo("Asia/Shanghai")
TIMEZONE_LABEL = "CST"
LOG_FILENAME = "webauthn_device_logs.log"
STATUS_FILENAME = "webauthn_device_logs.status"
LOG_STORAGE_DIRNAME = "webauthn-device-logs"
STARTUP_LOCK_FILENAME = "webauthn_device_logs.startup.lock"
MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# Configure logging
logger = logging.getLogger(__name__)

try:  # Unix platforms
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - not available on Windows
    fcntl = None  # type: ignore[assignment]

try:  # Windows
    import msvcrt  # type: ignore
except ImportError:  # pragma: no cover - not available on Unix
    msvcrt = None  # type: ignore[assignment]


class _InterProcessFileLock:
    """Lightweight cross-process file lock with platform-specific fallbacks."""

    def __init__(self, path: Path, stale_timeout: float = 300.0) -> None:
        self._path = path
        self._handle: Optional[object] = None
        self._mode: Optional[str] = None
        self._stale_timeout = stale_timeout

    def acquire(self, timeout: float = 10.0, poll_interval: float = 0.1) -> bool:
        deadline = time.monotonic() + timeout if timeout is not None else None

        if fcntl is None and msvcrt is None:
            return self._acquire_via_link(deadline, poll_interval)

        while True:
            try:
                file_handle = self._path.open("a+")
            except OSError as e:
                logger.warning(f"Failed to open lock file: {e}")
                return False

            try:
                if fcntl is not None:
                    fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._handle = file_handle
                    self._mode = "fcntl"
                    return True

                if msvcrt is not None:
                    file_handle.seek(0, os.SEEK_END)
                    if file_handle.tell() == 0:
                        file_handle.write("0")
                        file_handle.flush()
                        try:
                            os.fsync(file_handle.fileno())
                        except OSError:
                            pass
                    file_handle.seek(0)
                    try:
                        msvcrt.locking(file_handle.fileno(), msvcrt.LK_NBLCK, 1)
                        self._handle = file_handle
                        self._mode = "msvcrt"
                        return True
                    except OSError as exc:
                        if exc.errno not in (errno.EACCES, errno.EDEADLK):
                            file_handle.close()
                            raise
            except BlockingIOError:
                pass
            except OSError as e:
                logger.warning(f"Lock acquisition failed: {e}")
                file_handle.close()
                raise

            file_handle.close()

            if not self._sleep_until(deadline, poll_interval):
                return False

        return False

    def release(self) -> None:
        mode = self._mode
        handle = self._handle
        self._mode = None
        self._handle = None

        if mode is None:
            return

        try:
            if mode == "fcntl" and handle is not None and fcntl is not None:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            elif mode == "msvcrt" and handle is not None and msvcrt is not None:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            elif mode == "link":
                try:
                    self._path.unlink()
                except OSError:
                    pass
        finally:
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass

    def _acquire_via_link(self, deadline: Optional[float], poll_interval: float) -> bool:
        while True:
            try:
                fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                if self._stale_timeout is not None:
                    try:
                        if time.time() - self._path.stat().st_mtime > self._stale_timeout:
                            logger.info(f"Removing stale lock file: {self._path}")
                            self._path.unlink()
                            continue
                    except OSError:
                        pass

                if not self._sleep_until(deadline, poll_interval):
                    return False
                continue
            except OSError as e:
                logger.warning(f"Failed to create lock file: {e}")
                return False

            os.close(fd)
            self._mode = "link"
            return True

    @staticmethod
    def _sleep_until(deadline: Optional[float], poll_interval: float) -> bool:
        if deadline is None:
            time.sleep(poll_interval)
            return True

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False

        time.sleep(min(poll_interval, remaining))
        return True

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError("Failed to acquire lock")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalised = value.strip().lower()
    if normalised in {"", "0", "false", "off", "no"}:
        return False
    return True


def _normalise_aaguid(raw_value: Optional[object]) -> str:
    if raw_value is None:
        return "unknown-aaguid"
    if isinstance(raw_value, uuid.UUID):
        return str(raw_value)
    if isinstance(raw_value, (bytes, bytearray, memoryview)):
        data = bytes(raw_value)
        if len(data) == 0:
            return "unknown-aaguid"
        if len(data) == 16:
            try:
                return str(uuid.UUID(bytes=data))
            except ValueError:
                pass
        hex_str = data.hex()
        return hex_str if hex_str else "unknown-aaguid"
    if isinstance(raw_value, str):
        candidate = raw_value.strip()
        if not candidate:
            return "unknown-aaguid"
        try:
            return str(uuid.UUID(candidate))
        except ValueError:
            pass
        try:
            return str(uuid.UUID(hex=candidate.replace("-", "")))
        except ValueError:
            return candidate
    return str(raw_value)


def _clean_authenticator_name(raw_value: Optional[str]) -> str:
    if isinstance(raw_value, str):
        cleaned = raw_value.strip()
        if cleaned:
            return cleaned
    return "Unknown Authenticator"


def _parse_timestamp(raw_value: Optional[object]) -> Optional[datetime]:
    if not raw_value or not isinstance(raw_value, str):
        return None

    candidate = raw_value.strip()
    if not candidate:
        return None

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        try:
            legacy_date = date.fromisoformat(candidate)
        except ValueError:
            return None
        parsed = datetime(
            legacy_date.year,
            legacy_date.month,
            legacy_date.day,
            tzinfo=BEIJING_TZ,
        )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


@dataclass
class EmailConfig:
    email_address: str
    client_id: str
    client_secret: str
    refresh_token: str
    retry_attempts: int
    retry_delay_seconds: float

    def __post_init__(self):
        """Validate that required fields are not empty."""
        if not self.email_address or not self.email_address.strip():
            raise ValueError("Email address cannot be empty")
        if not self.client_id or not self.client_id.strip():
            raise ValueError("Client ID cannot be empty")
        if not self.client_secret or not self.client_secret.strip():
            raise ValueError("Client secret cannot be empty")
        if not self.refresh_token or not self.refresh_token.strip():
            raise ValueError("Refresh token cannot be empty")


@dataclass
class _DeliveryStatus:
    last_sent: Optional[datetime] = None
    startup_completed: bool = False

    def serialise_last_sent(self) -> Optional[str]:
        if self.last_sent is None:
            return None
        return self.last_sent.astimezone(timezone.utc).isoformat()


class RegistrationLogManager:
    """Coordinate log writes and perform startup email delivery."""

    def __init__(self) -> None:
        self._write_lock = threading.Lock()
        self._email_config = self._load_email_config()
        self.delivery_enabled = self._email_config is not None and _env_flag(
            "REGISTRATION_LOG_EMAIL_ENABLED", default=True
        )
        self.enabled = True

        try:
            self.log_dir = self._initialise_log_dir()
        except RuntimeError as e:
            logger.error(f"Failed to initialize log directory: {e}")
            self.enabled = False
            self.delivery_enabled = False
            return

        self._log_path = self.log_dir / LOG_FILENAME
        self._status_path = self.log_dir / STATUS_FILENAME
        self._startup_lock_path = self.log_dir / STARTUP_LOCK_FILENAME

        if not self._ensure_log_dir_exists():
            logger.error("Log directory does not exist and cannot be created")
            self.enabled = False
            self.delivery_enabled = False
            return

        if self.delivery_enabled:
            self._handle_startup()
        else:
            # Ensure log file exists for future writes even when delivery disabled.
            try:
                with self._write_lock:
                    self._ensure_log_file_exists()
            except OSError as e:
                logger.error(f"Failed to create log file: {e}")
                self.enabled = False

    # Public API -----------------------------------------------------

    def record_event(self, aaguid: Optional[object], authenticator_name: Optional[str]) -> None:
        if not self.enabled:
            return

        timestamp = datetime.now(tz=BEIJING_TZ)
        line = (
            f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} ({TIMEZONE_LABEL}) | "
            f"{_normalise_aaguid(aaguid)} | {_clean_authenticator_name(authenticator_name)}"
        )

        try:
            with self._write_lock:
                self._ensure_log_file_exists()
                self._check_log_size()
                with self._log_path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                    handle.flush()
                    try:
                        os.fsync(handle.fileno())
                    except OSError as e:
                        logger.warning(f"fsync failed: {e}")
        except (OSError, IOError) as e:
            # Log specific file-related errors
            logger.error(f"Failed to write log entry: {e}")
        except Exception as e:
            # Catch unexpected errors but log them
            logger.exception(f"Unexpected error writing log entry: {e}")

    # Startup processing --------------------------------------------

    def _handle_startup(self) -> None:
        startup_lock = _InterProcessFileLock(self._startup_lock_path)
        acquired = startup_lock.acquire(timeout=10.0)

        if not acquired:
            logger.info("Another process is handling startup; skipping")
            # Another worker will process startup; still ensure local log file exists.
            with self._write_lock:
                try:
                    self._ensure_log_file_exists()
                except OSError as e:
                    logger.error(f"Failed to create log file: {e}")
                    self.enabled = False
                    self.delivery_enabled = False
            return

        try:
            with self._write_lock:
                try:
                    self._ensure_log_file_exists()
                except OSError as e:
                    logger.error(f"Failed to create log file: {e}")
                    self.enabled = False
                    self.delivery_enabled = False
                    return

                # Reload status after acquiring lock to ensure we have the latest state
                status = self._load_delivery_status()
                now_local = datetime.now(tz=BEIJING_TZ)

                # Handle first-time verification email
                if not status.startup_completed:
                    logger.info("Sending verification email (first startup)")
                    if self._send_verification_email(now_local):
                        status.last_sent = now_local
                        status.startup_completed = True
                        self._store_delivery_status(status)
                        logger.info("Verification email sent successfully")
                    else:
                        logger.error("Failed to send verification email")
                    # Continue to check for daily reports (don't return here)

                # Handle daily report emails
                if status.startup_completed:
                    should_send_report = False

                    if status.last_sent is None:
                        # Verification was sent but no daily report yet
                        should_send_report = True
                    else:
                        # Check if we need to send today's report
                        last_sent_local = status.last_sent.astimezone(BEIJING_TZ)
                        if last_sent_local.date() != now_local.date():
                            should_send_report = True

                    if should_send_report:
                        contents = self._read_log_contents()
                        if contents is not None and contents.strip():
                            logger.info(f"Sending daily log report for {now_local.date()}")
                            if self._send_log_report(now_local, contents):
                                status.last_sent = now_local
                                self._store_delivery_status(status)
                                logger.info("Daily log report sent successfully")
                            else:
                                logger.error("Failed to send daily log report")
                        else:
                            logger.info("No log entries to send in daily report")
        finally:
            startup_lock.release()
            # Clean up lock file after release
            try:
                if self._startup_lock_path.exists():
                    self._startup_lock_path.unlink()
            except OSError:
                pass

    # Filesystem helpers --------------------------------------------

    def _ensure_log_dir_exists(self) -> bool:
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            return True
        except OSError as e:
            logger.error(f"Failed to create log directory: {e}")
            return False

    def _ensure_log_file_exists(self) -> None:
        try:
            if not self._log_path.exists():
                with self._log_path.open("a", encoding="utf-8"):
                    pass
        except OSError as exc:
            logger.error(f"Failed to create log file: {exc}")
            raise exc

    def _check_log_size(self) -> None:
        """Check if log file exceeds maximum size and truncate if needed."""
        try:
            if self._log_path.exists():
                size = self._log_path.stat().st_size
                if size > MAX_LOG_SIZE_BYTES:
                    logger.warning(f"Log file exceeds {MAX_LOG_SIZE_BYTES} bytes, truncating")
                    # Keep only the last 80% of the file
                    with self._log_path.open("r", encoding="utf-8") as f:
                        lines = f.readlines()
                    keep_lines = int(len(lines) * 0.8)
                    with self._log_path.open("w", encoding="utf-8") as f:
                        f.writelines(lines[-keep_lines:])
        except OSError as e:
            logger.warning(f"Failed to check/truncate log size: {e}")

    def _read_log_contents(self) -> Optional[str]:
        try:
            return self._log_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.debug("Log file not found")
            return None
        except OSError as e:
            logger.error(f"Failed to read log file: {e}")
            return None

    def _clear_log(self) -> None:
        try:
            with self._log_path.open("w", encoding="utf-8") as handle:
                handle.truncate(0)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError as e:
                    logger.warning(f"fsync failed while clearing log: {e}")
        except OSError as e:
            logger.error(f"Failed to clear log file: {e}")

    # Status helpers ------------------------------------------------

    def _load_delivery_status(self) -> "_DeliveryStatus":
        try:
            raw = self._status_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            logger.debug("Status file not found, using default status")
            return _DeliveryStatus()
        except OSError as e:
            logger.error(f"Failed to read status file: {e}")
            return _DeliveryStatus()

        if not raw:
            return _DeliveryStatus()

        if raw.startswith("{"):
            try:
                payload = json.loads(raw)
            except (ValueError, TypeError) as e:
                logger.error(f"Failed to parse status JSON: {e}")
                return _DeliveryStatus()

            last_sent_raw = payload.get("last_sent_utc")
            startup_completed = bool(payload.get("startup_completed"))

            last_sent = _parse_timestamp(last_sent_raw)
            return _DeliveryStatus(last_sent=last_sent, startup_completed=startup_completed)

        # Legacy format: just a timestamp
        last_sent = _parse_timestamp(raw)
        if last_sent is None:
            return _DeliveryStatus()
        return _DeliveryStatus(last_sent=last_sent, startup_completed=False)

    def _store_delivery_status(self, status: "_DeliveryStatus") -> None:
        payload = {
            "last_sent_utc": status.serialise_last_sent(),
            "startup_completed": status.startup_completed,
        }

        tmp_path = self._status_path.with_suffix(self._status_path.suffix + ".tmp")

        try:
            with tmp_path.open("w", encoding="utf-8") as f:
                json.dump(payload, f)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError as e:
                    logger.warning(f"fsync failed while storing status: {e}")

            # Atomic replace
            os.replace(tmp_path, self._status_path)
            logger.debug("Status file updated successfully")
        except OSError as e:
            logger.error(f"Failed to store status file: {e}")
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass

    # Email helpers -------------------------------------------------

    def _send_verification_email(self, now_local: datetime) -> bool:
        contents = self._read_log_contents()
        if contents is None:
            contents = ""

        subject = "WebAuthn Device Logs - verification startup"
        body_lines = [
            "Startup verification email for WebAuthn device logs.",
            "",
        ]
        if contents.strip():
            body_lines.append("Existing log entries:")
            body_lines.append(contents.rstrip())
        else:
            body_lines.append("No device registrations have been recorded yet.")
        body = "\n".join(body_lines).rstrip() + "\n"

        if self._deliver_email(subject, body):
            self._clear_log()
            return True
        return False

    def _send_log_report(self, now_local: datetime, contents: str) -> bool:
        subject = f"WebAuthn Device Logs (Beijing time {now_local.date().isoformat()})"
        body = contents.rstrip() + "\n"
        if self._deliver_email(subject, body):
            self._clear_log()
            return True
        return False

    # Internal helpers ---------------------------------------------

    def _initialise_log_dir(self) -> Path:
        configured = os.environ.get("REGISTRATION_LOG_DIRECTORY")
        candidates: list[Path] = []

        if configured:
            candidates.append(Path(configured).expanduser())
        else:
            data_home = os.environ.get("XDG_DATA_HOME")
            if data_home:
                candidates.append(Path(data_home) / LOG_STORAGE_DIRNAME)
            try:
                home_dir = Path.home()
            except Exception:
                home_dir = None
            if home_dir:
                candidates.append(home_dir / f".{LOG_STORAGE_DIRNAME}")
        candidates.append(Path(tempfile.gettempdir()) / LOG_STORAGE_DIRNAME)

        for candidate in candidates:
            try:
                candidate.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.debug(f"Could not create directory {candidate}: {e}")
                continue
            if candidate.is_dir():
                logger.info(f"Using log directory: {candidate}")
                return candidate

        raise RuntimeError("Unable to create log directory")

    def _load_email_config(self) -> Optional[EmailConfig]:
        email_address = os.environ.get("REGISTRATION_LOG_GMAIL_ADDRESS")
        client_id = os.environ.get("REGISTRATION_LOG_GMAIL_CLIENT_ID")
        client_secret = os.environ.get("REGISTRATION_LOG_GMAIL_CLIENT_SECRET")
        refresh_token = os.environ.get("REGISTRATION_LOG_GMAIL_REFRESH_TOKEN")

        if not all([email_address, client_id, client_secret, refresh_token]):
            logger.info("Email configuration incomplete, delivery disabled")
            return None

        try:
            retry_attempts = int(os.environ.get("REGISTRATION_LOG_EMAIL_RETRY_ATTEMPTS", "3"))
        except ValueError:
            retry_attempts = 3
        retry_attempts = max(retry_attempts, 1)

        try:
            retry_delay = float(os.environ.get("REGISTRATION_LOG_EMAIL_RETRY_DELAY_SECONDS", "5"))
        except ValueError:
            retry_delay = 5.0
        retry_delay = max(retry_delay, 1.0)

        try:
            config = EmailConfig(
                email_address=email_address,
                client_id=client_id,
                client_secret=client_secret,
                refresh_token=refresh_token,
                retry_attempts=retry_attempts,
                retry_delay_seconds=retry_delay,
            )
            logger.info("Email configuration loaded successfully")
            return config
        except ValueError as e:
            logger.error(f"Invalid email configuration: {e}")
            return None

    def _fetch_gmail_access_token(self) -> Optional[str]:
        if not self._email_config:
            return None

        payload = urllib_parse.urlencode(
            {
                "client_id": self._email_config.client_id,
                "client_secret": self._email_config.client_secret,
                "refresh_token": self._email_config.refresh_token,
                "grant_type": "refresh_token",
            }
        ).encode("utf-8")

        request = urllib_request.Request(
            "https://oauth2.googleapis.com/token",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        try:
            with urllib_request.urlopen(request, timeout=30) as response:
                data = response.read()
        except urllib_error.HTTPError as e:
            logger.error(f"HTTP error fetching access token: {e.code} {e.reason}")
            return None
        except urllib_error.URLError as e:
            logger.error(f"URL error fetching access token: {e.reason}")
            return None

        try:
            token_payload = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            logger.error(f"Failed to parse token response: {e}")
            return None

        access_token = token_payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            logger.error("Invalid access token in response")
            return None

        return access_token

    def _is_retryable_error(self, exc: Exception) -> bool:
        """Determine if an error is transient and should be retried."""
        if isinstance(exc, urllib_error.HTTPError):
            # Retry on server errors (5xx) and rate limits (429)
            # Don't retry on client errors (4xx) except 429
            if exc.code >= 500 or exc.code == 429:
                return True
            return False
        if isinstance(exc, urllib_error.URLError):
            # Network errors are typically retryable
            return True
        # Other errors (RuntimeError, ValueError) are not retryable
        return False

    def _deliver_email(self, subject: str, body: str) -> bool:
        if not self._email_config:
            logger.error("Cannot deliver email: no email configuration")
            return False

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self._email_config.email_address
        message["To"] = self._email_config.email_address
        message.set_content(body)

        last_error = None
        for attempt in range(1, self._email_config.retry_attempts + 1):
            try:
                access_token = self._fetch_gmail_access_token()
                if not access_token:
                    raise RuntimeError("Unable to obtain Gmail access token")

                encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
                request_body = json.dumps({"raw": encoded_message}).encode("utf-8")
                request = urllib_request.Request(
                    "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                    data=request_body,
                    method="POST",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json; charset=utf-8",
                    },
                )

                with urllib_request.urlopen(request, timeout=30) as response:
                    status = getattr(response, "status", None)
                    if status is None:
                        status = response.getcode()
                    if 200 <= status < 300:
                        logger.info(f"Email delivered successfully (attempt {attempt})")
                        return True
                    raise RuntimeError(f"Unexpected Gmail API response status: {status}")
            except (urllib_error.HTTPError, urllib_error.URLError, RuntimeError, ValueError) as e:
                last_error = e
                logger.warning(f"Email delivery attempt {attempt} failed: {e}")

                if attempt >= self._email_config.retry_attempts:
                    logger.error(f"All {self._email_config.retry_attempts} email delivery attempts failed")
                    return False

                # Only retry if the error is transient
                if not self._is_retryable_error(e):
                    logger.error(f"Non-retryable error, not retrying: {e}")
                    return False

                logger.info(f"Retrying in {self._email_config.retry_delay_seconds} seconds...")
                time.sleep(self._email_config.retry_delay_seconds)

        return False


_MANAGER = RegistrationLogManager()


def record_registration_event(
    aaguid: Optional[object],
    authenticator_name: Optional[str],
) -> None:
    """Public helper for route handlers to append registration log entries."""

    if _MANAGER.enabled:
        _MANAGER.record_event(aaguid, authenticator_name)