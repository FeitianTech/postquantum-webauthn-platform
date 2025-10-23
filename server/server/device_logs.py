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
                # Open in append mode to create if doesn't exist, but preserve content
                file_handle = self._path.open("a+")
            except OSError as e:
                logger.warning(f"Failed to open lock file: {e}")
                return False

            try:
                if fcntl is not None:
                    # Try non-blocking lock
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
                # Lock is held by another process, close and retry
                pass
            except OSError as e:
                logger.warning(f"Lock acquisition failed: {e}")
                file_handle.close()
                raise

            file_handle.close()

            if not self._sleep_until(deadline, poll_interval):
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
    last_verification_sent: Optional[datetime] = None
    last_daily_sent: Optional[datetime] = None
    startup_completed: bool = False

    def serialise_last_verification(self) -> Optional[str]:
        if self.last_verification_sent is None:
            return None
        return self.last_verification_sent.astimezone(timezone.utc).isoformat()

    def serialise_last_daily(self) -> Optional[str]:
        if self.last_daily_sent is None:
            return None
        return self.last_daily_sent.astimezone(timezone.utc).isoformat()


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
        """Handle startup processing with cross-process coordination.

        This routine ensures that only one process sends the verification
        email for a given deployment. It also determines whether a daily
        report should be sent based on the last sent timestamp. To avoid
        duplicate verification emails, the status file is updated only
        after the email is successfully delivered or explicitly marked.
        """
        # Acquire an inter-process lock to ensure only one worker handles
        # startup tasks at any given time. Without this lock, multiple
        # workers started simultaneously (for example, in a multi-process
        # web server) could all attempt to send the verification email.
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
                # Ensure the log file is available. If this fails, disable
                # logging and email delivery to avoid repeated attempts.
                try:
                    self._ensure_log_file_exists()
                except OSError as e:
                    logger.error(f"Failed to create log file: {e}")
                    self.enabled = False
                    self.delivery_enabled = False
                    return

                # Reload the status after acquiring the lock to obtain the
                # most up‑to‑date view of when emails were last sent.
                status = self._load_delivery_status()
                now_local = self._current_time()

                # If this is the first startup (status.startup_completed is False),
                # attempt to send a verification email. On success, mark the
                # startup as completed and record the send time. We return
                # immediately to avoid sending a daily report on the same
                # startup. If delivery fails, log an error and continue to
                # evaluate sending a daily report to avoid log build‑up.
                if not status.startup_completed:
                    logger.info("Sending verification email (first startup)")
                    if self._send_verification_email(now_local):
                        status.last_verification_sent = now_local
                        status.startup_completed = True
                        self._store_delivery_status(status)
                        logger.info("Verification email sent successfully")
                        # Do not send a daily report on the same startup as
                        # the verification email.
                        return
                    else:
                        logger.error("Failed to send verification email")
                        # Continue below to determine if a daily report is due.

                # Determine whether a daily log report should be sent. We only
                # send a report when there are log entries and either no
                # previous report has been sent (status.last_daily_sent is
                # None) or the date has changed relative to the last sent
                # timestamp.
                should_send_report = False
                if status.last_daily_sent is None:
                    # No previous report has been sent; send one now.
                    should_send_report = True
                else:
                    last_daily_local = status.last_daily_sent.astimezone(BEIJING_TZ)
                    if last_daily_local.date() != now_local.date():
                        should_send_report = True

                # Send the daily log report if due. If there are no log
                # entries, skip sending. After successfully sending the
                # report, update the status with the new timestamp and mark
                # startup as complete if it was not already marked (e.g., if
                # verification failed previously).
                if should_send_report:
                    contents = self._read_log_contents()
                    if contents is not None and contents.strip():
                        logger.info(f"Sending daily log report for {now_local.date()}")
                        if self._send_log_report(now_local, contents):
                            status.last_daily_sent = now_local
                            if not status.startup_completed:
                                status.startup_completed = True
                            if status.last_verification_sent is None:
                                status.last_verification_sent = now_local
                            self._store_delivery_status(status)
                            logger.info("Daily log report sent successfully")
                        else:
                            logger.error("Failed to send daily log report")
                    else:
                        logger.info("No log entries to send in daily report")
        finally:
            startup_lock.release()
            # Note: Do NOT delete the lock file here. Removing the lock file
            # can lead to race conditions where multiple processes believe
            # they have acquired the lock simultaneously.

    # Filesystem helpers --------------------------------------------

    def _current_time(self) -> datetime:
        """Return the current time in the configured local timezone."""

        return datetime.now(tz=BEIJING_TZ)

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

            startup_completed = bool(payload.get("startup_completed"))
            last_verification_raw = payload.get("last_verification_sent_utc")
            last_daily_raw = payload.get("last_daily_sent_utc")

            # Backwards compatibility with the previous single timestamp format.
            if last_verification_raw is None and last_daily_raw is None:
                legacy_last_sent = payload.get("last_sent_utc")
                last_verification = _parse_timestamp(legacy_last_sent)
                last_daily = _parse_timestamp(legacy_last_sent)
            else:
                last_verification = _parse_timestamp(last_verification_raw)
                last_daily = _parse_timestamp(last_daily_raw)

            return _DeliveryStatus(
                last_verification_sent=last_verification,
                last_daily_sent=last_daily,
                startup_completed=startup_completed,
            )

        # Legacy format: just a timestamp
        legacy_last_sent = _parse_timestamp(raw)
        if legacy_last_sent is None:
            return _DeliveryStatus()
        return _DeliveryStatus(
            last_verification_sent=legacy_last_sent,
            last_daily_sent=legacy_last_sent,
            startup_completed=False,
        )

    def _store_delivery_status(self, status: "_DeliveryStatus") -> None:
        payload = {
            "last_verification_sent_utc": status.serialise_last_verification(),
            "last_daily_sent_utc": status.serialise_last_daily(),
            "startup_completed": status.startup_completed,
            # Retain the legacy key for compatibility with older deployments.
            "last_sent_utc": status.serialise_last_daily() or status.serialise_last_verification(),
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
        """Determine where to store logs and status for this deployment.

        The default behaviour is to honour an explicit configuration via the
        ``REGISTRATION_LOG_DIRECTORY`` environment variable. If not set,
        logs are stored under the system temporary directory. Sticking to
        one well‑defined location avoids discrepancies between different
        worker processes that may have different home or data directories.
        """
        # If a specific directory is configured, attempt to use it.
        configured = os.environ.get("REGISTRATION_LOG_DIRECTORY")
        if configured:
            path = Path(configured).expanduser()
            try:
                path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Using log directory from REGISTRATION_LOG_DIRECTORY: {path}")
                return path
            except Exception as e:
                logger.warning(f"Unable to use configured log directory {path}: {e}")

        # Next, prefer a per-user data directory which is stable across
        # processes for the same deployment.
        home_dir = Path.home()
        if home_dir.exists():
            preferred = home_dir / LOG_STORAGE_DIRNAME
            try:
                preferred.mkdir(parents=True, exist_ok=True)
                logger.info(f"Using log directory in home path: {preferred}")
                return preferred
            except Exception as e:
                logger.warning(f"Unable to create home log directory {preferred}: {e}")

        # Fall back to a stable location under the system temporary directory.
        # This location is consistent across processes on the same host and
        # avoids the variability of per‑user home or XDG directories.
        fallback = Path(tempfile.gettempdir()) / LOG_STORAGE_DIRNAME
        try:
            fallback.mkdir(parents=True, exist_ok=True)
            logger.info(f"Using temporary log directory: {fallback}")
            return fallback
        except Exception as e:
            logger.error(f"Failed to create fallback log directory {fallback}: {e}")
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