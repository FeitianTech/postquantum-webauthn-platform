"""Background logging and email delivery for WebAuthn device registrations."""
from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable, Optional

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
LOG_PREFIX = "webauthn_device_logs_"
LOG_SUFFIX = ".log"
REPORT_HOUR = 9
LOCK_FILENAME = "webauthn_device_logs.lock"
STALE_LOCK_MAX_AGE_SECONDS = 6 * 60 * 60  # 6 hours
STATUS_FILENAME = "webauthn_device_logs.status"
MAX_LOCK_RECURSION_DEPTH = 3
LOG_STORAGE_DIRNAME = "webauthn-device-logs"


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
        if len(data) == 16:
            try:
                return str(uuid.UUID(bytes=data))
            except ValueError:
                pass
        return data.hex() or "unknown-aaguid"
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


@dataclass
class EmailConfig:
    email_address: str
    client_id: str
    client_secret: str
    refresh_token: str
    retry_attempts: int
    retry_delay_seconds: float


class RegistrationLogManager:
    """Coordinate log writes and scheduled email delivery."""

    def __init__(self) -> None:
        self._write_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._email_config = self._load_email_config()
        self.delivery_enabled = self._email_config is not None and _env_flag(
            "REGISTRATION_LOG_EMAIL_ENABLED", default=True
        )
        self.enabled = True

        try:
            self.log_dir = self._initialise_log_dir()
        except RuntimeError:
            self.enabled = False
            self.delivery_enabled = False
            return

        self._lock_path = self.log_dir / LOCK_FILENAME
        self._status_path = self.log_dir / STATUS_FILENAME
        self._last_processed_report_date = self._load_last_processed_report_date()

        # Clean up any stale scheduler lock left over from crashes or deploys.
        self._remove_stale_lock_if_present()

        if not self.delivery_enabled:
            return

        # Process any due reports immediately (e.g., after restarts).
        self._process_due_reports(initial=True)

        self._thread = threading.Thread(
            target=self._run_scheduler,
            name="RegistrationLogScheduler",
            daemon=True,
        )
        self._thread.start()

    def record_event(self, aaguid: Optional[object], authenticator_name: Optional[str]) -> None:
        if not self.enabled:
            return

        timestamp = datetime.now(tz=BEIJING_TZ)
        report_date = self._report_date_for_timestamp(timestamp)
        line = (
            f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} ({TIMEZONE_LABEL}) | "
            f"{_normalise_aaguid(aaguid)} | {_clean_authenticator_name(authenticator_name)}"
        )

        log_path = self._log_path_for_date(report_date)
        try:
            with self._write_lock:
                if not self.log_dir.exists():
                    self.log_dir.mkdir(parents=True, exist_ok=True)
                with log_path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
        except Exception:
            # Swallow logging errors to avoid impacting request handling.
            return

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
            except Exception:
                continue
            if candidate.is_dir():
                return candidate

        raise RuntimeError("Unable to create log directory")

    # Internal helpers -------------------------------------------------

    def _load_email_config(self) -> Optional[EmailConfig]:
        email_address = os.environ.get("REGISTRATION_LOG_GMAIL_ADDRESS")
        client_id = os.environ.get("REGISTRATION_LOG_GMAIL_CLIENT_ID")
        client_secret = os.environ.get("REGISTRATION_LOG_GMAIL_CLIENT_SECRET")
        refresh_token = os.environ.get("REGISTRATION_LOG_GMAIL_REFRESH_TOKEN")

        if not all([email_address, client_id, client_secret, refresh_token]):
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

        return EmailConfig(
            email_address=email_address,
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
            retry_attempts=retry_attempts,
            retry_delay_seconds=retry_delay,
        )

    def _report_date_for_timestamp(self, ts: datetime) -> date:
        local_ts = ts.astimezone(BEIJING_TZ)
        cutoff = local_ts.replace(hour=REPORT_HOUR, minute=0, second=0, microsecond=0)
        if local_ts < cutoff:
            return local_ts.date()
        return (local_ts + timedelta(days=1)).date()

    def _log_path_for_date(self, report_date: date) -> Path:
        filename = f"{LOG_PREFIX}{report_date.isoformat()}{LOG_SUFFIX}"
        return self.log_dir / filename

    def _acquire_lock(self, recursion_depth: int = 0) -> bool:
        if recursion_depth >= MAX_LOCK_RECURSION_DEPTH:
            return False

        try:
            fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if self._remove_stale_lock_if_present():
                return self._acquire_lock(recursion_depth + 1)
            return False
        except OSError:
            return False
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(f"pid={os.getpid()}\n")
                handle.write(f"timestamp={int(time.time())}\n")
            return True

    def _release_lock(self) -> None:
        try:
            os.unlink(self._lock_path)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _run_scheduler(self) -> None:
        while True:
            sleep_seconds = self._seconds_until_next_run()
            time.sleep(sleep_seconds)
            self._process_due_reports(initial=False)

    def _seconds_until_next_run(self) -> float:
        now_utc = datetime.now(tz=timezone.utc)
        local_now = now_utc.astimezone(BEIJING_TZ)
        target = local_now.replace(hour=REPORT_HOUR, minute=0, second=0, microsecond=0)
        if local_now >= target:
            target = target + timedelta(days=1)
        delta = target - local_now
        seconds = delta.total_seconds()
        return max(seconds, 60.0)

    def _due_log_files(self, due_through_date: date) -> Iterable[tuple[date, Path]]:
        for path in sorted(self.log_dir.glob(f"{LOG_PREFIX}*{LOG_SUFFIX}")):
            report_date = self._parse_report_date(path.name)
            if report_date is None or report_date > due_through_date:
                continue
            yield report_date, path

    def _parse_report_date(self, filename: str) -> Optional[date]:
        if not filename.startswith(LOG_PREFIX) or not filename.endswith(LOG_SUFFIX):
            return None
        raw = filename[len(LOG_PREFIX) : -len(LOG_SUFFIX)]
        try:
            return date.fromisoformat(raw)
        except ValueError:
            return None

    def _scheduled_report_date(self, now_local: datetime) -> date:
        cutoff = now_local.replace(hour=REPORT_HOUR, minute=0, second=0, microsecond=0)
        if now_local >= cutoff:
            return now_local.date()
        return (now_local - timedelta(days=1)).date()

    def _process_due_reports(self, *, initial: bool) -> None:
        if not (self.enabled and self.delivery_enabled):
            return
        if not self._acquire_lock():
            return

        try:
            now_local = datetime.now(tz=BEIJING_TZ)
            due_through_date = self._scheduled_report_date(now_local)
            attempted = False
            failed = False
            sent_count = 0
            empty_count = 0

            for report_date, path in self._due_log_files(due_through_date):
                if (
                    self._last_processed_report_date is not None
                    and report_date <= self._last_processed_report_date
                    and not self._should_force_resend(report_date, path, now_local)
                ):
                    continue

                attempted = True
                send_result = self._send_report(report_date, path)

                if send_result == "sent":
                    sent_count += 1
                    self._last_processed_report_date = report_date
                    self._store_last_processed_report_date(report_date)
                elif send_result == "empty":
                    empty_count += 1
                    self._last_processed_report_date = report_date
                    self._store_last_processed_report_date(report_date)
                else:  # "failed"
                    failed = True
                    break

            # Only update status to due_through_date if all reports were processed successfully
            if not failed and attempted:
                if (
                    self._last_processed_report_date is None
                    or self._last_processed_report_date < due_through_date
                ):
                    self._last_processed_report_date = due_through_date
                    self._store_last_processed_report_date(due_through_date)

            # Print summary only once per run
            if not initial:
                if sent_count > 0:
                    print(f"Sent {sent_count} device log report(s) and deleted file(s)")
                elif empty_count > 0 or not attempted:
                    print("No device logs today")
        finally:
            self._release_lock()

    def _send_report(self, report_date: date, path: Path) -> str:
        """
        Send a report for the given date.

        Returns:
            "sent" if email was successfully sent
            "empty" if log file was empty (and deleted)
            "failed" if there was an error
        """
        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return "failed"
        except OSError:
            return "failed"

        if not content.strip():
            try:
                path.unlink()
            except (FileNotFoundError, OSError):
                pass
            return "empty"

        if not self._email_config:
            return "failed"

        subject = f"WebAuthn Device Logs (Beijing time {report_date.isoformat()})"
        if self._deliver_email(subject, content):
            try:
                path.unlink()
            except (FileNotFoundError, OSError):
                pass
            return "sent"

        return "failed"

    def _remove_stale_lock_if_present(self) -> bool:
        try:
            metadata = self._lock_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        except OSError:
            metadata = ""

        if not self._is_lock_stale(metadata):
            return False

        try:
            self._lock_path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    def _is_lock_stale(self, metadata: str) -> bool:
        pid = None
        timestamp = None

        for line in metadata.splitlines():
            if line.startswith("pid="):
                try:
                    pid = int(line.split("=", 1)[1])
                except (ValueError, IndexError):
                    pid = None
            if line.startswith("timestamp="):
                try:
                    timestamp = int(line.split("=", 1)[1])
                except (ValueError, IndexError):
                    timestamp = None

        if pid is not None:
            if not self._process_alive(pid):
                return True

        if timestamp is not None:
            age = time.time() - timestamp
            if age >= STALE_LOCK_MAX_AGE_SECONDS:
                return True

        try:
            stat_result = self._lock_path.stat()
        except OSError:
            return False

        age = time.time() - stat_result.st_mtime
        return age >= STALE_LOCK_MAX_AGE_SECONDS

    @staticmethod
    def _process_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    def _load_last_processed_report_date(self) -> Optional[date]:
        try:
            raw = self._status_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return None
        except OSError:
            return None

        if not raw:
            return None

        try:
            return date.fromisoformat(raw)
        except ValueError:
            return None

    def _store_last_processed_report_date(self, report_date: date) -> None:
        try:
            self._status_path.write_text(report_date.isoformat(), encoding="utf-8")
        except OSError:
            pass

    def _should_force_resend(self, report_date: date, path: Path, now_local: datetime) -> bool:
        if now_local.date() <= report_date:
            return False

        if (now_local.date() - report_date) < timedelta(days=1):
            return False

        try:
            stat_result = path.stat()
        except FileNotFoundError:
            return False
        except OSError:
            return False

        if stat_result.st_size <= 0:
            return False

        return True

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
        except (urllib_error.HTTPError, urllib_error.URLError):
            return None

        try:
            token_payload = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

        access_token = token_payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            return None

        return access_token

    def _deliver_email(self, subject: str, body: str) -> bool:
        if not self._email_config:
            return False

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self._email_config.email_address
        message["To"] = self._email_config.email_address
        message.set_content(body.rstrip() + "\n")

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
                        return True
                    raise RuntimeError(f"Unexpected Gmail API response status: {status}")
            except (urllib_error.HTTPError, urllib_error.URLError, RuntimeError, ValueError):
                if attempt >= self._email_config.retry_attempts:
                    return False
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
