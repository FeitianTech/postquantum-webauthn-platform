"""Base metadata and packaged snapshot loading helpers."""
from __future__ import annotations


def load_cached_metadata_snapshot() -> bool:
    """Warm in-memory caches from the stored MDS metadata when available."""

    metadata, _ = _load_base_metadata()
    return metadata is not None


def _load_base_metadata() -> Tuple[Optional[MetadataBlobPayload], Optional[float]]:
    global _base_metadata_cache, _base_metadata_mtime, _base_metadata_source
    global _base_metadata_trust_verified, _base_metadata_entry_ids

    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    if (
        _base_metadata_cache is not None
        and _base_metadata_source == "verified"
        and _base_metadata_mtime == verified_mtime
    ):
        return _base_metadata_cache, verified_mtime

    metadata, fallback_mtime = _load_verified_metadata_fallback()

    if metadata is not None:
        _base_metadata_entry_ids = {id(entry) for entry in metadata.entries}
        _base_metadata_trust_verified = True
        _base_metadata_source = "verified"
    else:
        _base_metadata_entry_ids = set()
        _base_metadata_trust_verified = None
        _base_metadata_source = None

    _base_metadata_cache = metadata
    _base_metadata_mtime = fallback_mtime
    return metadata, fallback_mtime


def _load_verified_metadata_fallback() -> Tuple[Optional[MetadataBlobPayload], Optional[float]]:
    """Load the bundled verified metadata snapshot shipped with the application."""

    try:
        fallback_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        fallback_mtime = None

    try:
        with open(MDS_METADATA_VERIFIED_PATH, "r", encoding="utf-8") as fallback_file:
            payload = json.load(fallback_file)
    except FileNotFoundError:
        return None, fallback_mtime
    except (OSError, json.JSONDecodeError) as exc:
        app.logger.warning(
            "Unable to load verified metadata fallback %s: %s",
            MDS_METADATA_VERIFIED_PATH,
            exc,
        )
        return None, fallback_mtime

    try:
        return MetadataBlobPayload.from_dict(payload), fallback_mtime
    except Exception as exc:  # pylint: disable=broad-except
        app.logger.warning(
            "Verified metadata fallback %s is invalid: %s",
            MDS_METADATA_VERIFIED_PATH,
            exc,
        )
        return None, fallback_mtime


def _load_verified_metadata_payload() -> Optional[Dict[str, Any]]:
    try:
        with open(MDS_METADATA_VERIFIED_PATH, "r", encoding="utf-8") as fallback_file:
            payload = json.load(fallback_file)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None
    return payload


def _load_base_explorer_snapshot() -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[Optional[float], Optional[float]]]]:
    global _base_explorer_snapshot_cache, _base_explorer_snapshot_mtime

    try:
        explorer_mtime = os.path.getmtime(MDS_EXPLORER_PATH)
    except OSError:
        explorer_mtime = None

    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    cache_marker = (explorer_mtime, verified_mtime)
    if (
        _base_explorer_snapshot_cache is not None
        and _base_explorer_snapshot_mtime == cache_marker
    ):
        return _base_explorer_snapshot_cache, cache_marker

    snapshot: Optional[Dict[str, Any]] = None

    if explorer_mtime is not None and (verified_mtime is None or explorer_mtime >= verified_mtime):
        try:
            with open(MDS_EXPLORER_PATH, "r", encoding="utf-8") as explorer_file:
                loaded = json.load(explorer_file)
        except (OSError, json.JSONDecodeError):
            loaded = None
        if isinstance(loaded, dict):
            snapshot = loaded

    if snapshot is None:
        payload = _load_verified_metadata_payload()
        if payload is not None:
            snapshot = build_explorer_snapshot(payload, load_metadata_cache_entry())

    _base_explorer_snapshot_cache = snapshot
    _base_explorer_snapshot_mtime = cache_marker
    return snapshot, cache_marker


def _load_base_full_snapshot() -> Tuple[Optional[Dict[str, Any]], Optional[float]]:
    global _base_full_snapshot_cache, _base_full_snapshot_mtime

    try:
        verified_mtime = os.path.getmtime(MDS_METADATA_VERIFIED_PATH)
    except OSError:
        verified_mtime = None

    if (
        _base_full_snapshot_cache is not None
        and _base_full_snapshot_mtime == verified_mtime
    ):
        return _base_full_snapshot_cache, verified_mtime

    snapshot: Optional[Dict[str, Any]] = None
    payload = _load_verified_metadata_payload()
    if payload is not None:
        snapshot = build_bootstrap_snapshot(payload, load_metadata_cache_entry())

    _base_full_snapshot_cache = snapshot
    _base_full_snapshot_mtime = verified_mtime
    return snapshot, verified_mtime


def load_packaged_explorer_summary() -> Dict[str, Any]:
    snapshot, _ = _load_base_explorer_snapshot()
    if snapshot and isinstance(snapshot.get("meta"), Mapping):
        return dict(snapshot["meta"])

    payload = _load_verified_metadata_payload()
    if payload is None:
        return {}

    return build_explorer_snapshot(payload, load_metadata_cache_entry()).get("meta", {})
