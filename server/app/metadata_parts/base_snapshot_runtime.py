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

    # Concurrent requests on a cold instance wait for a single parse of the
    # multi-megabyte snapshot instead of each loading their own copy.
    with _base_metadata_lock:
        if (
            _base_metadata_cache is not None
            and _base_metadata_source == "verified"
            and _base_metadata_mtime == verified_mtime
        ):
            return _base_metadata_cache, verified_mtime

        metadata, fallback_mtime = _load_verified_metadata_fallback()

        # Entry ids are published before the trust flag so a concurrent reader
        # can only ever observe "not yet trusted", never a stale trusted state.
        if metadata is not None:
            _base_metadata_entry_ids = {id(entry) for entry in metadata.entries}
            _base_metadata_trust_verified = True
            _base_metadata_source = "verified"
        else:
            _base_metadata_trust_verified = None
            _base_metadata_entry_ids = set()
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


def _load_packaged_explorer_meta(snapshot_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return a packaged snapshot's meta when it describes the verified snapshot.

    The snapshot tool writes every packaged file and its meta in one run, so
    matching ``no``, ``etag`` and generation time mean the packaged snapshot is
    current. File mtimes cannot be used for this: checkouts and image builds do
    not preserve their relative order. Defaults to the explorer snapshot.
    """

    path = snapshot_path or MDS_EXPLORER_PATH
    try:
        with open(path + ".meta.json", "r", encoding="utf-8") as handle:
            explorer_meta = json.load(handle)
        with open(MDS_METADATA_VERIFIED_PATH + ".meta.json", "r", encoding="utf-8") as handle:
            verified_meta = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(explorer_meta, dict) or not isinstance(verified_meta, dict):
        return None

    explorer_key = (
        explorer_meta.get("no"),
        explorer_meta.get("etag"),
        explorer_meta.get("generatedAt"),
    )
    verified_key = (
        verified_meta.get("no"),
        verified_meta.get("etag"),
        verified_meta.get("generated_at"),
    )
    if None in explorer_key or explorer_key != verified_key:
        return None
    return explorer_meta


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

    with _base_explorer_snapshot_lock:
        if (
            _base_explorer_snapshot_cache is not None
            and _base_explorer_snapshot_mtime == cache_marker
        ):
            return _base_explorer_snapshot_cache, cache_marker

        snapshot: Optional[Dict[str, Any]] = None

        packaged_is_current = explorer_mtime is not None and (
            verified_mtime is None
            or explorer_mtime >= verified_mtime
            or _load_packaged_explorer_meta() is not None
        )
        if packaged_is_current:
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

    with _base_full_snapshot_lock:
        if (
            _base_full_snapshot_cache is not None
            and _base_full_snapshot_mtime == verified_mtime
        ):
            return _base_full_snapshot_cache, verified_mtime

        snapshot: Optional[Dict[str, Any]] = None

        # The packaged full snapshot is built by the same code as the fallback
        # below; loading it avoids re-parsing every attestation certificate.
        if _load_packaged_explorer_meta(MDS_EXPLORER_FULL_PATH) is not None:
            try:
                with open(MDS_EXPLORER_FULL_PATH, "r", encoding="utf-8") as full_file:
                    loaded = json.load(full_file)
            except (OSError, json.JSONDecodeError):
                loaded = None
            if isinstance(loaded, dict) and isinstance(loaded.get("entries"), list):
                snapshot = loaded

        if snapshot is None:
            payload = _load_verified_metadata_payload()
            if payload is not None:
                snapshot = build_bootstrap_snapshot(payload, load_metadata_cache_entry())

        _base_full_snapshot_cache = snapshot
        _base_full_snapshot_mtime = verified_mtime
        return snapshot, verified_mtime


def load_packaged_explorer_summary() -> Dict[str, Any]:
    # The summary is only the snapshot's meta block, which the packaged meta
    # file already holds; avoid parsing the multi-megabyte snapshot for it.
    if _base_explorer_snapshot_cache is None:
        packaged_meta = _load_packaged_explorer_meta()
        if packaged_meta is not None:
            return dict(packaged_meta)

    snapshot, _ = _load_base_explorer_snapshot()
    if snapshot and isinstance(snapshot.get("meta"), Mapping):
        return dict(snapshot["meta"])

    payload = _load_verified_metadata_payload()
    if payload is None:
        return {}

    return build_explorer_snapshot(payload, load_metadata_cache_entry()).get("meta", {})
