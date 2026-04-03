# AGENTS.md

This file is a quick orientation guide for coding agents working in this repository.

## Repository Purpose

This project is a Flask-based WebAuthn/FIDO2 demo and developer tool focused on:

- Simple registration and authentication flows
- Advanced WebAuthn request editing and debugging
- Post-quantum credential and algorithm experiments
- Credential inspection, attestation decoding, and metadata exploration
- A browser-based decoder for WebAuthn / CTAP structures

The repo includes both the application and a local `fido2/` library copy used by the server.

## High-Level Layout

- `server/app/`
  Flask app, route handlers, configuration, storage, attestation processing, metadata bootstrap, decoder logic.
- `frontend/templates/`
  Jinja/HTML templates for the main tabs and shared UI fragments.
- `frontend/static/scripts/`
  Frontend behavior, organized by feature area.
- `frontend/static/styles/`
  Shared and advanced-tab CSS.
- `tests/`
  App, library, PQC, and optional device tests.
- `fido2/`
  Local Python FIDO2 implementation used by the app. Treat changes here as library-level changes, not normal UI work.

## Frontend Map

The app is a multi-tab UI wired together from `frontend/static/scripts/main.js`.

Important frontend entry points:

- `frontend/static/scripts/simple/auth-simple.js`
  Simple register/authenticate flows.
- `frontend/static/scripts/advanced/auth-advanced.js`
  Advanced register/authenticate flows.
- `frontend/static/scripts/advanced/credential-display.js`
  Shared saved-credential list, card rendering, credential detail modal, list refresh behavior.
- `frontend/static/scripts/advanced/json-editor.js`
  Advanced JSON editor state and synchronization.
- `frontend/static/scripts/shared/navigation.js`
  Top-level tab switching and advanced sub-tab switching.
- `frontend/static/scripts/shared/local-storage.js`
  Browser-side stored credential records and serialization sent back to the server.
- `frontend/static/styles/shared/layout.css`
  Shared layout and credential card animation styles.

Important templates:

- `frontend/templates/simple/tab.html`
- `frontend/templates/advanced/tab.html`
- `frontend/templates/decoder/tab.html`
- `frontend/templates/shared/navigation.html`

## Backend Map

Flask app setup starts in:

- `server/app/app.py`
- `server/app/config.py`

Main route modules:

- `server/app/routes/simple.py`
  Simple WebAuthn begin/complete endpoints.
- `server/app/routes/advanced.py`
  Advanced WebAuthn begin/complete endpoints, algorithm handling, request validation, metadata-heavy flows.
- `server/app/routes/general.py`
  Index page, metadata bootstrap helpers, decoder endpoints, misc app routes.

Related backend modules:

- `server/app/attestation.py`
  Attestation parsing and validation helpers.
- `server/app/storage.py`
  Persistent credential storage helpers.
- `server/app/metadata.py`
  Metadata cache/bootstrap logic.
- `server/app/decoder/`
  Decoder/encoder logic used by the developer tooling UI.

## How Data Flows

For authentication work, the important path is usually:

1. Frontend collects stored credentials from browser-side storage.
2. Begin endpoint issues request options and stores server-side state in Flask session.
3. Browser performs `navigator.credentials.create/get`.
4. Complete endpoint verifies the response using `create_fido_server(...)`.
5. Frontend updates local saved credential state and refreshes the shared credential list.

The saved credential cards shown in simple and advanced tabs are rendered by the same shared display module, so UI changes there often affect both tabs.

## Common Places To Edit

- Credential card visuals or behavior:
  `frontend/static/scripts/advanced/credential-display.js`
  `frontend/static/styles/shared/layout.css`
- Simple auth UX:
  `frontend/static/scripts/simple/auth-simple.js`
  `server/app/routes/simple.py`
- Advanced auth UX:
  `frontend/static/scripts/advanced/auth-advanced.js`
  `server/app/routes/advanced.py`
- JSON editor or advanced request shaping:
  `frontend/static/scripts/advanced/json-editor.js`
  `frontend/static/scripts/advanced/forms.js`
  `frontend/static/scripts/advanced/hints.js`

## Testing Guidance

Fast checks:

- Frontend syntax:
  `node --check <file>`
- Python syntax:
  `python -m compileall <file-or-dir>`
- Focused pytest:
  `pytest -q tests/app/<target_test>.py`

Repo test layout:

- `tests/app/`
  Flask/app behavior.
- `tests/fido2/`
  Library-level tests for the local `fido2/` copy.
- `tests/pqc/`
  PQC-related tests.
- `tests/device/`
  Hardware tests. These are skipped unless explicitly enabled.

If you are changing only UI logic plus lightweight server responses, prefer targeted tests over the full suite first.

## Repo-Specific Gotchas

- The frontend is plain JS modules, not React/Vue.
- Global functions are intentionally exposed from `frontend/static/scripts/main.js` for template event handlers.
- The simple and advanced tabs share the saved credential display, so re-render logic can have cross-tab side effects.
- Flask session state matters in begin/complete flows. Be careful not to break the fallback `__session_state` handling.
- `server/app/routes/advanced.py` is large. Search before editing and make the smallest safe change.
- The local `fido2/` directory is part of the repo. Do not assume behavior matches the latest upstream package.

## Good First Step For Most Tasks

Before changing code, identify:

1. Which tab or route owns the user-visible behavior.
2. Whether the change affects shared credential rendering.
3. Whether the server returns data that the frontend currently needs but does not receive.
4. The smallest focused test that proves the change.

## Recommended Working Style

- Read the specific route and its matching frontend module together.
- Prefer focused fixes over broad refactors unless the task explicitly asks for restructuring.
- Verify both simple and advanced flows whenever you touch shared credential UI or browser storage behavior.
- When adding server response fields, update both the frontend handling and at least one focused app test.
