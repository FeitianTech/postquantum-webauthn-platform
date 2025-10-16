# Architecture

The platform couples a Flask backend with a modular JavaScript frontend to expose a full WebAuthn playground. This page explains how the pieces fit together.

## Application Entry Point

`server/server/app.py` serves as the executable entry point. It discovers the project root, imports the configuration module, and eagerly loads route packages so their Flask decorators register endpoints. When run directly it invokes `main()`, which ensures metadata bootstrapping occurs before starting the TLS-enabled development server on `https://demo.ftsafe.demo:5000` with debug mode enabled.【F:server/server/app.py†L1-L78】

## Configuration Layer

`server/server/config.py` defines the Flask application object, default relying party (RP) parameters, and helpers that derive RP IDs from incoming requests. It instantiates a `Fido2Server`, sets up metadata cache paths, and embeds the FIDO Metadata Service trust anchors used when verifying attestation chains.【F:server/server/config.py†L1-L234】 These utilities are imported throughout the backend to share the same RP entity, credential storage directory, and metadata constants.

## Routing and Metadata Services

The `routes` package contains multiple blueprints. `routes/general.py` handles high-level navigation, automatic MDS downloads, and REST endpoints for uploading, listing, and deleting session-specific metadata blobs. It protects the bootstrap process with a lock, gracefully handles rate limiting from the FIDO service, and renders the main `index.html` template with any cached metadata injected for client-side bootstrapping.【F:server/server/routes/general.py†L1-L205】

Additional route modules (`advanced` and `simple`) register WebAuthn ceremony endpoints imported alongside `general` in the entry point, while shared helpers like `storage.py` manage credential persistence in the module directory for easy inspection.【F:server/server/app.py†L52-L56】【F:server/server/storage.py†L1-L79】

## Frontend Composition

The frontend template `static/templates/index.html` stitches together shared header/navigation components plus the simple, advanced, decoder, and metadata tabs. It exposes initial metadata bootstrap data via DOM attributes and loads dedicated modules for the metadata explorer and overall UI orchestration.【F:server/server/static/templates/index.html†L1-L79】 The main JavaScript bundle (`static/scripts/main.js`) wires up WebAuthn helper functions, advanced form utilities, codec tooling, and credential management logic, exporting them on the `window` for use by declarative event handlers. It also initializes the loading overlay, randomizes demo inputs, and configures the JSON editor once the DOM is ready.【F:server/server/static/scripts/main.js†L1-L104】【F:server/server/static/scripts/main.js†L108-L160】
