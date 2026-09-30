"""``config.application``: a response handler registered once, and only before the first request."""
from __future__ import annotations

from flask import Flask

from server.app.config import application

MARKER = "_test_handler_marker"


def _marked(response):
    response.headers["X-Handled"] = "yes"
    return response


setattr(_marked, MARKER, True)


def test_a_handler_is_registered_once_however_often_it_is_added():
    app = Flask(__name__)
    app.add_url_rule("/", "index", lambda: "ok")

    application.add_after_request_once(app, _marked, MARKER)
    application.add_after_request_once(app, _marked, MARKER)

    assert app.after_request_funcs[None] == [_marked]
    assert app.test_client().get("/").headers["X-Handled"] == "yes"


def test_after_the_first_request_nothing_more_is_registered():
    # Flask refuses an after_request handler once the app has served a request.
    app = Flask(__name__)
    app.add_url_rule("/", "index", lambda: "ok")
    app.test_client().get("/")

    application.add_after_request_once(app, _marked, MARKER)

    assert app.after_request_funcs.get(None) == []
    assert "X-Handled" not in app.test_client().get("/").headers
