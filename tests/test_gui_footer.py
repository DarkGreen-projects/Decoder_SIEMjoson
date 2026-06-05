from __future__ import annotations

import inspect
from unittest.mock import MagicMock

from decoder_siem.gui import GUI_CSS, _launch_app, _launch_kwargs


def _signature_with_params(*names: str) -> inspect.Signature:
    return inspect.Signature(
        parameters=[
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                default=None if name == "footer_links" else "127.0.0.1",
            )
            for name in names
        ]
    )


def test_gui_css_hides_gradio_footer():
    assert "footer" in GUI_CSS
    assert "display: none" in GUI_CSS


def test_launch_kwargs_footer_links_when_supported():
    app = MagicMock()
    app.launch.__signature__ = _signature_with_params("footer_links", "server_name")

    kwargs = _launch_kwargs(app)
    assert kwargs["server_name"] == "127.0.0.1"
    assert kwargs["footer_links"] == []


def test_launch_kwargs_show_api_when_footer_links_unavailable():
    app = MagicMock()
    app.launch.__signature__ = _signature_with_params("show_api", "server_name")

    kwargs = _launch_kwargs(app)
    assert kwargs["server_name"] == "127.0.0.1"
    assert kwargs["show_api"] is False
    assert "footer_links" not in kwargs


def test_launch_app_calls_launch_with_kwargs():
    app = MagicMock()
    app.launch.__signature__ = _signature_with_params("footer_links", "server_name")

    _launch_app(app)

    app.launch.assert_called_once()
    call_kwargs = app.launch.call_args.kwargs
    assert call_kwargs["server_name"] == "127.0.0.1"
    assert call_kwargs["footer_links"] == []
