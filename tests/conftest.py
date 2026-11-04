

import pytest


@pytest.fixture(autouse=True)
def _no_local_focus(tmp_path, monkeypatch):
    """Tests must not read the developer's own focus file."""
    monkeypatch.setenv("GROUNDTRACE_FOCUS_FILE", str(tmp_path / "no-focus.json"))
