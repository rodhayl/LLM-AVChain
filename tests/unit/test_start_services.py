from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from avchain.scripts import start_services


def test_wait_for_service_urls_succeeds(monkeypatch) -> None:
    urls = ("http://127.0.0.1:8000/docs", "http://127.0.0.1:8501")

    monkeypatch.setattr(start_services, "service_urls", lambda: urls)
    monkeypatch.setattr(start_services.time, "sleep", lambda _: None)

    def fake_get(url: str, timeout: float) -> httpx.Response:
        _ = timeout
        return httpx.Response(200, request=httpx.Request("GET", url))

    monkeypatch.setattr(start_services.httpx, "get", fake_get)

    start_services.wait_for_service_urls(timeout=0.1)


def test_wait_for_worker_statuses_succeeds(monkeypatch) -> None:
    heartbeat = datetime.now(UTC).isoformat()
    statuses = {
        "validator1": {"last_heartbeat": heartbeat},
        "validator2": {"last_heartbeat": heartbeat},
        "validator3": {"last_heartbeat": heartbeat},
        "agent": {"last_heartbeat": heartbeat},
    }

    monkeypatch.setattr(start_services, "worker_status_names", lambda: tuple(statuses))
    monkeypatch.setattr(start_services, "read_status", lambda name: statuses.get(name))
    monkeypatch.setattr(start_services.time, "sleep", lambda _: None)

    start_services.wait_for_worker_statuses(timeout=0.1)


@pytest.mark.parametrize("failure", ["status", "spawn"])
def test_supervisor_cleans_children_when_startup_fails(monkeypatch, failure) -> None:
    from avchain.utils.runtime_status import StatusPublicationError

    children = []
    logs = []

    class Child:
        def __init__(self, pid):
            self.pid = pid
            self.stopped = False

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            self.stopped = True

        def wait(self, timeout):
            assert timeout == 10
            assert self.stopped
            return 0

    def spawn(command, title):
        if failure == "spawn" and len(children) == 2:
            raise OSError("spawn denied")
        child = Child(100 + len(children))
        children.append(child)
        return child

    def unavailable(*args):
        raise StatusPublicationError("status denied")

    def stop_tree(command, **kwargs):
        assert command[0] == "taskkill"
        pid = int(command[2])
        next(child for child in children if child.pid == pid).stopped = True

    monkeypatch.setattr(start_services, "ensure_runtime_prerequisites", lambda: None)
    monkeypatch.setattr(start_services, "ensure_ports_available", lambda *args: None)
    monkeypatch.setattr(start_services, "start_process", spawn)
    monkeypatch.setattr(start_services, "write_status", unavailable)
    monkeypatch.setattr(start_services, "_log_supervisor", logs.append)
    monkeypatch.setattr(start_services.subprocess, "run", stop_tree)
    with pytest.raises(
        OSError, match="status denied" if failure == "status" else "spawn denied"
    ):
        start_services.main()
    assert len(children) == (9 if failure == "status" else 2)
    assert all(child.stopped for child in children)
    assert any("status publication failed while stopping" in line for line in logs)
