"""Tests for the Flask web dashboard."""
from __future__ import annotations

import json

import pytest

from ralf.dashboard.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index_page(client):
    rv = client.get("/")
    assert rv.status_code == 200
    assert b"RALF" in rv.data
    assert b"Live Feed" in rv.data


def test_api_status(client):
    rv = client.get("/api/status")
    assert rv.status_code == 200
    data = rv.get_json()
    assert "paused" in data
    assert "rule_count" in data
    assert "stats" in data


def test_api_feed(client):
    rv = client.get("/api/feed?n=10")
    assert rv.status_code == 200
    data = rv.get_json()
    assert isinstance(data, list)


def test_api_feed_filter(client):
    rv = client.get("/api/feed?n=10&decision=block")
    assert rv.status_code == 200
    data = rv.get_json()
    assert isinstance(data, list)


def test_api_app_control_get(client):
    rv = client.get("/api/app-control")
    assert rv.status_code == 200
    data = rv.get_json()
    assert "allow" in data
    assert "block" in data
    assert "review" in data


def test_api_app_control_set_requires_token(client):
    rv = client.post(
        "/api/app-control",
        data=json.dumps({"action": "block"}),
        content_type="application/json",
    )
    assert rv.status_code == 400


def test_api_app_control_invalid_action(client):
    rv = client.post(
        "/api/app-control",
        data=json.dumps({"token": "test_bin", "action": "invalid"}),
        content_type="application/json",
    )
    assert rv.status_code == 400


def test_api_test_requires_command(client):
    rv = client.post(
        "/api/test",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert rv.status_code == 400


def test_api_test_benign(client):
    rv = client.post(
        "/api/test",
        data=json.dumps({"command": "ls /tmp"}),
        content_type="application/json",
    )
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["decision"] == "allow"
    assert data["score"] == 0


def test_api_test_malicious(client):
    cmd = "echo bad | crontab -"
    rv = client.post(
        "/api/test",
        data=json.dumps({"command": cmd}),
        content_type="application/json",
    )
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["decision"] == "block"
    assert data["score"] >= 10


def test_api_rules(client):
    rv = client.get("/api/rules?page=1&per_page=5")
    assert rv.status_code == 200
    data = rv.get_json()
    assert "total" in data
    assert "rules" in data
    assert len(data["rules"]) <= 5


def test_api_rules_search(client):
    rv = client.get("/api/rules?q=curl&per_page=10")
    assert rv.status_code == 200
    data = rv.get_json()
    assert isinstance(data["rules"], list)


def test_api_pause_resume(client):
    rv = client.post("/api/pause")
    assert rv.status_code == 200
    assert rv.get_json()["paused"] is True

    rv = client.post("/api/resume")
    assert rv.status_code == 200
    assert rv.get_json()["paused"] is False
