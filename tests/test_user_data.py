"""Tests for authenticated user-data persistence and isolation."""
import pytest

from app.user_data import UserDataStore, UserDataError


@pytest.fixture
def store(tmp_path):
    return UserDataStore(tmp_path / "user-data.sqlite3")


def test_research_record_crud_and_audit(store):
    row = store.create_record("alice", {
        "title": "BTC puzzle", "content": "offline notes",
        "tags": ["btc", "research"], "status": "active",
    })
    assert row["title"] == "BTC puzzle"
    assert store.list_records("alice")[0]["id"] == row["id"]
    updated = store.update_record("alice", row["id"], {"status": "completed"})
    assert updated["status"] == "completed"
    assert store.delete_record("alice", row["id"]) is True
    assert store.list_records("alice") == []
    assert [e["action"] for e in store.audit_log("alice")] == [
        "delete", "update", "create"
    ]


def test_user_cannot_read_or_mutate_another_users_record(store):
    row = store.create_record("alice", {"title": "private"})
    assert store.list_records("bob") == []
    assert store.update_record("bob", row["id"], {"title": "stolen"}) is None
    assert store.delete_record("bob", row["id"]) is False
    assert store.list_records("alice")[0]["title"] == "private"
    assert store.audit_log("bob") == []


def test_data_survives_new_store_instance(tmp_path):
    path = tmp_path / "persist.sqlite3"
    first = UserDataStore(path)
    first.create_record("u1", {"title": "persist me"})
    second = UserDataStore(path)
    assert second.list_records("u1")[0]["title"] == "persist me"


@pytest.mark.parametrize("payload", [
    {}, {"title": ""}, {"title": "x" * 161},
    {"title": "ok", "content": "x" * 20001},
    {"title": "ok", "tags": ["x"] * 21},
    {"title": "ok", "status": "arbitrary"},
])
def test_invalid_research_records_are_rejected(store, payload):
    with pytest.raises(UserDataError):
        store.create_record("u1", payload)


def test_settings_allowlist_and_per_user_isolation(store):
    result = store.update_settings("alice", {
        "locale": "lv", "theme": "dark", "notifications": False,
    })
    assert result["locale"] == "lv"
    assert result["theme"] == "dark"
    assert result["notifications"] is False
    assert store.get_settings("bob")["locale"] == "en"
    with pytest.raises(UserDataError):
        store.update_settings("alice", {"session_secret": "exfiltrate"})
    with pytest.raises(UserDataError):
        store.update_settings("alice", {"theme": "neon"})


def test_settings_and_audit_persist(store):
    store.update_settings("alice", {"default_chain": "bitcoin"})
    assert store.get_settings("alice")["default_chain"] == "bitcoin"
    assert store.audit_log("alice")[0]["entity_type"] == "settings"


def test_database_permissions_are_private(store):
    assert store.path.stat().st_mode & 0o777 == 0o600
