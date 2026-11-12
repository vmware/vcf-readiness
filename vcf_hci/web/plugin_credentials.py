"""Server-side resolution of explicitly selected plugin service credentials."""

from typing import Any
from urllib.parse import urlsplit

from vcf_hci.vault.store import VaultError
from vcf_hci.web import vault_session

_NO_STORE = {"Cache-Control": "no-store"}


def resolve_plugin_credentials(handler: Any, data: dict, kind: str, plugin: str = "") -> bool:
    if "vault_credential_id" not in data:
        return True
    if handler._is_remote_server() or not handler._require_same_origin():
        handler._send_json(
            {"error": "Saved credentials are available only in the local Web UI."}, 403, extra_headers=_NO_STORE
        )
        return False
    entry_id = data.get("vault_credential_id")
    if not isinstance(entry_id, str) or not entry_id:
        handler._send_json({"error": "Select a saved instance."}, 400, extra_headers=_NO_STORE)
        return False
    try:
        record = vault_session.service_action("resolve", {"id": entry_id, "kind": kind})
    except VaultError:
        handler._send_json({"error": "Vault is locked. Unlock it in Credential Vault."}, 423, extra_headers=_NO_STORE)
        return False
    except ValueError:
        handler._send_json(
            {"error": "Saved credentials are unavailable for this source. Select an instance again."},
            400,
            extra_headers=_NO_STORE,
        )
        return False
    if plugin == "vdt":
        url = urlsplit(record["endpoint"])
        target = data.get("target")
        if not isinstance(target, dict):
            handler._send_json({"error": "Supply separate appliance SSH settings."}, 400, extra_headers=_NO_STORE)
            return False
        target["host"] = url.hostname
        data.update(sso_username=record["username"], sso_password=record["password"], https_port=url.port or 443)
    else:
        endpoint_key = "endpoint"
        data.update({endpoint_key: record["endpoint"], "username": record["username"], "password": record["password"]})
        if kind == "operations":
            data["auth_source"] = record["auth_source"]
    return True


def service_credentials_api(handler: Any, action: str) -> None:
    if not handler._vault_guard():
        return
    body = {} if action == "list" else handler._read_json_body()
    if not isinstance(body, dict):
        handler._send_json({"error": "Expected a JSON object."}, 400, extra_headers=_NO_STORE)
        return
    try:
        result = vault_session.service_action(action, body)
    except VaultError:
        handler._send_json({"error": "Vault is locked. Unlock it in Credential Vault."}, 423, extra_headers=_NO_STORE)
        return
    except (ValueError, TypeError):
        handler._send_json({"error": "Enter valid instance details and credentials."}, 400, extra_headers=_NO_STORE)
        return
    except OSError:
        handler._send_json({"error": "Could not save the credential vault."}, 500, extra_headers=_NO_STORE)
        return
    finally:
        body.clear()
    handler._send_json({"ok": True, "entries": result} if action == "list" else {"ok": True}, extra_headers=_NO_STORE)
