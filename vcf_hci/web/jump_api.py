"""Vault jump-host HTTP endpoints. Localhost only, same gates as the credential vault."""

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from vcf_hci.logging_utils import is_cloud_metadata_target
from vcf_hci.vault.jump_hosts import public_jump_host
from vcf_hci.vault.store import VaultError

logger = logging.getLogger("vcf_assess")

_JUMP_TEST_CACHE: Dict[str, Dict[str, Any]] = {}

__all__ = ["JumpApiMixin", "diagnose_jump_error"]

if TYPE_CHECKING:
    from http.server import SimpleHTTPRequestHandler

    class _ApiMixinBase(SimpleHTTPRequestHandler):
        def _send_json(self, obj: Any, status: int = 200, extra_headers: Optional[dict] = None) -> None: ...
        def _read_json_body(self) -> dict: ...
        def _vault_guard(self) -> bool: ...
        def _vault_or_423(self): ...
else:
    _ApiMixinBase = object


def diagnose_jump_error(error_str: str, host: str = "") -> Dict[str, str]:
    """Classify jump host connection and preflight errors with actionable advice."""
    err_lower = (error_str or "").lower()
    troubleshooting = "Check jump host reachability and credentials."
    category = "general"

    if "timed out" in err_lower or "timeout" in err_lower:
        category = "timeout"
        host_str = f" to {host}" if host else ""
        troubleshooting = f"Connection timed out{host_str}. Verify host IP/hostname, firewall rules, and ensure VPN is active."
    elif "permission denied" in err_lower or "authentication failed" in err_lower or "auth fail" in err_lower:
        category = "auth"
        troubleshooting = "SSH authentication failed. Verify username and password, or verify that the SSH key is authorized."
    elif "connection refused" in err_lower:
        category = "refused"
        host_str = f" by {host}" if host else ""
        troubleshooting = f"Connection refused{host_str} on port 22. Verify that the SSH service (sshd) is running."
    elif "no route to host" in err_lower or "network is unreachable" in err_lower:
        category = "network"
        host_str = f" to {host}" if host else ""
        troubleshooting = f"No network route{host_str}. Verify local network interface, default gateway, or VPN connection."
    elif "could not resolve hostname" in err_lower or "name or service not known" in err_lower or "nodename nor servname" in err_lower:
        category = "dns"
        troubleshooting = f"Could not resolve hostname '{host}'. Verify DNS settings or use an IP address directly."
    elif "host key verification failed" in err_lower:
        category = "host_key"
        troubleshooting = "Remote host key verification failed. The server's host key has changed or does not match the pinned fingerprint. Verify the server identity and update the pinned host key in vault settings."
    elif "host key" in err_lower and ("not pinned" in err_lower or "unpinned" in err_lower):
        category = "host_key_unpinned"
        troubleshooting = "Remote jump host SSH key is not pinned. Pin the host key in the vault or confirmation dialog before connecting."
    elif "older than 3.9" in err_lower or ("not found" in err_lower and "python" in err_lower):
        category = "python_version"
        troubleshooting = "Remote jump host requires Python 3.9 or higher to run the readiness collector."
    elif "less than 500 mib free" in err_lower:
        category = "disk_space"
        troubleshooting = "Remote jump host has less than 500 MiB free disk space on /tmp. Free disk space before scanning."
    elif "not writable" in err_lower and "tmp" in err_lower:
        category = "permissions"
        troubleshooting = "The remote /tmp directory is not writable by the specified user account."

    return {
        "category": category,
        "troubleshooting": troubleshooting,
    }


class JumpApiMixin(_ApiMixinBase):
    """GET/POST /api/vault/jump-hosts. Registered from server.py."""

    def _api_jump_hosts_list(self) -> None:
        if not self._vault_guard():
            return
        vault = self._vault_or_423()
        if vault is None:
            return
        hosts = vault.list_jump_hosts()
        for row in hosts:
            jid = row.get("id")
            if jid and jid in _JUMP_TEST_CACHE:
                row["last_test"] = _JUMP_TEST_CACHE[jid]
        self._send_json({"ok": True, "jump_hosts": hosts})

    def _api_jump_hosts_save(self) -> None:
        if not self._vault_guard():
            return
        vault = self._vault_or_423()
        if vault is None:
            return
        body = self._read_json_body()
        # Merge with existing record on partial update; blank password/key keeps stored secret.
        existing = vault.get_jump_host(str(body.get("id") or "")) if body.get("id") else None
        if existing:
            merged = dict(existing)
            for k, v in body.items():
                if k in ("password", "private_key") and not v:
                    continue
                if k == "host_key" and not v and ("host" not in body or body["host"] == existing.get("host")):
                    continue
                merged[k] = v
            if "host_key" in body and "host_key_fingerprint" not in body:
                merged.pop("host_key_fingerprint", None)
                merged.pop("host_key_type", None)
            body = merged
        else:
            if not body.get("password") and body.get("auth_type") == "password":
                body["password"] = ""
            if not body.get("private_key") and body.get("auth_type", "key") == "key":
                body["private_key"] = ""
        host = str(body.get("host") or "").strip()
        if host and is_cloud_metadata_target(host):
            self._send_json({"ok": False, "error": f"Target '{host}' is a prohibited cloud metadata endpoint."}, 400)
            return
        try:
            jump_id = vault.set_jump_host(body)
            vault.save()
            _JUMP_TEST_CACHE.pop(jump_id, None)
        except VaultError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
            return
        saved = vault.get_jump_host(jump_id) or {}
        self._send_json({"ok": True, "jump_host": public_jump_host(saved)})

    def _api_jump_hosts_remove(self) -> None:
        if not self._vault_guard():
            return
        vault = self._vault_or_423()
        if vault is None:
            return
        body = self._read_json_body()
        jump_id = str(body.get("id") or "")
        if not vault.remove_jump_host(jump_id):
            self._send_json({"ok": False, "error": "jump host not found"}, 404)
            return
        vault.save()
        _JUMP_TEST_CACHE.pop(jump_id, None)
        self._send_json({"ok": True, "removed": jump_id})

    def _api_jump_hosts_subnets(self) -> None:
        if not self._vault_guard():
            return
        vault = self._vault_or_423()
        if vault is None:
            return
        body = self._read_json_body()
        jump_id = str(body.get("id") or "").strip()
        if not jump_id:
            self._send_json({"ok": False, "error": "Jump host id is required"}, 400)
            return
        subnets = body.get("subnets", [])
        action = str(body.get("action") or "replace").strip().lower()
        if action not in ("replace", "add", "remove"):
            self._send_json({"ok": False, "error": "action must be 'replace', 'add', or 'remove'"}, 400)
            return
        try:
            vault.update_jump_host_subnets(jump_id, subnets, mode=action)
            vault.save()
        except VaultError as exc:
            status = 404 if "not found" in str(exc).lower() else 400
            self._send_json({"ok": False, "error": str(exc)}, status)
            return
        saved = vault.get_jump_host(jump_id) or {}
        self._send_json({"ok": True, "jump_host": public_jump_host(saved)})

    def _api_jump_hosts_test(self) -> None:
        if not self._vault_guard():
            return
        vault = self._vault_or_423()
        if vault is None:
            return
        body = self._read_json_body()
        jump_id = str(body.get("id") or "").strip()

        # Support both saved jump host testing and transient form testing
        profile = None
        if jump_id and vault.get_jump_host(jump_id):
            profile = dict(vault.get_jump_host(jump_id) or {})
            if body.get("password"):
                profile["password"] = body["password"]
            if body.get("private_key"):
                profile["private_key"] = body["private_key"]
            if body.get("auth_type"):
                profile["auth_type"] = body["auth_type"]
            if body.get("username"):
                profile["username"] = body["username"]
            if body.get("host"):
                profile["host"] = body["host"]
            if body.get("host_key"):
                profile["host_key"] = body["host_key"]
            if body.get("port"):
                try:
                    profile["port"] = int(body["port"])
                except (TypeError, ValueError):
                    pass
        elif body.get("host") and (body.get("username") or body.get("user")):
            from vcf_hci.vault.jump_hosts import normalize_jump_host
            test_payload = dict(body)
            if not test_payload.get("id"):
                test_payload["id"] = "test-jump-host"
            try:
                profile = normalize_jump_host(test_payload)
            except VaultError as exc:
                self._send_json({"ok": False, "error": str(exc), "troubleshooting": "Check form inputs."}, 400)
                return
            if body.get("host_key"):
                profile["host_key"] = body["host_key"]
        elif jump_id:
            self._send_json({
                "ok": False,
                "error": f"Jump host '{jump_id}' not found in vault",
                "troubleshooting": "The requested jump host was not found in the vault. Please verify the ID or provide host details.",
            }, 404)
            return
        else:
            self._send_json({
                "ok": False,
                "error": "Host and username (or saved jump host ID) required",
                "troubleshooting": "Please specify the jump host address and username to test.",
            }, 400)
            return

        from vcf_hci.remote.executor import HostKeyRequiredError, RemoteExecError, preflight_jump
        target_host = str(profile.get("host") or jump_id)
        if target_host and is_cloud_metadata_target(target_host):
            self._send_json({
                "ok": False,
                "error": f"Target '{target_host}' is a prohibited cloud metadata endpoint.",
                "category": "security",
                "troubleshooting": "Cloud metadata endpoints cannot be configured as jump hosts.",
            }, 400)
            return
        target_user = str(profile.get("username") or "")
        target_id = str(jump_id or profile.get("id") or "").strip()
        if not profile.get("host_key"):
            target_port = int(profile.get("port") or 22)
            self._send_json({
                "ok": False,
                "category": "host_key_unpinned",
                "error": f"Jump host '{target_host}' SSH key is not pinned.",
                "troubleshooting": "Pin the jump host SSH host key before testing connection.",
                "unpinned": [{
                    "id": target_id or "test-jump-host",
                    "host": target_host,
                    "port": target_port,
                }],
            }, 409)
            return
        try:
            report = preflight_jump(profile, timeout=15)
        except HostKeyRequiredError as exc:
            target_port = int(profile.get("port") or 22)
            self._send_json({
                "ok": False,
                "category": "host_key_unpinned",
                "error": str(exc),
                "troubleshooting": "Pin the jump host SSH host key before connecting.",
                "unpinned": [{
                    "id": target_id or "test-jump-host",
                    "host": target_host,
                    "port": target_port,
                }],
            }, 409)
            return
        except RemoteExecError as exc:
            err_str = str(exc)
            diag = diagnose_jump_error(err_str, target_host)
            logger.info("Jump host preflight failed for %s (%s): %s", jump_id or target_host, diag["category"], err_str)
            err_res = {
                "ok": False,
                "error": err_str,
                "category": diag["category"],
                "troubleshooting": diag["troubleshooting"],
                "host": target_host,
                "id": jump_id or profile.get("id"),
            }
            if target_id and target_id != "test-jump-host":
                _JUMP_TEST_CACHE[target_id] = err_res
            self._send_json(err_res, 502)
            return
        except Exception as exc:
            err_str = str(exc)
            diag = diagnose_jump_error(err_str, target_host)
            err_res = {
                "ok": False,
                "error": err_str,
                "category": diag["category"],
                "troubleshooting": diag["troubleshooting"],
                "host": target_host,
                "id": jump_id or profile.get("id"),
            }
            if target_id and target_id != "test-jump-host":
                _JUMP_TEST_CACHE[target_id] = err_res
            self._send_json(err_res, 500)
            return

        free_bytes = int(report.get("free_bytes") or 0)
        free_gb = round(free_bytes / (1024 ** 3), 2)
        py_ver = str(report.get("python_version") or "")
        msg = f"Jump host '{target_host}' reachable as {target_user}"
        if py_ver:
            msg += f" (Python {py_ver})"
        msg += f". /tmp free: {free_gb:.2f} GiB"

        success_res = {
            "ok": True,
            "id": jump_id or profile.get("id"),
            "host": target_host,
            "username": target_user,
            "free_bytes": free_bytes,
            "free_gb": f"{free_gb:.2f} GiB",
            "python_version": py_ver,
            "message": msg,
        }
        if target_id and target_id != "test-jump-host":
            _JUMP_TEST_CACHE[target_id] = success_res
        self._send_json(success_res)

    def _api_jump_hosts_probe_key(self) -> None:
        if not self._vault_guard():
            return
        vault = self._vault_or_423()
        if vault is None:
            return
        body = self._read_json_body()
        jump_id = str(body.get("id") or "").strip()
        host = str(body.get("host") or "").strip()
        port = 22
        if not host and jump_id and vault.get_jump_host(jump_id):
            saved = vault.get_jump_host(jump_id) or {}
            host = str(saved.get("host") or "").strip()
            port = int(saved.get("port") or 22)
        else:
            try:
                port = int(body.get("port") or 22)
            except (ValueError, TypeError):
                port = 22

        if not host:
            self._send_json({
                "ok": False,
                "error": "host required",
                "troubleshooting": "Specify jump host IP or hostname.",
            }, 400)
            return
        if is_cloud_metadata_target(host):
            self._send_json({
                "ok": False,
                "error": f"Target '{host}' is a prohibited cloud metadata endpoint.",
                "category": "security",
                "troubleshooting": "Cloud metadata endpoints cannot be probed.",
            }, 400)
            return

        timeout = float(body.get("timeout") or 5.0)
        from vcf_hci.remote.executor import probe_jump_host_key
        res = probe_jump_host_key(host, port=port, timeout=timeout)
        if jump_id and vault.get_jump_host(jump_id):
            saved = vault.get_jump_host(jump_id) or {}
            pinned_fp = saved.get("host_key_fingerprint") or ""
            if pinned_fp:
                res["is_pinned"] = True
                res["pinned_fingerprint"] = pinned_fp
                res["fingerprint_matches"] = bool(res.get("fingerprint") == pinned_fp)
        status = 200 if res.get("ok") else 502
        self._send_json(res, status)

