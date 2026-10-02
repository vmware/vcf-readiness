"""
VCF Readiness Tool — Pluggable Credential Providers (vcf_hci.vault.providers)

Provides an extensible, standard-library-only interface for resolving BMC
credentials from external secret management systems (HashiCorp Vault, VMware
Cloud Foundation SDDC Manager) alongside the built-in encrypted local vault.

Supported Providers:
  • BaseCredentialProvider     — Abstract base class for all credential providers
  • HashiCorpVaultProvider     — HashiCorp Vault (AppRole / Token auth, KV v1 & v2)
  • SddcManagerSecretProvider  — VMware Cloud Foundation SDDC Manager REST API
  • ChainedCredentialProvider  — Cascading fallback across multiple providers
  • LocalVaultProvider         — Adapter wrapping the local CredentialVault

All HTTP operations use stdlib urllib.request. TLS certificate checks are
on by default, because these calls send Vault tokens and SDDC Manager
passwords. Pass verify_ssl=False only for a store whose network you trust.
No external third-party dependencies (requests, hvac) are permitted.
"""

import json
import logging
import os
import ssl
import time
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError

logger = logging.getLogger("vcf_assess")


class BaseCredentialProvider(ABC):
    """Abstract base class for credential resolution providers."""

    @abstractmethod
    def resolve(self, target: str) -> Optional[Tuple[str, str]]:
        """Resolve credentials for a specific host target.

        Returns (username, password) tuple or None if unmapped.
        """
        raise NotImplementedError

    def resolve_for_targets(self, targets: List[str]) -> Dict[str, Tuple[str, str]]:
        """Resolve credentials for a list of targets.

        Returns dict mapping target -> (username, password).
        """
        out: Dict[str, Tuple[str, str]] = {}
        for t in targets or []:
            cred = self.resolve(t)
            if cred is not None:
                out[str(t)] = cred
        return out

    def invalidate(self, target: Optional[str] = None) -> None:
        """Invalidate cached credentials (e.g. after password rotation or HTTP 401).

        target: specific host target to invalidate, or None to clear all.
        """
        return None


class LocalVaultProvider(BaseCredentialProvider):
    """Adapter wrapping the built-in local CredentialVault."""

    def __init__(self, vault: Any):
        self._vault = vault

    def resolve(self, target: str) -> Optional[Tuple[str, str]]:
        return self._vault.resolve(target)

    def resolve_for_targets(self, targets: List[str]) -> Dict[str, Tuple[str, str]]:
        return self._vault.resolve_for_targets(targets)

    def invalidate(self, target: Optional[str] = None) -> None:
        # Local vault is encrypted on-disk and in-memory entries don't expire mid-scan
        pass


def _resolve_ca_bundle(ca_bundle: Optional[str], env_var: str) -> Optional[str]:
    """Prefer an explicit PEM path, then the named environment variable."""
    raw = ca_bundle if ca_bundle else os.environ.get(env_var)
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _secret_provider_ssl_context(
    verify_ssl: bool,
    ca_bundle: Optional[str],
    provider_name: str,
) -> ssl.SSLContext:
    """TLS context for a secret store.

    Verification stays on unless the caller passes verify_ssl=False. These
    requests carry Vault tokens or SDDC Manager passwords, so the BMC default
    (accept any certificate) does not apply here. A ca_bundle replaces the
    system trust store for this client.
    """
    if not verify_ssl:
        logger.warning(
            "%s TLS certificate verification is disabled. "
            "Tokens and passwords can be intercepted on this connection. "
            "Pass verify_ssl=True, or ca_bundle for a private CA.",
            provider_name,
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            raise ValueError(f"{provider_name} CA bundle is not a file: {ca_bundle}")
        try:
            ctx = ssl.create_default_context(cafile=ca_bundle)
        except (OSError, ssl.SSLError) as exc:
            raise ValueError(
                f"{provider_name} could not load CA bundle {ca_bundle}: {exc}"
            ) from exc
    else:
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class HashiCorpVaultProvider(BaseCredentialProvider):
    """Stdlib-only HashiCorp Vault provider supporting AppRole and Token auth.

    Queries KV v1 and KV v2 secret engines. TLS certificate checks are on
    unless verify_ssl is passed as False.
    """

    def __init__(
        self,
        vault_addr: str,
        token: Optional[str] = None,
        role_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        mount_point: str = "secret",
        kv_version: int = 2,
        secret_prefix: str = "bmcs",
        namespace: Optional[str] = None,
        cache_ttl_sec: float = 300.0,
        verify_ssl: bool = True,
        ca_bundle: Optional[str] = None,
    ):
        self.vault_addr = vault_addr.rstrip("/")
        self.token = token or os.environ.get("VAULT_TOKEN", "")
        self.role_id = role_id or os.environ.get("VAULT_ROLE_ID", "")
        self.secret_id = secret_id or os.environ.get("VAULT_SECRET_ID", "")
        self.mount_point = mount_point.strip("/")
        self.kv_version = kv_version
        self.secret_prefix = secret_prefix.strip("/")
        self.namespace = namespace or os.environ.get("VAULT_NAMESPACE")
        self.cache_ttl_sec = cache_ttl_sec
        self.verify_ssl = verify_ssl
        self.ca_bundle = _resolve_ca_bundle(ca_bundle, "VAULT_CACERT")

        # In-memory resolution cache: target -> (creds_tuple, expire_ts)
        self._cache: Dict[str, Tuple[Tuple[str, str], float]] = {}
        self._token_expiry: float = 0.0

        self._ssl_ctx = _secret_provider_ssl_context(
            verify_ssl, self.ca_bundle, "HashiCorp Vault"
        )

    def _ensure_authenticated(self) -> bool:
        """Authenticate via AppRole if token is absent or expired."""
        now = time.time()
        if self.token and (not self._token_expiry or now < self._token_expiry):
            return True

        if not self.role_id or not self.secret_id:
            logger.debug("HashiCorp Vault: No token and AppRole credentials not configured")
            return bool(self.token)

        login_url = f"{self.vault_addr}/v1/auth/approle/login"
        payload = json.dumps({"role_id": self.role_id, "secret_id": self.secret_id}).encode("utf-8")
        req = urllib.request.Request(
            login_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.namespace:
            req.add_header("X-Vault-Namespace", self.namespace)

        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ssl_ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                auth_data = data.get("auth") or {}
                client_token = auth_data.get("client_token")
                lease_duration = auth_data.get("lease_duration", 3600)
                if client_token:
                    self.token = client_token
                    self._token_expiry = now + max(60, lease_duration - 60)
                    logger.debug("HashiCorp Vault: AppRole login successful (lease: %ds)", lease_duration)
                    return True
        except (HTTPError, URLError, json.JSONDecodeError, Exception) as exc:
            logger.warning("HashiCorp Vault AppRole authentication failed: %s", exc)

        return False

    def _fetch_secret_data(self, path: str) -> Optional[Dict[str, Any]]:
        """Fetch secret dictionary from KV engine."""
        if not self._ensure_authenticated():
            return None

        if self.kv_version == 2:
            url = f"{self.vault_addr}/v1/{self.mount_point}/data/{path.lstrip('/')}"
        else:
            url = f"{self.vault_addr}/v1/{self.mount_point}/{path.lstrip('/')}"

        req = urllib.request.Request(url, headers={"X-Vault-Token": self.token}, method="GET")
        if self.namespace:
            req.add_header("X-Vault-Namespace", self.namespace)

        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ssl_ctx) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                if self.kv_version == 2:
                    return (body.get("data") or {}).get("data") or {}
                return body.get("data") or {}
        except HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 401:
                logger.warning("HashiCorp Vault token expired or unauthorized (HTTP 401)")
                self.token = ""
            logger.debug("HashiCorp Vault GET %s failed: HTTP %s", url, e.code)
        except Exception as exc:
            logger.debug("HashiCorp Vault request error for %s: %s", url, exc)

        return None

    def resolve(self, target: str) -> Optional[Tuple[str, str]]:
        t_clean = str(target or "").strip().lower()
        if not t_clean:
            return None

        now = time.time()
        if t_clean in self._cache:
            creds, exp = self._cache[t_clean]
            if now < exp:
                return creds
            del self._cache[t_clean]

        # 1. Try host-specific path: e.g. bmcs/192.0.2.10
        paths_to_try = []
        if self.secret_prefix:
            paths_to_try.append(f"{self.secret_prefix}/{t_clean}")
            paths_to_try.append(f"{self.secret_prefix}/default")
        else:
            paths_to_try.append(t_clean)
            paths_to_try.append("default")

        for p in paths_to_try:
            data = self._fetch_secret_data(p)
            if data and isinstance(data, dict):
                # Search common key names
                u = data.get("username") or data.get("user") or data.get("login") or ""
                pwd = data.get("password") or data.get("pass") or ""
                if u and pwd:
                    creds_tuple = (str(u), str(pwd))
                    self._cache[t_clean] = (creds_tuple, now + self.cache_ttl_sec)
                    return creds_tuple

        return None

    def invalidate(self, target: Optional[str] = None) -> None:
        """Evict cached credentials on password rotation or 401."""
        if target:
            t_clean = str(target).strip().lower()
            self._cache.pop(t_clean, None)
            logger.debug("HashiCorp Vault cache invalidated for target: %s", t_clean)
        else:
            self._cache.clear()
            self.token = ""
            self._token_expiry = 0.0
            logger.debug("HashiCorp Vault cache and token invalidated")


class SddcManagerSecretProvider(BaseCredentialProvider):
    """Stdlib-only VMware Cloud Foundation SDDC Manager Secret Provider.

    Queries SDDC Manager REST API (/v1/system/credentials) for physical host credentials.
    TLS certificate checks are on unless verify_ssl is passed as False.
    """

    def __init__(
        self,
        sddc_manager_host: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        cache_ttl_sec: float = 300.0,
        verify_ssl: bool = True,
        ca_bundle: Optional[str] = None,
    ):
        self.sddc_host = sddc_manager_host.rstrip("/")
        if "://" not in self.sddc_host:
            self.sddc_host = f"https://{self.sddc_host}"
        self.api_token = api_token or os.environ.get("VCF_SDDC_TOKEN", "")
        self.username = username or os.environ.get("VCF_SDDC_USER", "")
        self.password = password or os.environ.get("VCF_SDDC_PASSWORD", "")
        self.cache_ttl_sec = cache_ttl_sec
        self.verify_ssl = verify_ssl
        self.ca_bundle = _resolve_ca_bundle(ca_bundle, "VCF_SDDC_CACERT")

        self._cache: Dict[str, Tuple[Tuple[str, str], float]] = {}
        self._token_expiry: float = 0.0

        self._ssl_ctx = _secret_provider_ssl_context(
            verify_ssl, self.ca_bundle, "SDDC Manager"
        )

    def _ensure_token(self) -> bool:
        now = time.time()
        if self.api_token and (not self._token_expiry or now < self._token_expiry):
            return True

        if not self.username or not self.password:
            return bool(self.api_token)

        login_url = f"{self.sddc_host}/v1/tokens"
        payload = json.dumps({"username": self.username, "password": self.password}).encode("utf-8")
        req = urllib.request.Request(
            login_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ssl_ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                tok = data.get("accessToken") or data.get("token")
                if tok:
                    self.api_token = tok
                    self._token_expiry = now + 1800
                    return True
        except Exception as exc:
            logger.warning("VCF SDDC Manager token retrieval failed: %s", exc)

        return False

    def resolve(self, target: str) -> Optional[Tuple[str, str]]:
        t_clean = str(target or "").strip().lower()
        if not t_clean:
            return None

        now = time.time()
        if t_clean in self._cache:
            creds, exp = self._cache[t_clean]
            if now < exp:
                return creds
            del self._cache[t_clean]

        if not self._ensure_token():
            return None

        # Query SDDC Manager system credentials or host inventory
        url = f"{self.sddc_host}/v1/system/credentials"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self.api_token}", "Accept": "application/json"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=15, context=self._ssl_ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, list):
                    elements = data
                elif isinstance(data, dict):
                    elements = data.get("elements") or []
                else:
                    elements = []
                for item in elements:
                    if not isinstance(item, dict):
                        continue
                    # Match host IP or FQDN in credentials list
                    host_val = str(item.get("resourceName") or item.get("target") or "").lower()
                    cred_type = str(item.get("credentialType") or item.get("accountType") or "").upper()
                    if (t_clean in host_val or host_val in t_clean) and ("BMC" in cred_type or "IPMI" in cred_type or "HOST" in cred_type):
                        u = str(item.get("username") or "")
                        p = str(item.get("password") or "")
                        if u and p:
                            res = (u, p)
                            self._cache[t_clean] = (res, now + self.cache_ttl_sec)
                            return res
        except Exception as exc:
            logger.debug("VCF SDDC Manager credential query error: %s", exc)

        return None

    def invalidate(self, target: Optional[str] = None) -> None:
        if target:
            self._cache.pop(str(target).strip().lower(), None)
        else:
            self._cache.clear()
            self.api_token = ""
            self._token_expiry = 0.0


class ChainedCredentialProvider(BaseCredentialProvider):
    """Cascading credential provider querying an ordered sequence of providers.

    Precedence: First provider that successfully returns credentials wins.
    """

    def __init__(self, providers: List[BaseCredentialProvider]):
        self.providers = list(providers)

    def resolve(self, target: str) -> Optional[Tuple[str, str]]:
        for prov in self.providers:
            try:
                cred = prov.resolve(target)
                if cred is not None:
                    return cred
            except Exception as exc:
                logger.debug("Provider %s error on target %s: %s", prov.__class__.__name__, target, exc)
        return None

    def resolve_for_targets(self, targets: List[str]) -> Dict[str, Tuple[str, str]]:
        out: Dict[str, Tuple[str, str]] = {}
        unresolved = list(targets or [])
        for prov in self.providers:
            if not unresolved:
                break
            resolved = prov.resolve_for_targets(unresolved)
            for t, cred in resolved.items():
                out[t] = cred
            unresolved = [t for t in unresolved if t not in out]
        return out

    def invalidate(self, target: Optional[str] = None) -> None:
        """Propagate invalidation to all providers in the chain."""
        for prov in self.providers:
            try:
                prov.invalidate(target)
            except Exception as exc:
                logger.debug("Error invalidating provider %s: %s", prov.__class__.__name__, exc)


__all__ = [
    "BaseCredentialProvider",
    "LocalVaultProvider",
    "HashiCorpVaultProvider",
    "SddcManagerSecretProvider",
    "ChainedCredentialProvider",
]
