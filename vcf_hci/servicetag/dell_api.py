"""
VCF Readiness Tool — Dell TechDirect API client.

Provides OAuth2-authenticated access to the Dell TechDirect REST API for
warranty lookups and component-level asset inventory by service tag.

Registration: https://techdirect.dell.com/portal/AboutAPIs.aspx
  1. Log in to TechDirect and request API access.
  2. You will receive a client_id and client_secret.
  3. Configure these credentials in the VCF Readiness GUI under
     "Dell Service Tag Lookup" → "Save to Keychain".

API limits:
  - Up to 100 service tags per request (batched automatically).
  - OAuth2 tokens expire after 3600 seconds and are cached + auto-refreshed.
  - Rate limit: ~300 requests/hour per credential pair.

No external dependencies — stdlib urllib.request only.
"""
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

from vcf_hci.constants import (
    DELL_TECHDIRECT_COMPONENTS_URL,
    DELL_TECHDIRECT_HEADER_URL,
    DELL_TECHDIRECT_OAUTH_URL,
    DELL_TECHDIRECT_WARRANTY_URL,
)

logger = logging.getLogger("vcf_assess")

_BATCH_SIZE = 100   # Dell API maximum per request

# Module-level thread-safe token cache shared across client instances
# Key: (client_id, client_secret) -> (access_token, monotonic_expiry_ts)
_SHARED_TOKEN_CACHE: Dict[Tuple[str, str], Tuple[str, float]] = {}
_SHARED_TOKEN_LOCK = threading.Lock()


class DellTechDirectClient:
    """
    Lightweight OAuth2 client for the Dell TechDirect asset API.

    Thread-safe for concurrent reads once constructed with valid credentials.
    Token refresh is thread-safe and shared across instances to prevent duplicate
    authentication requests during concurrent multi-host sweeps.
    """

    def __init__(self, client_id: str, client_secret: str) -> None:
        if not client_id or not client_secret:
            raise ValueError("client_id and client_secret are required")
        self._client_id     = client_id.strip()
        self._client_secret = client_secret.strip()
        self._token: Optional[str] = None
        self._token_expires: float = 0.0    # monotonic timestamp

    @classmethod
    def clear_token_cache(cls) -> None:
        """Clear the shared OAuth2 token cache (primarily for unit tests and session reset)."""
        with _SHARED_TOKEN_LOCK:
            _SHARED_TOKEN_CACHE.clear()

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        """Return a valid Bearer token, refreshing if within 60 s of expiry with thread-safe sharing."""
        cache_key = (self._client_id, self._client_secret)
        now = time.monotonic()

        # Fast path: check instance cache
        if self._token and now < self._token_expires - 60:
            return self._token

        # Synchronized path: check/refresh shared cache
        with _SHARED_TOKEN_LOCK:
            now = time.monotonic()
            if cache_key in _SHARED_TOKEN_CACHE:
                cached_token, cached_exp = _SHARED_TOKEN_CACHE[cache_key]
                if now < cached_exp - 60:
                    self._token = cached_token
                    self._token_expires = cached_exp
                    return self._token

            body = urllib.parse.urlencode({
                "grant_type":    "client_credentials",
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
            }).encode()
            req = urllib.request.Request(
                DELL_TECHDIRECT_OAUTH_URL,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            except urllib.error.HTTPError as exc:
                raise RuntimeError(
                    f"Dell TechDirect auth failed ({exc.code}): "
                    "check your client_id and client_secret at "
                    "https://techdirect.dell.com"
                ) from exc
            except Exception as exc:
                raise RuntimeError(
                    f"Dell TechDirect auth error: {exc}"
                ) from exc

            token = payload.get("access_token")
            if not token:
                raise RuntimeError(
                    "Dell TechDirect returned no access_token — "
                    "verify your credentials."
                )
            expires_in = int(payload.get("expires_in", 3600))
            self._token = token
            self._token_expires = time.monotonic() + expires_in
            _SHARED_TOKEN_CACHE[cache_key] = (self._token, self._token_expires)
            logger.debug("Dell TechDirect: new token acquired (expires in %ds)", expires_in)
            return self._token

    # ------------------------------------------------------------------
    # Internal HTTP helper
    # ------------------------------------------------------------------

    def _get(self, url: str, params: dict) -> list:
        """GET request with Bearer auth; always returns a list (API returns JSON array)."""
        qs = urllib.parse.urlencode(params)
        full_url = f"{url}?{qs}"
        token = self._get_token()
        req = urllib.request.Request(
            full_url,
            headers={
                "Accept":        "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            raise RuntimeError(
                f"Dell TechDirect API error ({exc.code}) querying {url}: {body[:200]}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"Dell TechDirect request failed: {exc}") from exc

        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Dell TechDirect: non-JSON response from %s", url)
            return []

        return result if isinstance(result, list) else [result]

    # ------------------------------------------------------------------
    # Batched helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _batch(tags: List[str]) -> List[List[str]]:
        """Split tag list into batches of at most _BATCH_SIZE."""
        tags = [t.strip().upper() for t in tags if t.strip()]
        return [tags[i:i + _BATCH_SIZE] for i in range(0, len(tags), _BATCH_SIZE)]

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def get_warranty(self, tags: List[str]) -> List[dict]:
        """
        Return warranty/entitlement data for up to 100 service tags per call.

        Each element of the returned list is a dict with keys:
          serviceTag, systemDescription, shipDate, productId,
          entitlements[]{itemNumber, startDate, endDate,
                          serviceLevelCode, serviceLevelDescription,
                          serviceLevelGroup, entitlementType}
        """
        results: List[dict] = []
        for batch in self._batch(tags):
            params = {"servicetags": ",".join(batch), "Method": "GET"}
            results.extend(self._get(DELL_TECHDIRECT_WARRANTY_URL, params))
        return results

    def get_components(self, tags: List[str]) -> List[dict]:
        """
        Return component-level inventory for up to 100 service tags.

        Each element is a dict keyed by service tag containing a list of
        component records with keys: itemNumber, description, quantity, unitPrice.
        Component descriptions use Dell order-code format, e.g.:
          "780-BCDI: No RAID"
          "405-AAVW: PERC H750 Adapter, RAID"
          "540-BCOF: Mellanox ConnectX-5 Dual Port 10/25GbE SFP28"
        """
        results: List[dict] = []
        for batch in self._batch(tags):
            params = {"servicetags": ",".join(batch), "Method": "GET"}
            results.extend(self._get(DELL_TECHDIRECT_COMPONENTS_URL, params))
        return results

    def get_header(self, tags: List[str]) -> List[dict]:
        """
        Return basic asset header (model, ship date, country) without entitlements.

        Faster than get_warranty() when you only need the model description.
        Keys: serviceTag, productId, systemDescription, shipDate, countryCode.
        """
        results: List[dict] = []
        for batch in self._batch(tags):
            params = {"servicetags": ",".join(batch), "Method": "GET"}
            results.extend(self._get(DELL_TECHDIRECT_HEADER_URL, params))
        return results

    def get_all(self, tags: List[str]) -> dict:
        """
        Convenience method: fetch warranty + components for each tag in one call.

        Returns a dict keyed by (uppercased) service tag:
        {
          "CTW4V43": {
            "header":     {...},     # from asset-header
            "warranty":   {...},     # from asset-entitlements
            "components": [...],     # from asset-components (list of component dicts)
          },
          ...
        }
        Missing data fields are empty dicts / lists rather than raising.
        """
        tags_clean = [t.strip().upper() for t in tags if t.strip()]
        if not tags_clean:
            return {}

        combined: dict = {t: {"header": {}, "warranty": {}, "components": []}
                          for t in tags_clean}

        try:
            for rec in self.get_warranty(tags_clean):
                tag = str(rec.get("serviceTag", "")).upper()
                if tag in combined:
                    combined[tag]["warranty"] = rec
                    # header fields are also present in the warranty response
                    combined[tag]["header"] = {
                        k: rec.get(k)
                        for k in ("serviceTag", "systemDescription", "shipDate",
                                  "productId", "brandName", "productLineDescription")
                    }
        except RuntimeError as exc:
            logger.warning("Dell TechDirect warranty fetch failed: %s", exc)

        try:
            for rec in self.get_components(tags_clean):
                tag = str(rec.get("serviceTag", "")).upper()
                if tag in combined:
                    combined[tag]["components"] = rec.get("components", [])
        except RuntimeError as exc:
            logger.warning("Dell TechDirect components fetch failed: %s", exc)

        return combined
