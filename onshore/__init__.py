"""Onshore client. Standard library plus `cryptography` for Ed25519."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import quote
import uuid
from typing import Any, Dict, Iterable, List, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_BATCH = 500


def verify_webhook(secret: str, raw_body: bytes, signature_header: str, tolerance_seconds: int = 300, now: Optional[int] = None) -> bool:
    """Checks a webhook from Onshore. Pass the body exactly as received and the
    x-rv-signature header. During a rotation it holds two signatures; either is enough."""
    parts = [p.split("=", 1) for p in (signature_header or "").split(",") if "=" in p]
    try:
        at = int(next(v for k, v in parts if k == "t"))
    except (StopIteration, ValueError):
        return False
    if abs((int(time.time()) if now is None else now) - at) > tolerance_seconds:
        return False
    want = hmac.new(secret.encode(), f"{at}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(v, want) for k, v in parts if k == "v1")


class VaultError(Exception):
    def __init__(self, status: int, code: str, message: str, policy: Optional[str] = None, request_id: Optional[str] = None):
        super().__init__(f"{code}: {message}")
        self.status, self.code, self.message, self.policy, self.request_id = status, code, message, policy, request_id


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class VaultClient:
    """Handles token refresh, batching and retries. Detokenize fails closed: when
    the vault cannot answer it raises, and it never returns a token as a value."""

    def __init__(self, base_url: str, service_account_id: str, key_id: str, private_key: str, *, max_attempts: int = 4, timeout: float = 10.0, ssl_context: Optional[ssl.SSLContext] = None):
        self.base_url = base_url.rstrip("/")
        self.service_account_id, self.key_id = service_account_id, key_id
        self._key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
        self.max_attempts, self.timeout, self._ssl = max_attempts, timeout, ssl_context
        self._token: Optional[str] = None
        self._expiry = 0.0

    def _assertion(self) -> str:
        now = int(time.time())
        head = _b64u(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": self.key_id}).encode())
        body = _b64u(json.dumps({"iss": self.service_account_id, "sub": self.service_account_id, "aud": "onshore", "jti": str(uuid.uuid4()), "iat": now, "exp": now + 120}).encode())
        return f"{head}.{body}.{_b64u(self._key.sign(f'{head}.{body}'.encode()))}"

    def _bearer(self) -> str:
        if self._token and time.time() < self._expiry - 60:
            return self._token
        r = self._raw("POST", "/v1/auth/token", {"assertion": self._assertion()}, None)
        self._token, self._expiry = r["access_token"], time.time() + r["expires_in"]
        return self._token

    def _raw(self, method: str, path: str, body: Any, token: Optional[str], headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        last: Optional[VaultError] = None
        for attempt in range(self.max_attempts):
            if attempt:
                time.sleep(min(2.0, 0.1 * 2**attempt) * (0.5 + random.random() / 2))
            req = urllib.request.Request(self.base_url + path, method=method, data=None if body is None else json.dumps(body).encode())
            req.add_header("Content-Type", "application/json")
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl) as resp:
                    return json.loads(resp.read() or b"{}")
            except urllib.error.HTTPError as e:
                try:
                    data = json.loads(e.read() or b"{}")
                except ValueError:
                    data = {}
                err = data.get("error", {})
                failure = VaultError(e.code, err.get("code", "error"), err.get("message", f"status {e.code}"), err.get("policy"), data.get("request_id"))
                if e.code == 401:
                    self._token = None
                    raise failure
                if e.code == 429 or e.code >= 500:
                    last = failure
                    continue
                raise failure
            except (urllib.error.URLError, TimeoutError) as e:
                last = VaultError(0, "network_error", type(e).__name__)
        assert last is not None
        raise last

    def _call(self, method: str, path: str, body: Any = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return self._raw(method, path, body, self._bearer(), headers)

    def tokenize(self, vault: str, items: Iterable[Dict[str, str]], continue_on_error: bool = False, dry_run: bool = False) -> List[Dict[str, Any]]:
        """Stores values and returns tokens, in 500-item batches. dry_run checks and stores nothing."""
        all_items, out = list(items), []
        for i in range(0, len(all_items), _BATCH):
            r = self._call("POST", f"/v1/vaults/{vault}/tokenize", {"items": all_items[i : i + _BATCH], "continue_on_error": continue_on_error, "dry_run": dry_run})
            out += [{**x, "index": x["index"] + i} for x in r["results"]]
        return out

    def detokenize(self, vault: str, tokens: Iterable[Union[str, Dict[str, str]]], purpose: str, continue_on_error: bool = False) -> List[Dict[str, Any]]:
        """Returns values as policy allows. Each item is a token, or {"token": ..., "redaction": "masked" | "token_only"}."""
        all_tokens, out = list(tokens), []
        for i in range(0, len(all_tokens), _BATCH):
            items = [{"token": t} if isinstance(t, str) else t for t in all_tokens[i : i + _BATCH]]
            r = self._call("POST", f"/v1/vaults/{vault}/detokenize", {"items": items, "purpose": purpose, "continue_on_error": continue_on_error})
            out += [{**x, "index": x["index"] + i} for x in r["results"]]
        return out

    def insert_record(self, vault: str, fields: Dict[str, str], subject_ref: Optional[str] = None) -> Dict[str, Any]:
        return self._call("POST", f"/v1/vaults/{vault}/records", {"fields": fields, "subject_ref": subject_ref or ""})

    def get_record(self, vault: str, record_id: str, purpose: str) -> Dict[str, Dict[str, Any]]:
        """Reads every field of a record, each as the caller's access rules allow."""
        return self._call("GET", f"/v1/vaults/{vault}/records/{quote(record_id, safe='')}", None, {"X-RV-Purpose": purpose})["fields"]

    def update_value(self, vault: str, token: str, value: str) -> None:
        """Changes the value behind a new-token-each-time (cell) token. The token stays the same."""
        self._call("PUT", f"/v1/vaults/{vault}/tokens/{quote(token, safe='')}", {"value": value})

    def search_subjects(self, vault: str, query: str = "", **filters: Any) -> Dict[str, Any]:
        """Lists the people in a vault: {"subjects": [...], "total": n}. Filters: field_type, has_reveals,
        flagged, created_after, created_before, sort, dir, limit (1 to 200, default 50), offset."""
        return self._call("POST", f"/v1/vaults/{vault}/subjects/search", {"query": query, **filters})

    def get_subject(self, vault: str, subject_id: str) -> Dict[str, Any]:
        """One person and their fields, each masked at most. Never returns real values."""
        r = self._call("GET", f"/v1/vaults/{vault}/subjects/{quote(subject_id, safe='')}")
        r.pop("request_id", None)
        return r

    def export_subject(self, vault: str, subject_id: str, purpose: str) -> List[Dict[str, str]]:
        """Exports one person's fields for an access request, as access rules allow."""
        return self._call("GET", f"/v1/vaults/{vault}/subjects/{quote(subject_id, safe='')}/export", None, {"X-RV-Purpose": purpose})["fields"]

    def restrict_subject(self, vault: str, subject_id: str, restricted: bool, purpose: str) -> bool:
        """While restricted, nothing about the person reveals, whatever the access rules say."""
        return self._call("POST", f"/v1/vaults/{vault}/subjects/{quote(subject_id, safe='')}/restrict", {"restricted": restricted, "purpose": purpose})["restricted"]

    def check_flow(self, vault: str, flow: str, text: str) -> Dict[str, Any]:
        """Checks a batch before a job sends it somewhere Onshore cannot sit in the path. Only counts are kept."""
        return self._call("POST", f"/v1/vaults/{vault}/flows/{quote(flow, safe='')}/check", {"text": text})

    def lookup(self, vault: str, field: str, value: str) -> str:
        return self._call("POST", f"/v1/vaults/{vault}/lookup", {"field": field, "value": value})["token"]

    def detect(self, text: str, tokenize: bool = False, vault: Optional[str] = None, entities: Optional[List[str]] = None, include_shadow: bool = False) -> Dict[str, Any]:
        """Custom entities apply when vault is named. entities limits to built-in or custom slugs."""
        return self._call("POST", "/v1/detect", {"text": text, "tokenize": tokenize, "vault": vault or "", "entities": entities or [], "include_shadow": include_shadow})

    def create_client_token(self, vault: str, kind: str, origin: str, fields: Optional[List[str]] = None, tokens: Optional[List[str]] = None, purpose: str = "", on_behalf_of: str = "", subject_ref: str = "", bind_ip: str = "", ttl_seconds: int = 0) -> Dict[str, Any]:
        """Mints a single-use token for a secure component in a browser. collect names
        fields; reveal names tokens and needs a purpose. Call this from your server."""
        return self._call("POST", f"/v1/vaults/{vault}/client-tokens", {"kind": kind, "origin": origin, "fields": fields or [], "tokens": tokens or [], "purpose": purpose, "on_behalf_of": on_behalf_of, "subject_ref": subject_ref, "bind_ip": bind_ip, "ttl_seconds": ttl_seconds})

    def resident_check(self, vault: str, token: str, check: str, arg: str, purpose: str) -> bool:
        """Runs a check in the country and returns only True or False. Checks: equals,
        name_match, age_at_least, amount_at_least. Needs the `compare` policy action."""
        return self._call("POST", f"/v1/vaults/{vault}/resident/check", {"token": token, "check": check, "arg": arg, "purpose": purpose})["result"]

    def cloak(self, vault: str, text: str, profile_id: Optional[str] = None, options: Optional[Dict[str, str]] = None, keep_days: int = 0) -> Dict[str, Any]:
        """Cloaks text before it goes to a model or any outside service. Returns text,
        changed (counts by type) and, with keep_days, the digital twin's id."""
        body: Dict[str, Any] = {"text": text}
        if profile_id:
            body["profile_id"] = profile_id
        if options is not None:
            body["options"] = options
        if keep_days:
            body["keep_days"] = keep_days
        return self._call("POST", f"/v1/vaults/{vault}/cloak", body)

    def uncloak(self, vault: str, twin_id: str, text: str, purpose: str) -> Dict[str, Any]:
        """Swaps placeholders and stand-in names back, as far as the caller's policy allows."""
        return self._call("POST", f"/v1/vaults/{vault}/uncloak", {"id": twin_id, "text": text, "purpose": purpose})

    def delete_twin(self, vault: str, twin_id: str) -> Dict[str, Any]:
        return self._call("DELETE", f"/v1/vaults/{vault}/twins/{twin_id}")

    def erase_subject(self, vault: str, subject_id: str, purpose: str) -> Dict[str, Any]:
        """Erases everything held on a person. Returns {"erased_records": n, ...}."""
        return self._call("DELETE", f"/v1/vaults/{vault}/subjects/{quote(subject_id, safe='')}", None, {"X-RV-Purpose": purpose})
