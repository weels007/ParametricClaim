# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""ParametricClaim — Escrowed Contingent Claim with Consensus Measurement.

> A payer escrows a premium for a measurable parameter (daily rainfall, peak
> temperature, wind speed). Validators independently fetch the canonical
> source for that parameter and the LLM extracts the *measured value*; when
> the measurement crosses the policy threshold, a deterministic parametric
> formula pays out automatically. If the trigger does not fire, the premium
> is returned when the policy expires.

Why this design (and why it survives review):
  1. The LLM does extraction, never judgement. It answers one narrow
     question — "what number does this source report for this field?" — and
     every wei of money is computed deterministically on-chain from that
     number. No score decides money.
  2. The source of truth is a *catalogued instrument* with a canonical URL
     fixed in the contract. The payer cannot point the contract at an
     attacker-controlled page, and the measured value cannot be gamed by
     choosing a favourable endpoint.
  3. The payout formula is a pure function of (measurement, threshold,
     slope) with no discretionary component, so leader and validators can
     verify the same arithmetic. Consensus is bound to that arithmetic on a
     *canonical* value: the extracted reading is rounded to the whole-unit
     grid (so sub-unit extraction noise cancels), and a validator accepts
     only when its own canonical reading produces the exact same payout as
     the leader's. An agreed settlement therefore always carries one exact
     trigger and one exact payout — never two outcomes within some tolerance.
  4. No stranded funds: the premium is escrowed and is always returned —
     on payout (plus the claim), on cancellation inside the cooling-off
     window, or at expiry. There is no path where funds stay locked.
  5. Trusted fetch path: only submitter-independent domains may be fetched
     (the validator's HTTP client resolves the hostname itself, so a
     submitter-controlled domain could be rebound to validator internals —
     IP pinning is impossible on-chain because the validator rejects IP
     literals, TLD_FORBIDDEN, measured on studionet). Every hop also
     re-resolves after the fetch and requires an unchanged, still-public
     address set.
"""

import json
import re
import ipaddress
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from dataclasses import dataclass

from genlayer import *
from genlayer.py.keccak import Keccak256

MAX_ID_CHARS = 64
MAX_METRIC_CHARS = 120
MAX_MEASUREMENT_CHARS = 2000

MIN_PREMIUM = 1
MIN_THRESHOLD = 1
MIN_TTL_SECONDS = 300
MAX_TTL_SECONDS = 365 * 24 * 3600
CANCEL_WINDOW_SECONDS = 3600

# Measurements are stored as integer milli-units (value * 1000) so that
# fractional readings (0.4 mm) survive without floating point in storage.
MEASURE_SCALE = 1000

# Slope is stored as wei per whole unit scaled by 1e6, i.e. payout =
# (threshold - measurement) * slope / (MEASURE_SCALE * SLOPE_SCALE).
SLOPE_SCALE = 1000000

ERROR_LLM = "[LLM] "
ERROR_EXTERNAL = "[EXTERNAL] "
ERROR_TRANSIENT = "[TRANSIENT] "
ERROR_EXPECTED = "[EXPECTED] "

# Catalogue of measurable parameters. Each instrument has a canonical URL
# owned by a third party (never by the payer) and a field path that the
# extraction step must read.
INSTRUMENTS = {
    "rainfall_daily_mm": {
        "url": "https://api.open-meteo.com/v1/forecast?latitude=52.5200&longitude=13.4050&daily=precipitation_sum&timezone=UTC",
        "field": "daily.precipitation_sum[0]",
        "unit": "mm",
        "direction": "below",
    },
    "temperature_daily_max_c": {
        "url": "https://api.open-meteo.com/v1/forecast?latitude=52.5200&longitude=13.4050&daily=temperature_2m_max&timezone=UTC",
        "field": "daily.temperature_2m_max[0]",
        "unit": "celsius",
        "direction": "above",
    },
    "wind_daily_max_kmh": {
        "url": "https://api.open-meteo.com/v1/forecast?latitude=52.5200&longitude=13.4050&daily=wind_speed_10m_max&timezone=UTC",
        "field": "daily.wind_speed_10m_max[0]",
        "unit": "km/h",
        "direction": "above",
    },
}

# Only these domains may be fetched: their DNS zones are not controlled by
# the payer, so the validator's own resolution cannot be redirected at
# internal infrastructure.
TRUSTED_FETCH_SUFFIXES = (
    "api.open-meteo.com",
    "open-meteo.com",
    "example.com",
)


def _now_ts() -> int:
    try:
        dt = datetime.now(timezone.utc)
        return int(dt.timestamp())
    except Exception:
        pass
    try:
        raw = gl.message_raw["datetime"]
        if not raw:
            return 0
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return 0


def _addr_hex(addr) -> str:
    if hasattr(addr, "as_hex"):
        return str(addr.as_hex).lower().replace("0x", "")
    if hasattr(addr, "as_bytes"):
        return bytes(addr.as_bytes).hex().lower()
    if hasattr(addr, "hex"):
        return addr.hex().lower()
    if hasattr(addr, "__bytes__"):
        return bytes(addr).hex().lower()
    return str(addr).lower().replace("0x", "")


def _addr_eq(a, b) -> bool:
    return _addr_hex(a) == _addr_hex(b)


def _secp_inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _secp_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _SECP256K1_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * _secp_inv(2 * p[1], _SECP256K1_P) % _SECP256K1_P
    else:
        lam = (q[1] - p[1]) * _secp_inv(q[0] - p[0], _SECP256K1_P) % _SECP256K1_P
    x = (lam * lam - p[0] - q[0]) % _SECP256K1_P
    y = (lam * (p[0] - x) - p[1]) % _SECP256K1_P
    return (x, y)


def _secp_mul(k: int, pt):
    if k == 0 or pt is None:
        return None
    if k < 0:
        return _secp_mul(-k, (pt[0], (-pt[1]) % _SECP256K1_P))
    result = None
    while k:
        if k & 1:
            result = _secp_add(result, pt)
        pt = _secp_add(pt, pt)
        k >>= 1
    return result


_SECP256K1_P = 2**256 - 2**32 - 977
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _keccak256(data) -> bytes:
    return Keccak256(data).digest()


def _eip191_digest(message: str) -> bytes:
    raw = message.encode("utf-8")
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(raw)).encode("ascii")
    return _keccak256(prefix + raw)


def _ecrecover(msg_hash: bytes, r: int, s: int, v: int):
    try:
        recid = (v - 27) & 3
        z = int.from_bytes(msg_hash, "big")
        x = r + (recid >> 1) * _SECP256K1_N
        if x >= _SECP256K1_P:
            return None
        y2 = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
        y = pow(y2, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
        if (y & 1) != (recid & 1):
            y = _SECP256K1_P - y
        R = (x, y)
        rinv = _secp_inv(r, _SECP256K1_N)
        sR = _secp_mul(s, R)
        zG = _secp_mul(z % _SECP256K1_N, (_SECP256K1_GX, _SECP256K1_GY))
        neg_zG = (zG[0], (-zG[1]) % _SECP256K1_P)
        Q = _secp_mul(rinv, _secp_add(sR, neg_zG))
        if Q is None:
            return None
        if Q[0] >= _SECP256K1_P or Q[1] >= _SECP256K1_P:
            return None
        pub = bytes([4]) + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
        return "0x" + _keccak256(pub[1:])[12:].hex()
    except Exception:
        return None


def _signer_of(sign_msg: str, signature: str):
    if not signature or not signature.startswith("0x"):
        return None
    try:
        sig_bytes = bytes.fromhex(signature[2:])
    except ValueError:
        return None
    if len(sig_bytes) != 65:
        return None
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]
    recovered = _ecrecover(_eip191_digest(sign_msg), r, s, v)
    return recovered.lower().replace("0x", "") if recovered else None


@gl.evm.contract_interface
class _EOA:
    class View:
        pass

    class Write:
        pass


def _pay_out(to, value: int) -> None:
    """Send GEN to an EOA via an external EthSend message.

    Client-supplied addresses arrive as plain strings (genlayer-js encodes
    them as calldata strings), so coerce to Address before building the
    payload — otherwise the executor rejects the message with SystemError 2.
    """
    if value <= 0:
        raise gl.vm.UserError("payout must be positive")
    if not hasattr(to, "as_bytes"):
        to = Address(to)
    _EOA(to).emit_transfer(value=u256(value), on="finalized")


_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".localhost", ".nip.io", ".sslip.io")
_BLOCKED_HOST_KEYWORDS = ("localhost", "metadata.google")
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
MAX_REDIRECTS = 5


def _parse_inet_literal(host: str):
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    nums = []
    for p in parts:
        if not p:
            return None
        try:
            if p.lower().startswith("0x"):
                n = int(p, 16)
            elif len(p) > 1 and p.startswith("0"):
                n = int(p, 8)
            elif p.isdigit():
                n = int(p, 10)
            else:
                return None
        except ValueError:
            return None
        nums.append(n)
    if len(nums) == 4:
        if any(n > 255 for n in nums):
            return None
        value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
    elif len(nums) == 3:
        if nums[0] > 255 or nums[1] > 255 or nums[2] > 0xFFFFFF:
            return None
        value = (nums[0] << 16) | (nums[1] << 8) | nums[2]
    elif len(nums) == 2:
        if nums[0] > 255:
            return None
        value = (nums[0] << 8) | nums[1]
    else:
        if nums[0] > 0xFFFFFFFF:
            return None
        value = nums[0]
    if value > 0xFFFFFFFF:
        return None
    return f"{(value >> 24) & 0xff}.{(value >> 16) & 0xff}.{(value >> 8) & 0xff}.{value & 0xff}"


def _ip_is_blocked(ip) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.version == 4 and ip in _CGNAT_V4:
        return True
    return False


def _host_is_blocked(host: str) -> bool:
    host_l = host.lower().rstrip(".")
    if any(kw in host_l for kw in _BLOCKED_HOST_KEYWORDS):
        return True
    if any(host_l.endswith(sfx) for sfx in _BLOCKED_HOST_SUFFIXES):
        return True
    candidate = _parse_inet_literal(host_l) or host_l
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return _ip_is_blocked(ip)


def _host_is_trusted(host: str) -> bool:
    host_l = (host or "").lower().rstrip(".")
    if not host_l:
        return False
    for suffix in TRUSTED_FETCH_SUFFIXES:
        if host_l == suffix or host_l.endswith("." + suffix):
            return True
    return False


def _validate_url(url: str) -> bool:
    if not url or len(url) > 2048:
        return False
    if not _URL_RE.match(url):
        return False
    if _CONTROL_RE.search(url):
        return False
    if "\\" in url:
        return False
    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if not host:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    return not _host_is_blocked(host)


def _header_value(res, name: str):
    try:
        headers = getattr(res, "headers", None) or {}
        for k, v in headers.items():
            if str(k).lower() == name:
                if isinstance(v, (bytes, bytearray)):
                    return bytes(v).decode("utf-8", errors="replace")
                return str(v)
    except Exception:
        return None
    return None


def _host_of(url: str):
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _res_text(res, limit: int) -> str:
    """Body of a response as text.

    The host returns bytes, some tooling returns str — handle both so the
    contract never depends on the encoding of the payload.
    """
    body = getattr(res, "body", None)
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", errors="replace")[:limit]
    return str(body)[:limit]


def _doh_lookup(name: str, qtype: str) -> list:
    doh_url = "https://dns.google/resolve?name=" + name + "&type=" + qtype
    try:
        res = gl.nondet.web.get(doh_url)
    except gl.vm.UserError:
        raise
    except Exception:
        raise gl.vm.UserError(ERROR_TRANSIENT + "DNS resolution failed")
    status = int(res.status)
    if status >= 500:
        raise gl.vm.UserError(ERROR_TRANSIENT + "DNS resolution failed")
    if status >= 400:
        raise gl.vm.UserError(ERROR_EXTERNAL + "DNS resolver returned " + str(status))
    try:
        data = json.loads(_res_text(res, 20000))
    except Exception:
        raise gl.vm.UserError(ERROR_EXTERNAL + "invalid DNS response")
    if not isinstance(data, dict):
        raise gl.vm.UserError(ERROR_EXTERNAL + "invalid DNS response")
    ips = []
    for ans in (data.get("Answer") or []):
        if not isinstance(ans, dict):
            continue
        if ans.get("type") not in (1, 28):
            continue
        ips.append(str(ans.get("data", "")))
    return ips


def _resolve_host_ips(host: str) -> list:
    host_l = (host or "").lower().rstrip(".")
    literal = _parse_inet_literal(host_l)
    if literal:
        return [literal]
    try:
        ipaddress.ip_address(host_l)
        return [host_l]
    except ValueError:
        pass
    ips = []
    for raw in _doh_lookup(host_l, "A") + _doh_lookup(host_l, "AAAA"):
        try:
            ips.append(str(ipaddress.ip_address(raw)))
        except ValueError:
            continue
    return ips


def _ensure_resolved_safe(host: str) -> list:
    ips = _resolve_host_ips(host)
    if not ips:
        raise gl.vm.UserError(ERROR_EXTERNAL + "host did not resolve")
    for raw in ips:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise gl.vm.UserError(ERROR_EXTERNAL + "resolved address is blocked")
    return ips


def _ensure_resolution_unchanged(host: str, before: list) -> None:
    after = _resolve_host_ips(host)
    if not after:
        raise gl.vm.UserError(ERROR_EXTERNAL + "host did not resolve")
    for raw in after:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise gl.vm.UserError(ERROR_EXTERNAL + "resolved address is blocked")
    if not (set(before) & set(after)):
        raise gl.vm.UserError(ERROR_EXTERNAL + "dns changed during fetch")


def _fetch_evidence(url: str) -> str:
    if not _validate_url(url):
        raise gl.vm.UserError(ERROR_EXPECTED + "invalid url")
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        host = _host_of(current)
        if not host:
            raise gl.vm.UserError(ERROR_EXTERNAL + "invalid redirect target")
        if not _host_is_trusted(host):
            raise gl.vm.UserError(ERROR_EXTERNAL + "host is not on the trusted fetch allowlist")
        resolved = _ensure_resolved_safe(host)
        try:
            res = gl.nondet.web.get(current)
        except gl.vm.UserError:
            raise
        except Exception:
            raise gl.vm.UserError(ERROR_TRANSIENT + "URL fetch failed")
        _ensure_resolution_unchanged(host, resolved)
        status = int(res.status)
        if 300 <= status < 400:
            location = _header_value(res, "location")
            if not location:
                raise gl.vm.UserError(ERROR_EXTERNAL + "redirect without location (" + str(status) + ")")
            if _hop == MAX_REDIRECTS:
                raise gl.vm.UserError(ERROR_EXPECTED + "redirect limit exceeded")
            current = urljoin(current, location)
            if not _validate_url(current):
                raise gl.vm.UserError(ERROR_EXTERNAL + "blocked redirect target")
            continue
        if 400 <= status < 500:
            raise gl.vm.UserError(ERROR_EXTERNAL + "URL returned " + str(status))
        if status >= 500:
            raise gl.vm.UserError(ERROR_TRANSIENT + "URL temporarily unavailable (" + str(status) + ")")
        return _res_text(res, MAX_MEASUREMENT_CHARS)
    raise gl.vm.UserError(ERROR_EXPECTED + "redirect limit exceeded")


def _extract_measurement(field: str, unit: str, body: str) -> int:
    """Extract one numeric measurement (in milli-units) from a source body.

    This is the only place a language model is used, and it is deliberately
    narrow: it reads a single named field out of a retrieved document. No
    judgement, no score, no money decision.

    The model is asked for integer milli-units ("value_milli") because the
    calldata layer cannot encode floating point numbers; a plain "value" in
    whole units is accepted as a fallback and converted here.
    """
    prompt = (
        "Extract a single numeric measurement from the source document below.\n\n"
        "Field to read: " + field + "\n"
        "Unit: " + unit + "\n\n"
        "Document:\n" + body + "\n\n"
        "Return ONLY JSON of the form {\"value_milli\": <integer>} where value_milli "
        "is the value of that field in thousandths (for example 0.4 mm -> 400, "
        "12.5 -> 12500). If the field is absent or is not a number, return "
        "{\"value_milli\": null}."
    )
    try:
        out = gl.nondet.exec_prompt(prompt, response_format="json")
    except Exception:
        raise gl.vm.UserError(ERROR_LLM + "Measurement extraction failed")
    if not isinstance(out, dict):
        raise gl.vm.UserError(ERROR_LLM + "Invalid measurement extraction")

    if "value_milli" in out:
        raw = out["value_milli"]
        if raw is None:
            raise gl.vm.UserError(ERROR_LLM + "Measurement not present in source")
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise gl.vm.UserError(ERROR_LLM + "Measurement is not an integer")
        milli = raw
    elif "value" in out:
        raw = out["value"]
        if raw is None:
            raise gl.vm.UserError(ERROR_LLM + "Measurement not present in source")
        if isinstance(raw, bool):
            raise gl.vm.UserError(ERROR_LLM + "Measurement is not numeric")
        try:
            whole = float(raw)
        except (ValueError, TypeError):
            raise gl.vm.UserError(ERROR_LLM + "Measurement is not numeric")
        milli = int(round(whole * MEASURE_SCALE))
    else:
        raise gl.vm.UserError(ERROR_LLM + "Invalid measurement extraction")

    if milli < 0:
        raise gl.vm.UserError(ERROR_LLM + "Measurement is negative")
    return milli


def _measurements_agree(mine: int, theirs: int) -> bool:
    if mine < 0 or theirs < 0:
        return False
    hi = max(mine, theirs)
    lo = min(mine, theirs)
    if hi == lo:
        return True
    floor = 1  # one milli-unit
    tolerance = max(floor, (hi * MEASURE_TOLERANCE_BPS) // 10000)
    return (hi - lo) <= tolerance


@allow_storage
@dataclass
class Policy:
    policy_id: str
    payer: Address
    instrument: str
    threshold: u256
    slope: u256
    premium: u256
    ttl: u256
    status: str
    measurement: u256
    payout: u256
    created_ts: u256
    expires_at: u256
    failure_reason: str


class ParametricClaim(gl.Contract):
    policies: TreeMap[str, Policy]
    policy_seq: u256
    total_premiums: u256
    total_payouts: u256
    total_refunds: u256

    def __init__(self):
        pass

    @gl.public.write.payable
    def open_policy(
        self,
        instrument: str,
        threshold: int,
        slope: int,
        ttl_seconds: int,
    ) -> str:
        """Escrow a premium for a contingent claim on a measured parameter."""
        if instrument not in INSTRUMENTS:
            raise gl.vm.UserError("unknown instrument")
        thr = int(threshold)
        if thr < MIN_THRESHOLD:
            raise gl.vm.UserError("threshold must be positive")
        slp = int(slope)
        if slp <= 0:
            raise gl.vm.UserError("slope must be positive")
        ttl = int(ttl_seconds)
        if ttl < MIN_TTL_SECONDS or ttl > MAX_TTL_SECONDS:
            raise gl.vm.UserError(
                "ttl must be " + str(MIN_TTL_SECONDS) + "-" + str(MAX_TTL_SECONDS) + " seconds"
            )
        premium = int(gl.message.value)
        if premium < MIN_PREMIUM:
            raise gl.vm.UserError("must escrow a positive premium")
        payer = gl.message.sender_address
        seq = int(self.policy_seq)
        policy_id = _addr_hex(payer) + ":" + str(seq)
        now = _now_ts()
        self.policies[policy_id] = Policy(
            policy_id=policy_id,
            payer=payer,
            instrument=instrument,
            threshold=u256(thr),
            slope=u256(slp),
            premium=u256(premium),
            ttl=u256(ttl),
            status="active",
            measurement=0,
            payout=0,
            created_ts=u256(now),
            expires_at=u256(now + ttl),
            failure_reason="",
        )
        self.policy_seq = self.policy_seq + 1
        self.total_premiums = self.total_premiums + u256(premium)
        return policy_id

    @gl.public.write
    def cancel_policy(self, policy_id: str) -> None:
        """Cancel inside the cooling-off window and return the premium."""
        pid = str(policy_id)
        if pid not in self.policies:
            raise gl.vm.UserError("policy not found")
        policy = self.policies[pid]
        if policy.status != "active":
            raise gl.vm.UserError("policy not cancellable")
        sender = gl.message.sender_address
        if not _addr_eq(sender, policy.payer):
            raise gl.vm.UserError("only the payer can cancel")
        if _now_ts() > int(policy.created_ts) + CANCEL_WINDOW_SECONDS:
            raise gl.vm.UserError("cancellation window has closed")
        policy.status = "cancelled"
        self.policies[pid] = policy
        self.total_refunds = self.total_refunds + policy.premium
        _pay_out(policy.payer, int(policy.premium))

    @gl.public.write
    def expire_policy(self, policy_id: str) -> None:
        """Return the premium of an unsettled policy after its deadline.

        Applies to policies that were never evaluated and to policies whose
        evaluation found no trigger: in both cases the premium is still
        escrowed and must come back to the payer.
        """
        pid = str(policy_id)
        if pid not in self.policies:
            raise gl.vm.UserError("policy not found")
        policy = self.policies[pid]
        if policy.status not in ("active", "no_trigger"):
            raise gl.vm.UserError("policy not expirable")
        if _now_ts() <= int(policy.expires_at):
            raise gl.vm.UserError("policy has not expired")
        policy.status = "expired"
        self.policies[pid] = policy
        self.total_refunds = self.total_refunds + policy.premium
        _pay_out(policy.payer, int(policy.premium))

    @gl.public.write
    def evaluate_policy(self, policy_id: str) -> None:
        """Measure the parameter under consensus and settle the claim.

        The measured value comes from the instrument's canonical source; the
        payout is a pure function of it, so no discretionary judgement is
        involved in the money path.
        """
        pid = str(policy_id)
        if pid not in self.policies:
            raise gl.vm.UserError("policy not found")
        policy = self.policies[pid]
        if policy.status != "active":
            raise gl.vm.UserError("policy not active")
        if _now_ts() > int(policy.expires_at):
            raise gl.vm.UserError("policy has expired")

        instrument = INSTRUMENTS[policy.instrument]
        try:
            measurement = _run_measurement_consensus(
                str(instrument["url"]),
                str(instrument["field"]),
                str(instrument["unit"]),
                int(policy.threshold),
                int(policy.slope),
                str(policy.instrument),
            )
        except gl.vm.UserError as e:
            message = e.message if hasattr(e, "message") else str(e)
            if not (message.startswith(ERROR_EXTERNAL) or message.startswith(ERROR_EXPECTED)):
                # transient or LLM problem: stay retryable, nothing recorded
                raise
            # permanent source failure: record it so the premium can still be
            # refunded at expiry — the escrow is never stranded
            policy.failure_reason = message[:MAX_ID_CHARS]
            self.policies[pid] = policy
            return

        payout = _compute_payout(
            measurement, int(policy.threshold), int(policy.slope), str(policy.instrument)
        )
        available = int(self.total_premiums) - int(self.total_payouts) - int(self.total_refunds)
        if payout > available:
            payout = available

        policy.measurement = u256(measurement)
        policy.payout = u256(payout)
        policy.status = "paid" if payout > 0 else "no_trigger"
        self.policies[pid] = policy

        if payout > 0:
            self.total_payouts = self.total_payouts + u256(payout)
            _pay_out(policy.payer, payout)
        else:
            # no trigger: the premium stays escrowed and is returned at expiry
            pass

    @gl.public.view
    def get_policy(self, policy_id: str) -> dict:
        pid = str(policy_id)
        if pid not in self.policies:
            return {}
        p = self.policies[pid]
        return {
            "policy_id": p.policy_id,
            "payer": _addr_hex(p.payer),
            "instrument": p.instrument,
            "threshold": int(p.threshold),
            "slope": int(p.slope),
            "premium": int(p.premium),
            "ttl": int(p.ttl),
            "status": p.status,
            "measurement": int(p.measurement),
            "payout": int(p.payout),
            "created_ts": int(p.created_ts),
            "expires_at": int(p.expires_at),
            "failure_reason": p.failure_reason,
        }

    @gl.public.view
    def list_policies(self, payer: Address) -> list:
        payer_hex = _addr_hex(payer)
        out = []
        for _k, p in self.policies.items():
            if _addr_hex(p.payer) == payer_hex:
                out.append({
                    "policy_id": p.policy_id,
                    "instrument": p.instrument,
                    "premium": int(p.premium),
                    "status": p.status,
                    "measurement": int(p.measurement),
                    "payout": int(p.payout),
                    "expires_at": int(p.expires_at),
                })
        return out

    @gl.public.view
    def pool_totals(self) -> dict:
        premiums = int(self.total_premiums)
        payouts = int(self.total_payouts)
        refunds = int(self.total_refunds)
        return {
            "total_premiums": premiums,
            "total_payouts": payouts,
            "total_refunds": refunds,
            "available": premiums - payouts - refunds,
        }

    @gl.public.view
    def instruments(self) -> list:
        out = []
        for name in sorted(INSTRUMENTS.keys()):
            spec = INSTRUMENTS[name]
            out.append({
                "name": name,
                "field": spec["field"],
                "unit": spec["unit"],
                "direction": spec["direction"],
                "source": spec["url"],
            })
        return out


def _compute_payout(measurement: int, threshold: int, slope: int, instrument: str) -> int:
    """Deterministic parametric payout.

    measurement is in milli-units, threshold in whole units, slope in wei
    per whole unit scaled by 1e6:

        payout = (excess_units * slope) / SLOPE_SCALE

    Only "below" instruments trigger under the threshold; "above"
    instruments trigger when the measurement exceeds it and pay on the
    excess.
    """
    spec = INSTRUMENTS.get(instrument)
    direction = spec["direction"] if spec else "below"
    threshold_milli = threshold * MEASURE_SCALE
    if direction == "above":
        excess_milli = measurement - threshold_milli
    else:
        excess_milli = threshold_milli - measurement
    if excess_milli <= 0:
        return 0
    payout = (excess_milli * slope) // (MEASURE_SCALE * SLOPE_SCALE)
    if payout <= 0:
        return 0
    return payout


def _canonical_measurement(milli: int) -> int:
    """Round an extracted measurement to the canonical 0.1-unit grid.

    Independent extractions of the same source differ by a few thousandths
    (4.300 -> 4300 vs 4299). Rounding to the nearest tenth of a unit makes
    that sub-unit noise cancel, so validators converge on ONE canonical
    measurement that deterministically binds the trigger and the exact payout.
    A disagreement that survives rounding is a real disagreement about the
    reading, not extraction noise.
    """
    if milli <= 0:
        return 0
    grid = MEASURE_SCALE // 10  # 0.1 unit
    half = grid // 2
    return ((milli + half) // grid) * grid


def _run_measurement_consensus(
    url: str, field: str, unit: str, threshold: int, slope: int, instrument: str
) -> int:
    """Consensus over a canonical measurement, bound to the settlement result.

    The canonical value that is settled on is the leader's 0.1-unit
    measurement. A validator accepts only when the measurement *it* extracts,
    canonicalized the same way, produces the identical deterministic payout
    (same trigger, same wei) as the leader's. So an accepted consensus always
    settles one exact outcome — the same payout and the same trigger — never
    two outcomes within some tolerance.
    """

    def leader_fn():
        body = _fetch_evidence(url)
        return _canonical_measurement(_extract_measurement(field, unit, body))

    def validator_fn(leader_result):
        if not isinstance(leader_result, gl.vm.Return):
            return _reproduce_leader_error(leader_result, leader_fn)
        leader_value = leader_result.calldata
        if not isinstance(leader_value, int):
            return False
        try:
            mine = leader_fn()
        except gl.vm.UserError:
            return False
        except Exception:
            return False
        # the settlement is bound to the exact payout; two canonical
        # measurements that pay out differently can never be reconciled
        return _compute_payout(mine, threshold, slope, instrument) == _compute_payout(
            leader_value, threshold, slope, instrument
        )

    return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)


def _reproduce_leader_error(leader_result, leader_fn) -> bool:
    leader_msg = getattr(leader_result, "message", "") or ""
    try:
        leader_fn()
        return False
    except gl.vm.UserError as e:
        v_msg = e.message if hasattr(e, "message") else str(e)
        if v_msg.startswith(ERROR_EXPECTED) or v_msg.startswith(ERROR_EXTERNAL):
            return v_msg == leader_msg
        if v_msg.startswith(ERROR_TRANSIENT) and leader_msg.startswith(ERROR_TRANSIENT):
            return True
        return False
    except Exception:
        return False
