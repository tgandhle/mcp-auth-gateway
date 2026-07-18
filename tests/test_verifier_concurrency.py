"""Concurrency and failure-mode tests for JWKS key resolution.

The proxy calls ``verify()`` from a worker thread, so the verifier's own
locking is what protects concurrent requests. These tests pin the properties
the redesigned ``_resolve_key`` claims:

- single-flight: concurrent misses collapse into one fetch;
- non-blocking fast path: a cached key keeps verifying while another thread is
  stuck in a slow fetch (previously every verification serialized behind the
  lock held across the network call);
- failure containment: a failed fetch is a ``TokenError`` (a 401 at the proxy),
  not an unhandled exception, and it starts the cooldown so an unreachable
  authorization server is retried once per window rather than once per request.
"""

from __future__ import annotations

import threading
import time

import pytest

from conftest import AUDIENCE, ISSUER, mint
from mcp_gateway.verifier import JwksVerifier, TokenError


def make_verifier(**kw) -> JwksVerifier:
    defaults = {
        "jwks_url": "https://issuer.test/jwks",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "allowed_algorithms": ["RS256"],
        "min_refresh_interval": 10.0,
        "fetch_timeout": 2.0,
    }
    defaults.update(kw)
    return JwksVerifier(**defaults)


def test_concurrent_misses_single_flight(monkeypatch, jwks, rsa_key):
    """Ten threads hitting a cold cache at once must produce exactly one fetch."""
    v = make_verifier()
    fetch_count = 0
    fetch_lock = threading.Lock()

    def counting_fetch():
        nonlocal fetch_count
        with fetch_lock:
            fetch_count += 1
        time.sleep(0.05)  # widen the race window
        return jwks

    monkeypatch.setattr(v, "_fetch_jwks", counting_fetch)
    token = mint(rsa_key)

    results: list[str | Exception] = []

    def worker():
        try:
            results.append(v.verify(token).subject)
        except Exception as exc:  # noqa: BLE001 - collected for assertion
            results.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert fetch_count == 1
    assert all(r == "user-123" for r in results), results


def test_cached_key_verifies_while_fetch_is_in_flight(monkeypatch, jwks, rsa_key):
    """The property that moves the stall off the hot path: while one thread is
    stuck in a slow JWKS fetch (triggered by a bogus kid after the cooldown),
    verification of a cached kid must complete without waiting for it."""
    v = make_verifier(min_refresh_interval=0.0)  # allow the miss-refresh immediately
    fetch_started = threading.Event()
    release_fetch = threading.Event()
    calls = 0

    def gated_fetch():
        nonlocal calls
        calls += 1
        if calls == 1:
            return jwks  # cold populate: fast
        fetch_started.set()
        assert release_fetch.wait(timeout=5), "test deadlock: fetch never released"
        return jwks

    monkeypatch.setattr(v, "_fetch_jwks", gated_fetch)

    good = mint(rsa_key)
    bogus = mint(rsa_key, kid="no-such-kid")

    v.verify(good)  # populate the cache (fetch #1)

    slow_result: list[BaseException | None] = []

    def slow_worker():
        try:
            v.verify(bogus)  # triggers fetch #2, which blocks on the gate
            slow_result.append(None)
        except BaseException as exc:  # noqa: BLE001
            slow_result.append(exc)

    t = threading.Thread(target=slow_worker)
    t.start()
    assert fetch_started.wait(timeout=5), "refresh never started"

    # The refresh is now in flight and holding no lock: cached verification
    # must succeed promptly.
    start = time.monotonic()
    assert v.verify(good).subject == "user-123"
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, f"cached verification blocked behind the fetch ({elapsed:.2f}s)"

    release_fetch.set()
    t.join(timeout=5)
    assert slow_result and isinstance(slow_result[0], TokenError)  # bogus kid: fail closed


def test_fetch_failure_is_token_error_and_starts_cooldown(monkeypatch, jwks, rsa_key):
    """An unreachable authorization server must yield a 401-shaped TokenError,
    not an unhandled URLError, and must not be re-fetched inside the cooldown."""
    v = make_verifier(min_refresh_interval=30.0)
    attempts = 0

    def failing_fetch():
        nonlocal attempts
        attempts += 1
        raise OSError("connection refused")

    monkeypatch.setattr(v, "_fetch_jwks", failing_fetch)
    token = mint(rsa_key)

    with pytest.raises(TokenError):
        v.verify(token)          # cold fetch attempt -> fails -> TokenError
    with pytest.raises(TokenError):
        v.verify(token)          # inside the cooldown: fail closed, NO new attempt
    assert attempts == 1


def test_stale_key_served_during_refresh_window(monkeypatch, jwks, rsa_key):
    """A key past its TTL is served while a refresh is in flight rather than
    making every request wait on the fetch."""
    v = make_verifier(cache_ttl=0, min_refresh_interval=0.0)  # everything is instantly stale
    fetch_started = threading.Event()
    release_fetch = threading.Event()
    calls = 0

    def gated_fetch():
        nonlocal calls
        calls += 1
        if calls == 1:
            return jwks
        fetch_started.set()
        assert release_fetch.wait(timeout=5)
        return jwks

    monkeypatch.setattr(v, "_fetch_jwks", gated_fetch)
    token = mint(rsa_key)
    v.verify(token)  # populate

    holder: list[BaseException | None] = []

    def refresher():
        try:
            v.verify(token)  # TTL expired -> this thread refreshes, gated
            holder.append(None)
        except BaseException as exc:  # noqa: BLE001
            holder.append(exc)

    t = threading.Thread(target=refresher)
    t.start()
    assert fetch_started.wait(timeout=5)

    start = time.monotonic()
    assert v.verify(token).subject == "user-123"  # stale-serve, no waiting
    assert time.monotonic() - start < 1.0

    release_fetch.set()
    t.join(timeout=5)
    assert holder == [None]
