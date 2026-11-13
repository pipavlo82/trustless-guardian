"""SQLite-backed atomic replay state for local research boundaries.

SQLite supplies cross-thread and cross-process uniqueness.  No in-memory fallback
exists: open, schema, transaction, capacity, or transition failures are refusals.
"""

import os
from pathlib import Path
import secrets
import sqlite3

from research.auth_gateway_v1.errors import SecurityError


SCHEMA_VERSION = "guardian.durable-security-state.v1"
ADMISSION_STATES = frozenset({"PREPARED", "COMMITTED", "ABORTED", "RECOVERY_REQUIRED"})
CHALLENGE_STATES = frozenset({"ISSUED", "CONSUMED", "EXPIRED"})


class DurableSecurityState:
    def __init__(self, path, scope, admission_capacity=1024, challenge_capacity=1024, timeout=5.0):
        self.path = Path(path).resolve()
        if type(scope) is not str or not scope or len(scope) > 256:
            raise ValueError("scope")
        if type(admission_capacity) is not int or admission_capacity < 1:
            raise ValueError("admission_capacity")
        if type(challenge_capacity) is not int or challenge_capacity < 1:
            raise ValueError("challenge_capacity")
        if type(timeout) not in {int, float} or timeout <= 0:
            raise ValueError("timeout")
        if not self.path.parent.is_dir() or self.path.is_symlink():
            raise SecurityError("DURABLE_STATE_UNAVAILABLE")
        self.scope = scope
        self.admission_capacity = admission_capacity
        self.challenge_capacity = challenge_capacity
        self.timeout = float(timeout)
        self._closed = False
        self._initialize()

    def close(self):
        self._closed = True

    def _connect(self):
        if self._closed:
            raise SecurityError("DURABLE_STATE_UNAVAILABLE")
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.timeout,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = " + str(int(self.timeout * 1000)))
            return connection
        except (sqlite3.Error, OSError) as error:
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error

    def _initialize(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT"
            )
            row = connection.execute(
                "SELECT value FROM metadata WHERE name = 'schema'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO metadata(name, value) VALUES('schema', ?)",
                    (SCHEMA_VERSION,),
                )
            elif row["value"] != SCHEMA_VERSION:
                connection.rollback()
                raise SecurityError("DURABLE_STATE_INCONSISTENT")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS admissions (
                    scope TEXT NOT NULL,
                    grant_id TEXT NOT NULL,
                    grant_sha256 TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL,
                    owner_session TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('PREPARED','COMMITTED','ABORTED','RECOVERY_REQUIRED')),
                    prepared_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    outcome_sha256 TEXT,
                    exit_code INTEGER,
                    PRIMARY KEY(scope, grant_id)
                ) STRICT
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS challenges (
                    scope TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    uri TEXT NOT NULL,
                    wallet TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    request_id TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('ISSUED','CONSUMED','EXPIRED')),
                    consumed_at INTEGER,
                    PRIMARY KEY(scope, challenge_id),
                    UNIQUE(scope, nonce)
                ) STRICT
                """
            )
            connection.commit()
        except SecurityError:
            raise
        except (sqlite3.Error, OSError) as error:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error
        finally:
            connection.close()
        if os.name != "nt":
            try:
                os.chmod(self.path, 0o600)
            except OSError as error:
                raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error

    @staticmethod
    def _text(value, name, minimum=1, maximum=512):
        if type(value) is not str or len(value) < minimum or len(value) > maximum:
            raise SecurityError(name)
        return value

    @staticmethod
    def _time(value, name):
        if type(value) is not int:
            raise SecurityError(name)
        return value

    def issue_challenge(
        self,
        session_id,
        domain,
        uri,
        wallet,
        chain_id,
        request_id,
        binding_sha256,
        now,
        ttl_seconds=120,
    ):
        session_id = self._text(session_id, "SIWE_CHALLENGE_SESSION")
        domain = self._text(domain, "SIWE_CHALLENGE_DOMAIN", maximum=253)
        uri = self._text(uri, "SIWE_CHALLENGE_URI", maximum=2048)
        wallet = self._text(wallet, "SIWE_CHALLENGE_WALLET", maximum=64).lower()
        request_id = self._text(request_id, "SIWE_CHALLENGE_REQUEST")
        binding_sha256 = self._text(binding_sha256, "SIWE_CHALLENGE_BINDING", minimum=64, maximum=64)
        now = self._time(now, "SIWE_CHALLENGE_TIME")
        if type(chain_id) is not int or chain_id < 1:
            raise SecurityError("SIWE_CHALLENGE_CHAIN")
        if type(ttl_seconds) is not int or ttl_seconds < 30 or ttl_seconds > 300:
            raise SecurityError("SIWE_CHALLENGE_TTL")
        challenge_id = secrets.token_hex(16)
        nonce = secrets.token_hex(16)
        expires_at = now + ttl_seconds
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE challenges SET state='EXPIRED' WHERE scope=? AND state='ISSUED' AND expires_at<=?",
                (self.scope, now),
            )
            connection.execute(
                "DELETE FROM challenges WHERE scope=? AND state IN ('CONSUMED','EXPIRED') AND expires_at<=?",
                (self.scope, now - 300),
            )
            count = connection.execute(
                "SELECT COUNT(*) AS value FROM challenges WHERE scope=?",
                (self.scope,),
            ).fetchone()["value"]
            if count >= self.challenge_capacity:
                connection.rollback()
                raise SecurityError("DURABLE_CHALLENGE_FULL")
            connection.execute(
                """
                INSERT INTO challenges(
                    scope, challenge_id, nonce, session_id, domain, uri, wallet,
                    chain_id, request_id, binding_sha256, issued_at, expires_at,
                    state, consumed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'ISSUED', NULL)
                """,
                (
                    self.scope,
                    challenge_id,
                    nonce,
                    session_id,
                    domain,
                    uri,
                    wallet,
                    chain_id,
                    request_id,
                    binding_sha256,
                    now,
                    expires_at,
                ),
            )
            connection.commit()
        except SecurityError:
            raise
        except (sqlite3.Error, OSError) as error:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error
        finally:
            connection.close()
        return {
            "schema": "guardian.siwe-challenge.v1",
            "challenge_id": challenge_id,
            "nonce": nonce,
            "session_id": session_id,
            "domain": domain,
            "uri": uri,
            "wallet": wallet,
            "chain_id": chain_id,
            "request_id": request_id,
            "binding_sha256": binding_sha256,
            "issued_at": now,
            "expires_at": expires_at,
        }

    def inspect_challenge(
        self,
        challenge_id,
        session_id,
        domain,
        uri,
        wallet,
        chain_id,
        request_id,
        binding_sha256,
        now,
    ):
        challenge_id = self._text(challenge_id, "SIWE_CHALLENGE_ID")
        now = self._time(now, "SIWE_CHALLENGE_TIME")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM challenges WHERE scope=? AND challenge_id=?",
                (self.scope, challenge_id),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise SecurityError("SIWE_CHALLENGE_UNSOLICITED")
            if row["state"] == "CONSUMED":
                connection.rollback()
                raise SecurityError("SIWE_CHALLENGE_DUPLICATE")
            if row["state"] == "EXPIRED" or now >= row["expires_at"]:
                connection.execute(
                    "UPDATE challenges SET state='EXPIRED' WHERE scope=? AND challenge_id=?",
                    (self.scope, challenge_id),
                )
                connection.commit()
                raise SecurityError("SIWE_CHALLENGE_EXPIRED")
            if now < row["issued_at"]:
                connection.rollback()
                raise SecurityError("SIWE_CHALLENGE_FUTURE")
            if row["session_id"] != session_id:
                connection.rollback()
                raise SecurityError("SIWE_CHALLENGE_CROSS_SESSION")
            expected = (
                row["domain"],
                row["uri"],
                row["wallet"],
                row["chain_id"],
                row["request_id"],
                row["binding_sha256"],
            )
            observed = (domain, uri, wallet.lower(), chain_id, request_id, binding_sha256)
            if observed != expected:
                connection.rollback()
                raise SecurityError("SIWE_CHALLENGE_BINDING")
            result = dict(row)
            connection.commit()
            return result
        except SecurityError:
            raise
        except (sqlite3.Error, OSError) as error:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error
        finally:
            connection.close()

    def consume_challenge(self, record, now):
        if type(record) is not dict:
            raise SecurityError("SIWE_CHALLENGE_RECORD")
        now = self._time(now, "SIWE_CHALLENGE_TIME")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE challenges SET state='CONSUMED', consumed_at=?
                WHERE scope=? AND challenge_id=? AND nonce=? AND session_id=?
                  AND binding_sha256=? AND state='ISSUED' AND expires_at>?
                """,
                (
                    now,
                    self.scope,
                    record.get("challenge_id"),
                    record.get("nonce"),
                    record.get("session_id"),
                    record.get("binding_sha256"),
                    now,
                ),
            )
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT state, expires_at FROM challenges WHERE scope=? AND challenge_id=?",
                    (self.scope, record.get("challenge_id")),
                ).fetchone()
                connection.rollback()
                if row is not None and (row["state"] == "CONSUMED"):
                    raise SecurityError("SIWE_CHALLENGE_DUPLICATE")
                if row is not None and (row["state"] == "EXPIRED" or now >= row["expires_at"]):
                    raise SecurityError("SIWE_CHALLENGE_EXPIRED")
                raise SecurityError("SIWE_CHALLENGE_ATOMIC_CONSUME")
            connection.commit()
        except SecurityError:
            raise
        except (sqlite3.Error, OSError) as error:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error
        finally:
            connection.close()

    def prepare_admission(
        self,
        grant_id,
        grant_sha256,
        binding_sha256,
        owner_session,
        attempt_id,
        now,
        expires_at,
    ):
        grant_id = self._text(grant_id, "GRANT_ID")
        grant_sha256 = self._text(grant_sha256, "GRANT_DIGEST", minimum=64, maximum=64)
        binding_sha256 = self._text(binding_sha256, "GRANT_REQUEST_BINDING", minimum=64, maximum=64)
        owner_session = self._text(owner_session, "ADMISSION_SESSION")
        attempt_id = self._text(attempt_id, "ADMISSION_ATTEMPT")
        now = self._time(now, "ADMISSION_TIME")
        expires_at = self._time(expires_at, "ADMISSION_TIME")
        if expires_at <= now:
            raise SecurityError("GRANT_TIME")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM admissions WHERE scope=? AND grant_id=?",
                (self.scope, grant_id),
            ).fetchone()
            if row is not None:
                if row["grant_sha256"] != grant_sha256 or row["binding_sha256"] != binding_sha256:
                    connection.rollback()
                    raise SecurityError("GRANT_ID_COLLISION")
                if row["state"] == "COMMITTED":
                    connection.rollback()
                    raise SecurityError("GRANT_REPLAY_COMMITTED")
                if row["state"] == "ABORTED":
                    connection.rollback()
                    raise SecurityError("GRANT_REPLAY_ABORTED")
                if row["state"] == "RECOVERY_REQUIRED":
                    connection.rollback()
                    raise SecurityError("GRANT_RECOVERY_REQUIRED")
                connection.rollback()
                raise SecurityError("GRANT_REPLAY_PREPARED")
            count = connection.execute(
                "SELECT COUNT(*) AS value FROM admissions WHERE scope=?",
                (self.scope,),
            ).fetchone()["value"]
            if count >= self.admission_capacity:
                connection.rollback()
                raise SecurityError("DURABLE_ADMISSION_FULL")
            connection.execute(
                """
                INSERT INTO admissions(
                    scope, grant_id, grant_sha256, binding_sha256, owner_session,
                    attempt_id, state, prepared_at, updated_at, expires_at,
                    outcome_sha256, exit_code
                ) VALUES(?,?,?,?,?,?, 'PREPARED', ?,?,?, NULL,NULL)
                """,
                (
                    self.scope,
                    grant_id,
                    grant_sha256,
                    binding_sha256,
                    owner_session,
                    attempt_id,
                    now,
                    now,
                    expires_at,
                ),
            )
            connection.commit()
            return {
                "scope": self.scope,
                "grant_id": grant_id,
                "attempt_id": attempt_id,
                "owner_session": owner_session,
                "state": "PREPARED",
            }
        except SecurityError:
            raise
        except (sqlite3.Error, OSError) as error:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error
        finally:
            connection.close()

    def _transition(self, claim, state, now, outcome_sha256=None, exit_code=None):
        if state not in {"COMMITTED", "ABORTED", "RECOVERY_REQUIRED"}:
            raise ValueError("state")
        now = self._time(now, "ADMISSION_TIME")
        if type(claim) is not dict:
            raise SecurityError("ADMISSION_CLAIM")
        if outcome_sha256 is not None:
            self._text(outcome_sha256, "ADMISSION_OUTCOME", minimum=64, maximum=64)
        if exit_code is not None and type(exit_code) is not int:
            raise SecurityError("ADMISSION_OUTCOME")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE admissions SET state=?, updated_at=?, outcome_sha256=?, exit_code=?
                WHERE scope=? AND grant_id=? AND attempt_id=? AND owner_session=? AND state='PREPARED'
                """,
                (
                    state,
                    now,
                    outcome_sha256,
                    exit_code,
                    self.scope,
                    claim.get("grant_id"),
                    claim.get("attempt_id"),
                    claim.get("owner_session"),
                ),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise SecurityError("DURABLE_STATE_TRANSITION")
            connection.commit()
        except SecurityError:
            raise
        except (sqlite3.Error, OSError) as error:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error
        finally:
            connection.close()

    def mark_committed(self, claim, now, outcome_sha256, exit_code):
        self._transition(claim, "COMMITTED", now, outcome_sha256, exit_code)

    def mark_aborted(self, claim, now, outcome_sha256):
        self._transition(claim, "ABORTED", now, outcome_sha256, None)

    def mark_recovery_required(self, claim, now, outcome_sha256=None):
        self._transition(claim, "RECOVERY_REQUIRED", now, outcome_sha256, None)

    def require_recovery(self, grant_id, grant_sha256, binding_sha256, now):
        """Explicitly classify a known-stopped PREPARED attempt; never infer death."""
        grant_id = self._text(grant_id, "GRANT_ID")
        grant_sha256 = self._text(grant_sha256, "GRANT_DIGEST", minimum=64, maximum=64)
        binding_sha256 = self._text(binding_sha256, "GRANT_REQUEST_BINDING", minimum=64, maximum=64)
        now = self._time(now, "ADMISSION_TIME")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE admissions SET state='RECOVERY_REQUIRED', updated_at=?
                WHERE scope=? AND grant_id=? AND grant_sha256=?
                  AND binding_sha256=? AND state='PREPARED'
                """,
                (now, self.scope, grant_id, grant_sha256, binding_sha256),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise SecurityError("DURABLE_STATE_TRANSITION")
            connection.commit()
        except SecurityError:
            raise
        except (sqlite3.Error, OSError) as error:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error
        finally:
            connection.close()

    def read_admission(self, grant_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM admissions WHERE scope=? AND grant_id=?",
                (self.scope, grant_id),
            ).fetchone()
            return None if row is None else dict(row)
        except (sqlite3.Error, OSError) as error:
            raise SecurityError("DURABLE_STATE_UNAVAILABLE") from error
        finally:
            connection.close()
