"""Live SQLite action execution, one-use MFA evidence and protected file effects."""

import copy
import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from . import execution, oracle, policy


class Executor:
    """Application-owned current policy/action registry; no policy labels from clients."""

    def __init__(self, database, root, key, objects, pdp=None):
        self.database = str(database)
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.key = key
        self.objects = copy.deepcopy(objects)
        self.pdp = pdp or oracle.decision
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Executor key needs 32 bytes")
        for identifier, item in self.objects.items():
            if Path(identifier).name != identifier or any(
                char in identifier for char in ("/", "\\", ":")
            ):
                raise ValueError("Invalid object ID")
            self.path(item["path"])
        with self.connect() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1),public TEXT,actual TEXT);
            CREATE TABLE IF NOT EXISTS identity(principal TEXT PRIMARY KEY,attributes TEXT,mfa_until REAL);
            CREATE TABLE IF NOT EXISTS mfa(token TEXT PRIMARY KEY,principal TEXT,expires REAL,consumed INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS workflow(id TEXT PRIMARY KEY,principal TEXT,action TEXT,request TEXT,status TEXT);
            CREATE TABLE IF NOT EXISTS effects(id INTEGER PRIMARY KEY,principal TEXT,epoch TEXT,request TEXT,objects TEXT,committed_at REAL);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def path(self, name):
        result = (self.root / name).resolve()
        if not result.is_relative_to(self.root):
            raise PermissionError("Path escapes application root")
        return result

    def install(self, public, actual):
        """Trusted administrator installs an epoch and its actual confidential policy."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT public FROM config WHERE id=1").fetchone()
            if (
                row is not None
                and json.loads(row[0]).get("epoch") == public.get("epoch")
                and json.loads(row[0]) != public
            ):
                raise ValueError("Changed public metadata requires a new epoch")
            db.execute(
                "INSERT OR REPLACE INTO config VALUES(1,?,?)",
                (policy.encode(public), policy.encode(actual)),
            )
            db.commit()

    def set_identity(self, principal, attributes, mfa_until=0):
        """Trusted identity provider records private attributes and current factor validity."""
        if "principal" in attributes:
            raise ValueError("Principal is bound separately")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR REPLACE INTO identity VALUES(?,?,?)",
                (principal, policy.encode(attributes), mfa_until),
            )
            db.commit()

    def grant_mfa(self, principal, token, expires):
        """Trusted factor provider registers evidence; the caller must actually supply it."""
        if expires <= time.time():
            raise ValueError("MFA evidence already expired")
        with self.connect() as db:
            db.execute(
                "INSERT INTO mfa(token,principal,expires) VALUES(?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), principal, expires),
            )

    def execute(
        self, certificate, request, principal, evidence=None, destination="effects"
    ):
        evidence = evidence or {}
        if request.get("principal") != principal:
            raise PermissionError("Authenticated principal mismatch")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            config = db.execute("SELECT * FROM config WHERE id=1").fetchone()
            if config is None:
                raise RuntimeError("No installed policy epoch")
            public, actual = json.loads(config["public"]), json.loads(config["actual"])
            identity = db.execute(
                "SELECT * FROM identity WHERE principal=?", (principal,)
            ).fetchone()
            if identity is None:
                raise PermissionError("Unknown authenticated identity")
            attributes = json.loads(identity["attributes"])
            for name, value in attributes.items():
                if name in request and not policy.equal(request[name], value):
                    raise PermissionError(
                        "Request disagrees with trusted identity attributes"
                    )
            for name in public.get(
                "trusted_fields", ["tenant", "provenance", "rights"]
            ):
                if name in request and (
                    name not in attributes
                    or not policy.equal(request[name], attributes[name])
                ):
                    raise PermissionError("Untrusted identity field")
            for name, values in public.get("hidden_request_fields", {}).items():
                if name not in attributes or not any(
                    policy.equal(attributes[name], value) for value in values
                ):
                    raise PermissionError("Identity is outside declared public model")
            if request.get("mfa") is True and identity["mfa_until"] <= time.time():
                raise PermissionError("Current MFA session absent or expired")
            # Signature/bindings and independent robust feasibility precede every handler.
            decision = execution.authorize(
                certificate, public, request, actual, self.key, attributes
            )
            if decision["type"] != "EXECUTE":
                raise PermissionError(decision["type"])
            current = copy.deepcopy(request)
            for name in certificate["payload"]["sequence"]:
                primitive = public["actions"][name]
                if (
                    primitive.get("handler") == "mfa"
                    or primitive.get("set", {}).get("mfa") is True
                ):
                    supplied = evidence.get(name)
                    if not isinstance(supplied, str):
                        raise PermissionError("Actual MFA evidence required")
                    token = hashlib.sha256(supplied.encode()).hexdigest()
                    row = db.execute(
                        "SELECT * FROM mfa WHERE token=?", (token,)
                    ).fetchone()
                    if (
                        row is None
                        or row["principal"] != principal
                        or row["consumed"]
                        or row["expires"] <= time.time()
                    ):
                        raise PermissionError(
                            "Invalid, expired or consumed MFA evidence"
                        )
                    db.execute("UPDATE mfa SET consumed=1 WHERE token=?", (token,))
                current = oracle.projected_replay(public, current, [name])
                if current is None:
                    raise PermissionError("Primitive precondition changed")
            if policy.encode(current) != policy.encode(decision["request"]):
                raise PermissionError(
                    "Actual transformation differs from certified plan"
                )
            if self.pdp(actual, {**current, **attributes}) != "Permit":
                raise PermissionError("Current native PDP denies repaired request")
            requested = current.get("objects", list(self.objects))
            if not isinstance(requested, list) or any(
                type(name) is not str or name not in self.objects for name in requested
            ):
                raise PermissionError("Unknown protected object")
            selected = [
                name
                for name in requested
                if self.objects[name]["scope"]
                == current.get("scope", self.objects[name]["scope"])
            ]
            target = self.path(destination)
            target.mkdir(parents=True, exist_ok=True)
            for identifier in selected:
                concrete = {
                    **current,
                    **attributes,
                    "resource": identifier,
                    "scope": self.objects[identifier]["scope"],
                }
                if self.pdp(actual, concrete) != "Permit":
                    raise PermissionError("Current native PDP denies actual object")
                (target / (identifier + ".bin")).write_bytes(
                    self.path(self.objects[identifier]["path"]).read_bytes()
                )
            db.execute(
                "INSERT INTO effects(principal,epoch,request,objects,committed_at) VALUES(?,?,?,?,?)",
                (
                    principal,
                    policy.encode(public.get("epoch")),
                    policy.encode(current),
                    policy.encode(selected),
                    time.time(),
                ),
            )
            db.commit()
            return dict(type="COMMITTED", request=current, objects=selected)

    def process(self, principal, request, name):
        """Submit an actual pending workflow; it creates no access authorization."""
        if request.get("principal") != principal:
            raise PermissionError("Authenticated principal mismatch")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT public FROM config WHERE id=1").fetchone()
            public = json.loads(row[0])
            if (
                db.execute(
                    "SELECT principal FROM identity WHERE principal=?", (principal,)
                ).fetchone()
                is None
            ):
                raise PermissionError("Unknown authenticated identity")
            primitive = public.get("process_actions", {}).get(name)
            if primitive is None:
                raise PermissionError("Unknown public workflow")
            reviewed = {key: value for key, value in primitive.items() if key != "kind"}
            if oracle.replay(request, [name], {name: reviewed}) is None:
                raise PermissionError("Workflow precondition denied")
            identifier = secrets.token_hex(16)
            db.execute(
                "INSERT INTO workflow VALUES(?,?,?,?,?)",
                (identifier, principal, name, policy.encode(request), "PENDING"),
            )
            db.commit()
            return dict(type="PROCESS_SUBMITTED", id=identifier, status="PENDING")
