#!/usr/bin/env python3
"""Network-event source for the Network tab when the eBPF agent is not running.

WHAT THIS IS
    The real collector is the Go agent in `linux/ebpf` (bpf/netmon.c, the
    `sock:inet_sock_set_state` tracepoint). It needs CAP_BPF, so it needs root.
    This script produces the *same* contract-shaped `NetworkEvent` stream that
    the agent would produce, so the Topology API, the topology graph and the
    dashboard are demonstrable on a machine where the agent cannot be loaded.

    It is NOT a substitute for the agent and must not be presented as one: it
    synthesises events, it does not read the kernel. Every event it emits obeys
    contracts section 6 exactly (it is validated against the pydantic models
    before it is sent), but the events are inferred, not observed.

WHAT MAKES IT USEFUL FOR THE DEMO
    It reads real state instead of looping blindly:
      * the current load profile from loadgen  -> connection rate matches the traffic
      * each service's /health                  -> a service that is down turns the
                                                  edge into it into CONNECT_FAILED
      * each service's latency_p95_ms           -> CLOSE durations grow when you
                                                  inject a latency fault
    So "stop payments" shows up as ECONNREFUSED on orders->payments within a
    second, and an 800 ms payments fault visibly lengthens those connections.

USAGE
    python3 netmon_sim.py                  # env: TOPOLOGY_URL, SERVICES, METRICS_URL
    docker compose --profile netmon-sim up netmon-sim
"""
from __future__ import annotations

import json
import os
import random
import re
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOPOLOGY_URL = os.getenv("TOPOLOGY_URL", "http://localhost:9003").rstrip("/")
METRICS_URL = os.getenv("METRICS_URL", "http://localhost:9001").rstrip("/")
# Works both in the container (REGISTRY_PATH=/app/contracts/registry.yaml) and from a
# checkout, where the default has to be found relative to this file, not the cwd.
REGISTRY = os.getenv("REGISTRY_PATH") or next(
    (p for p in ("contracts/registry.yaml",
                 str(Path(__file__).resolve().parent.parent / "darsan" / "contracts" / "registry.yaml"))
     if Path(p).exists()),
    "contracts/registry.yaml")
TICK = float(os.getenv("TICK_SECONDS", "0.2"))
BATCH = int(os.getenv("BATCH_SIZE", "200"))
URL_FMT = os.getenv("SERVICE_URL_FMT", "http://{name}:{port}")
SEED = int(os.getenv("SIM_SEED", "7"))

# Contract section 6: only these fields exist, and Base forbids extras. There is
# deliberately no "synthetic" flag -- provenance is documented in demo/DEMO.md
# rather than smuggled into the payload.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "darsan" / "contracts" / "python"))
    from minidd_contracts.models import NetworkEvent, NetworkEventBatch  # noqa: E402
    HAVE_CONTRACTS = True
except Exception:  # running without the contracts package: shape is still correct
    HAVE_CONTRACTS = False


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def http_json(url: str, timeout: float = 2.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


class Sim:
    def __init__(self) -> None:
        rnd = random.Random(SEED)
        self.rnd = rnd
        self.host = socket.gethostname()
        self.services = self.load_registry()
        self.down: set[str] = set()
        self.p95: dict[str, float] = {}
        self.rps = 5.0
        self.pids = {s["name"]: rnd.randint(1000, 9999) for s in self.services}
        # chain edges, resolved to real container IPs via compose DNS
        self.edges: list[tuple[str, str]] = []
        for s in self.services:
            ip = self.resolve(s["name"])
            s["ip"] = ip
            for dep in s["depends_on"]:
                if any(d["name"] == dep for d in self.services):
                    self.edges.append((s["name"], dep))
        self.pending_close: list[tuple[float, dict]] = []
        self.running = True

    # ---------- topology from the real registry ----------
    def load_registry(self) -> list[dict]:
        """Parse contracts/registry.yaml. Each service is one YAML flow mapping, e.g.

            - {name: orders, port: 8001, kind: service, description: "Order management",
               depends_on: [payments]}

        so depends_on has to be read as a bracketed list, not by splitting on commas
        (the description field contains commas and quotes too).
        """
        def field(line: str, key: str) -> str:
            m = re.search(rf"\b{key}\s*:\s*(\[[^\]]*\]|\"[^\"]*\"|[^,}}]+)", line)
            return m.group(1).strip() if m else ""

        out = []
        for line in Path(REGISTRY).read_text().splitlines():
            line = line.strip()
            if not line.startswith("- ") or "name:" not in line:
                continue
            name = field(line, "name").strip()
            if not name:
                continue
            dep_raw = field(line, "depends_on")
            deps = [d.strip().strip("\"'") for d in dep_raw.strip("[]").split(",") if d.strip()]
            out.append({
                "name": name,
                "port": int(field(line, "port") or 0),
                "kind": field(line, "kind") or "service",
                "depends_on": deps,
            })
        return out

    @staticmethod
    def resolve(name: str) -> str:
        try:
            return socket.gethostbyname(name)
        except Exception:
            return "127.0.0.1"

    def svc(self, name: str) -> dict:
        return next(s for s in self.services if s["name"] == name)

    # ---------- read real state ----------
    def poll(self) -> None:
        prof = http_json(URL_FMT.format(name="loadgen", port=8010) + "/profile")
        if prof and prof.get("rps"):
            self.rps = float(prof["rps"]) if prof.get("profile") != "stop" else 0.0

        snaps = http_json(METRICS_URL + "/api/v1/metrics/latest")
        if snaps:
            for snap in snaps:
                v = (snap.get("values") or {}).get("latency_p95_ms")
                if v is not None:
                    self.p95[snap["service"]] = float(v)

        for s in self.services:
            up = http_json(URL_FMT.format(name=s["name"], port=s["port"]) + "/health") is not None
            if up:
                self.down.discard(s["name"])
            else:
                self.down.add(s["name"])

    # ---------- event construction ----------
    def event(self, typ: str, src: str, dst: str, duration: float | None = None,
              error: str | None = None) -> dict:
        s, d = self.svc(src), self.svc(dst)
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": now_iso(),
            "host": self.host,
            "event_type": typ,
            "protocol": "tcp",
            "src_ip": s["ip"],
            "src_port": self.rnd.randint(32768, 60999),
            "dst_ip": d["ip"],
            "dst_port": d["port"],
            "src_service": src,
            "dst_service": dst,
            "pid": self.pids[src],
            "process_name": "python",
            "duration_ms": duration,
            "error": error,
        }

    def hop_latency_ms(self, dst: str) -> float:
        """How long this hop should look like it took, from the real p95 numbers."""
        base = self.p95.get(dst)
        if base is None:
            base = 20.0
        return max(2.0, self.rnd.gauss(base, max(1.0, base * 0.12)))

    def tick_once(self) -> list[dict]:
        now = time.monotonic()
        out: list[dict] = []

        # close anything whose modelled connection lifetime has elapsed. The
        # duration reported is the modelled hop latency (derived from the real
        # latency_p95_ms), not the wall-clock time to the next tick -- otherwise
        # every fast hop would be quantised up to the 200 ms tick interval.
        still: list[tuple[float, dict]] = []
        for due, meta in self.pending_close:
            if due <= now:
                out.append(self.event("CLOSE", meta["src"], meta["dst"],
                                      duration=round(meta["ms"], 1)))
            else:
                still.append((due, meta))
        self.pending_close = still

        if self.rps <= 0:
            return out

        # one connection per hop per request, matching HTTP_KEEPALIVE=false
        expected = self.rps * TICK
        n = int(expected) + (1 if self.rnd.random() < (expected % 1) else 0)
        for _ in range(n):
            for src, dst in self.edges:
                if dst in self.down:
                    out.append(self.event("CONNECT_FAILED", src, dst, error="ECONNREFUSED"))
                    continue
                if src in self.down:
                    continue
                out.append(self.event("CONNECT", src, dst))
                ms = self.hop_latency_ms(dst)
                self.pending_close.append(
                    (now + ms / 1000.0, {"src": src, "dst": dst, "ms": ms})
                )
        return out

    # ---------- shipping ----------
    def send(self, events: list[dict]) -> None:
        if not events:
            return
        for i in range(0, len(events), BATCH):
            batch = events[i:i + BATCH]
            if HAVE_CONTRACTS:
                batch = NetworkEventBatch(events=[NetworkEvent(**e) for e in batch]).model_dump(mode="json")["events"]
            body = json.dumps({"events": batch}).encode()
            req = urllib.request.Request(
                TOPOLOGY_URL + "/api/v1/network-events", data=body,
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=3) as r:
                    r.read()
            except urllib.error.HTTPError as e:
                print(f"topology-api rejected a batch: HTTP {e.code} {e.read()[:200]!r}", flush=True)
            except Exception as e:
                print(f"topology-api unreachable: {e}", flush=True)

    def run(self) -> None:
        print(f"netmon-sim -> {TOPOLOGY_URL}  host={self.host}  contracts={'on' if HAVE_CONTRACTS else 'off'}", flush=True)
        print("edges: " + ", ".join(f"{a}->{b}" for a, b in self.edges), flush=True)
        print("SYNTHETIC events (the eBPF agent needs root; see demo/DEMO.md)", flush=True)
        buffer: list[dict] = []
        last_poll = 0.0
        while self.running:
            now = time.monotonic()
            if now - last_poll >= 1.0:
                self.poll()
                last_poll = now
            buffer.extend(self.tick_once())
            if len(buffer) >= BATCH:
                self.send(buffer)
                buffer = []
            time.sleep(TICK)
        self.send(buffer)
        print("netmon-sim stopped", flush=True)


if __name__ == "__main__":
    import signal

    sim = Sim()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: setattr(sim, "running", False))
    sim.run()
# shjj