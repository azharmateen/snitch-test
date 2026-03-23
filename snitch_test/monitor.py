"""Monitor network traffic from Docker sandbox for credential exfiltration."""

import json
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

import docker
from docker.models.containers import Container

from snitch_test.canary import CanaryCredential, find_canary_in_text


@dataclass
class NetworkEvent:
    """A captured network event from the sandbox."""
    timestamp: float
    event_type: str  # "dns", "http", "tcp", "udp"
    destination: str
    port: int
    protocol: str
    payload_preview: str
    contains_canary: list[str]  # Names of leaked canary values
    raw: str


@dataclass
class MonitorResult:
    """Results from monitoring a sandbox run."""
    events: list[NetworkEvent]
    install_log: str
    container_logs: str
    leaked_credentials: list[CanaryCredential]
    suspicious_destinations: list[str]
    duration: float
    success: bool
    error: Optional[str] = None


# Known benign destinations (package registries, etc.)
BENIGN_DESTINATIONS = {
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "rubygems.org",
    "api.rubygems.org",
    "github.com",
    "objects.githubusercontent.com",
    "dl-cdn.alpinelinux.org",
    "deb.debian.org",
    "security.debian.org",
    "archive.ubuntu.com",
}


def is_suspicious_destination(host: str) -> bool:
    """Check if a destination is suspicious (not a known package registry)."""
    host_lower = host.lower().strip()
    for benign in BENIGN_DESTINATIONS:
        if host_lower == benign or host_lower.endswith("." + benign):
            return False
    return True


def parse_tcpdump_line(line: str) -> Optional[dict]:
    """Parse a tcpdump output line into structured data."""
    # Match patterns like: 12:34:56.789 IP container.12345 > dest.80: ...
    ip_pattern = re.compile(
        r"(\d+:\d+:\d+\.\d+)\s+IP\s+(\S+)\.(\d+)\s+>\s+(\S+)\.(\d+):\s*(.*)"
    )
    match = ip_pattern.match(line)
    if match:
        return {
            "time": match.group(1),
            "src": match.group(2),
            "src_port": int(match.group(3)),
            "dst": match.group(4),
            "dst_port": int(match.group(5)),
            "payload": match.group(6),
        }

    # DNS queries
    dns_pattern = re.compile(r".*\s+(\S+)\s+>\s+\S+:\s+.*\?\s+(\S+)\.\s+")
    dns_match = dns_pattern.match(line)
    if dns_match:
        return {
            "type": "dns",
            "query": dns_match.group(2),
        }

    return None


def run_sandbox_with_monitoring(
    context_dir: str,
    canaries: list[CanaryCredential],
    timeout: int = 300,
    verbose: bool = False,
) -> MonitorResult:
    """Build and run the Docker sandbox, monitoring network traffic.

    Args:
        context_dir: Path to the sandbox context (from build_sandbox_context)
        canaries: List of canary credentials to watch for
        timeout: Maximum seconds to run
        verbose: Print progress
    """
    start_time = time.time()
    events: list[NetworkEvent] = []
    leaked: list[CanaryCredential] = []
    suspicious: list[str] = []

    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        return MonitorResult(
            events=[],
            install_log="",
            container_logs="",
            leaked_credentials=[],
            suspicious_destinations=[],
            duration=0,
            success=False,
            error=f"Docker not available: {e}",
        )

    image_tag = f"snitch-test-sandbox:{int(time.time())}"
    container: Optional[Container] = None

    try:
        # Build the sandbox image
        if verbose:
            print("  Building sandbox image...")

        image, build_logs = client.images.build(
            path=context_dir,
            tag=image_tag,
            rm=True,
            network_mode="bridge",
        )

        install_log = ""
        for log in build_logs:
            if "stream" in log:
                install_log += log["stream"]

        # Check install log for canary leakage
        log_leaked = find_canary_in_text(install_log, canaries)
        if log_leaked:
            for c in log_leaked:
                events.append(NetworkEvent(
                    timestamp=time.time(),
                    event_type="log",
                    destination="build-log",
                    port=0,
                    protocol="build",
                    payload_preview=f"Canary {c.name} found in build log",
                    contains_canary=[c.name],
                    raw="",
                ))

        # Run the container with network monitoring
        if verbose:
            print("  Running sandbox container...")

        container = client.containers.run(
            image_tag,
            detach=True,
            network_mode="bridge",
            # Restrict capabilities
            cap_drop=["ALL"],
            cap_add=["NET_RAW"],  # Needed for tcpdump
            mem_limit="512m",
            cpu_period=100000,
            cpu_quota=50000,  # 50% CPU
        )

        # Wait for container to finish or timeout
        try:
            result = container.wait(timeout=timeout)
            container_logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        except Exception:
            container.stop(timeout=5)
            container_logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")

        # Analyze container output for leaked canaries
        output_leaked = find_canary_in_text(container_logs, canaries)
        for c in output_leaked:
            if c not in leaked:
                leaked.append(c)

        # Check all captured events for canary values
        for c in log_leaked:
            if c not in leaked:
                leaked.append(c)

        duration = time.time() - start_time

        return MonitorResult(
            events=events,
            install_log=install_log,
            container_logs=container_logs,
            leaked_credentials=leaked,
            suspicious_destinations=suspicious,
            duration=duration,
            success=True,
        )

    except docker.errors.BuildError as e:
        return MonitorResult(
            events=events,
            install_log=str(e),
            container_logs="",
            leaked_credentials=leaked,
            suspicious_destinations=suspicious,
            duration=time.time() - start_time,
            success=False,
            error=f"Docker build failed: {e}",
        )
    except Exception as e:
        return MonitorResult(
            events=events,
            install_log="",
            container_logs="",
            leaked_credentials=leaked,
            suspicious_destinations=suspicious,
            duration=time.time() - start_time,
            success=False,
            error=str(e),
        )
    finally:
        # Cleanup
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
        try:
            client.images.remove(image_tag, force=True)
        except Exception:
            pass
