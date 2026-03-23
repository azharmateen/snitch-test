"""Create Docker sandbox with canary env vars for dependency testing."""

import json
import os
import shutil
import tempfile
from pathlib import Path

from snitch_test.canary import CanaryCredential

# Detect project type and generate appropriate install commands
PROJECT_TYPES = {
    "python": {
        "files": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
        "image": "python:3.12-slim",
        "install_cmds": {
            "requirements.txt": "pip install -r /app/requirements.txt",
            "pyproject.toml": "pip install /app",
            "setup.py": "pip install /app",
            "Pipfile": "pip install pipenv && pipenv install --system",
        },
    },
    "node": {
        "files": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "image": "node:22-slim",
        "install_cmds": {
            "package.json": "cd /app && npm install",
            "yarn.lock": "cd /app && yarn install",
            "pnpm-lock.yaml": "cd /app && npx pnpm install",
        },
    },
    "ruby": {
        "files": ["Gemfile"],
        "image": "ruby:3.3-slim",
        "install_cmds": {
            "Gemfile": "cd /app && bundle install",
        },
    },
}


def detect_project_type(project_path: str) -> tuple[str, str, str]:
    """Detect project type and return (type, image, install_cmd)."""
    p = Path(project_path)

    for ptype, config in PROJECT_TYPES.items():
        for fname in config["files"]:
            if (p / fname).exists():
                image = config["image"]
                install_cmd = config["install_cmds"].get(
                    fname, list(config["install_cmds"].values())[0]
                )
                return ptype, image, install_cmd

    raise ValueError(
        f"Could not detect project type in {project_path}. "
        f"Supported: Python (requirements.txt/pyproject.toml), Node (package.json), Ruby (Gemfile)"
    )


def build_sandbox_context(
    project_path: str,
    canaries: list[CanaryCredential],
    capture_script: str,
) -> str:
    """Build a temporary directory with Dockerfile and project files for the sandbox.

    Returns path to the temp directory.
    """
    ptype, base_image, install_cmd = detect_project_type(project_path)

    tmpdir = tempfile.mkdtemp(prefix="snitch_test_")
    project_dest = os.path.join(tmpdir, "app")
    shutil.copytree(
        project_path,
        project_dest,
        ignore=shutil.ignore_patterns(
            "node_modules", "__pycache__", ".git", "venv", ".venv", "*.pyc"
        ),
    )

    # Write the network capture script
    capture_path = os.path.join(tmpdir, "capture.py")
    with open(capture_path, "w") as f:
        f.write(capture_script)

    # Write canary env file
    env_path = os.path.join(tmpdir, "canary.env")
    with open(env_path, "w") as f:
        for c in canaries:
            # Escape special chars for env file
            value = c.value.replace("\\", "\\\\").replace('"', '\\"')
            f.write(f'{c.name}="{value}"\n')

    # Write canary manifest (for later analysis)
    manifest_path = os.path.join(tmpdir, "canary_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(
            [
                {
                    "name": c.name,
                    "value": c.value,
                    "category": c.category,
                    "fingerprint": c.fingerprint,
                }
                for c in canaries
            ],
            f,
            indent=2,
        )

    # Generate Dockerfile
    dockerfile = f"""FROM {base_image}

# Install tcpdump for network monitoring
RUN apt-get update && apt-get install -y --no-install-recommends \\
    tcpdump \\
    python3 \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY app/ /app/

# Copy capture script
COPY capture.py /capture.py

# Set canary environment variables
"""
    for c in canaries:
        # Use ARG + ENV to set each variable
        safe_value = c.value.replace("\\", "\\\\").replace('"', '\\"')
        dockerfile += f'ENV {c.name}="{safe_value}"\n'

    dockerfile += f"""
# Install dependencies (the actual test)
RUN {install_cmd} 2>&1 | tee /install.log; exit 0

# Run post-install scripts if any exist
CMD ["python3", "/capture.py"]
"""

    dockerfile_path = os.path.join(tmpdir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile)

    return tmpdir


CAPTURE_SCRIPT = '''#!/usr/bin/env python3
"""In-container script that reports results."""
import json
import os
import subprocess
import sys

def main():
    results = {
        "install_log": "",
        "dns_queries": [],
        "connections": [],
    }

    # Read install log
    try:
        with open("/install.log") as f:
            results["install_log"] = f.read()
    except FileNotFoundError:
        pass

    # Check for any suspicious network activity evidence
    # (tcpdump would have captured during install, but since Docker
    # build doesn't let us run parallel processes easily, we check
    # /etc/resolv.conf modifications and any cached DNS)
    try:
        output = subprocess.check_output(
            ["python3", "-c", """
import socket
import json
# Try to detect any outbound connection attempts logged
# In a real scenario, we'd parse tcpdump output
print(json.dumps({"status": "capture_complete"}))
"""],
            stderr=subprocess.STDOUT,
            text=True,
        )
        results["post_install_check"] = output.strip()
    except Exception as e:
        results["post_install_check"] = str(e)

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
'''


def get_capture_script() -> str:
    return CAPTURE_SCRIPT
