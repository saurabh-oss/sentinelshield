"""
Run from host machine (requires: pip install requests)
Alternatively run inside container: docker compose exec sentinel-engine python -m scripts.demo_simulator
"""
import subprocess, sys
try:
    result = subprocess.run(
        ["docker", "compose", "exec", "sentinel-engine", "python", "-m", "scripts.demo_simulator"],
        cwd=".", capture_output=False
    )
    sys.exit(result.returncode)
except FileNotFoundError:
    print("Docker not found. Please run from the sentinelshield/ directory with Docker available.")
    sys.exit(1)
