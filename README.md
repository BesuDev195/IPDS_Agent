# IPDS_Agent: Linux Security Agent for AI-Based IDS/IPS

An independent, modular, installable Linux Security Agent written in Python 3.11+.

See [linux-agent/README.md](linux-agent/README.md) for full architecture and usage documentation.

### Quick Test Execution
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r linux-agent/requirements.txt
PYTHONPATH=linux-agent pytest linux-agent/tests
```
