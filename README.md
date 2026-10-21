# ARYAN HOST — Flask starter

Mobile-friendly Flask hosting dashboard with registration, login, Python-file uploads, per-file Start/Stop/Restart controls, and logs.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="replace-with-a-long-random-secret"
python app.py
```

Open http://127.0.0.1:5000. On Windows PowerShell, set the secret with `$env:SECRET_KEY="your-long-random-secret"`.

## Deploy to Railway

1. Upload these project files to a **private** GitHub repository.
2. Create a Railway project from that repository.
3. Set Start Command to `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120` (or use the included Procfile).
4. Set `SECRET_KEY` to a long random value in Railway Variables.
5. Attach a persistent volume and set `DATA_DIR` to its mount path if you need account/file data to survive redeploys. SQLite and uploads are otherwise local ephemeral data on many hosts.
6. Keep `RUNNER_ENABLED=0` unless you understand the execution risks below.

## Important security limitation

**This starter is not a secure public multi-user code-hosting platform.** A Python file can read environment variables, access the network, consume CPU/RAM, or modify files available to the process. `RUNNER_ENABLED` defaults to `0`. Enabling it is only suitable for private/local testing with trusted uploads. Before allowing arbitrary public users to run bots, move each process into a real isolated container/VM with no secrets, restricted network, CPU/memory/process/time limits, non-root user, and separate filesystem; add CSRF protection, rate limiting, monitoring, and persistent storage. Do not put API keys or credentials in source code or uploaded bot files.

Only `.py` uploads are enabled in this initial version; ZIP extraction is intentionally omitted to avoid unsafe archive extraction. Passwords are stored as Werkzeug password hashes, not plaintext.
