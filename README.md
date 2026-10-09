# UniSphere — HacXLerate 2026

A full-stack student success analytics prototype using FastAPI, SQLAlchemy, a persistent database, and a responsive green/beige glassmorphism frontend. It includes Student, Faculty, and Admin roles; a transparent score; explainable rule-based risk flags; segments; marks; attendance; inbox and replies; interventions; learning resources; private feedback; CSV/XLSX import; CSV reports; and audit logs.

## Windows / VS Code quick start

Install Python 3.11+ first. Open PowerShell in the extracted project folder. Use `py -m pip`, not bare `pip`:

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r backend/requirements.txt
py -m uvicorn backend.app.main:app --reload
```

If PowerShell says scripts are disabled, run this for the current terminal only: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again. If `py` is not recognized, install Python from https://www.python.org/downloads/windows/ and tick **Add python.exe to PATH**, then restart VS Code.

Open http://127.0.0.1:8000 and API docs at http://127.0.0.1:8000/docs.

## Demo logins

- Admin: `admin` / `Hope@50`
- Faculty: `faculty01` / `Faculty@123`
- Faculty: `faculty02` / `Faculty@123`
- Student: `STU1001` / `Student@123`
- Student: `STU1002` / `Student@123` (at-risk example)
- Student: `STU1003` / `Student@123`
- Student: `STU1004` / `Student@123`
- Student: `STU1005` / `Student@123` (high-risk example)
- Student: `STU1006` / `Student@123`

These are synthetic demo accounts only. Set a unique admin password and secret before deployment.

## Score methodology

Student Success Score = 30% academic performance (CGPA normalized to 0–100) + 20% attendance + 15% LMS/assignment activity (65% LMS and 35% assignment completion) + 10% engagement + 10% skills + 15% placement readiness. Risk is rule-based: high when score <50 or a critical condition applies (attendance <55%, internal marks <35, or 3+ backlogs); medium when score <70, attendance <75%, marks <50, or any backlog; otherwise low. Academic and placement risk are also separate. This is a transparent baseline, not a trained predictive model. Validate with institutional data before consequential decisions.

## Deploy to Render

1. Push the extracted project to a GitHub repository.
2. In Render, choose **New + → Blueprint** and connect the repository. Render reads `render.yaml`, creates the Docker web service and managed PostgreSQL database.
3. Set `UNISPHERE_ADMIN_PASSWORD` to a unique strong value in the service environment. Keep the generated `UNISPHERE_SECRET` secret.
4. Deploy and wait for `/api/health` to return `{"status":"ok",...}`.
5. Open the public URL, test all three roles, then change demo credentials or disable demo accounts before real use.

For deployment elsewhere, Dockerfile builds and runs the service. Set `DATABASE_URL` to a PostgreSQL connection string. PostgreSQL URL formats beginning `postgres://` are normalized by the app. Do not use ephemeral SQLite storage for multi-instance production.

## Security / honest limitations

- Passwords use PBKDF2-HMAC-SHA256 salted hashes; JWTs expire after 10 hours.
- Forgot-password is intentionally not enabled for resetting passwords until an SMS provider is configured; the endpoint does not leak OTPs. Integrate an SMS service before production.
- Student/faculty login accounts are not publicly self-registered; admins create them.
- The baseline is rule-based, not trained ML. Do not claim future outcomes are predicted by a validated model.
- File uploads are local to the service filesystem. On hosts with ephemeral disks, files can disappear on redeploy. For production resource persistence, configure object storage or a persistent disk.
- Before using real institutional data: use HTTPS, strict CORS, backups, rate limiting, monitoring, institution-approved privacy controls, and a security review. Rotate demo credentials.
- Student data import expects stable student IDs; new imported accounts receive temporary password `ChangeMe123!`, which must be changed before real use.

## Verification performed on this package

- Python backend source compiles successfully.
- Frontend JavaScript passes Node syntax checking.
- FastAPI starts locally; `/api/health` returns `status: ok`.
- Admin login with the configured demo credentials returned a token in a local smoke test.

A public deployment has not been created from this workspace because it requires your GitHub/hosting account and its deployment permissions. Follow the Render Blueprint steps above to publish it.
