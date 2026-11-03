# CyberShield — Threat Detection and Incident Response

A full-stack security operations dashboard built with React, Express, and MongoDB. It ingests security events, applies defensive pattern-based detection rules, raises alerts, and supports incident investigation and reporting.

## Included modules
- JWT authentication, bcrypt password hashing, admin/analyst roles
- Dashboard metrics, 7-day event trend, alert severity distribution
- Security log ingestion, bulk ingestion API, search and event stream
- Rule-based detection for failed logins, SQL injection indicators, XSS indicators, and path traversal
- Alert triage, severity/risk score, MITRE ATT&CK technique labels, incident escalation
- Incident lifecycle, investigation notes, assignment-ready schema, resolution tracking
- Custom regex detection rules, enable/disable controls
- Synthetic event simulator (no external traffic or real attack)
- PDF report export and audit trail
- Helmet headers, API rate limiting on authentication, input size limit

## Requirements
- Node.js 18+
- MongoDB Community Server running locally, or a MongoDB connection string

## 1. Backend setup (macOS/Linux)
```bash
cd CyberShield-Complete/backend
cp .env.example .env
npm install
npm run seed
npm run dev
```
Backend: http://localhost:5001  
Health check: http://localhost:5001/api/health

Edit `.env` if your MongoDB URL, port, or frontend URL differs. Keep `JWT_SECRET` private and replace the example value before deployment.

## 2. Frontend setup (new terminal)
```bash
cd CyberShield-Complete/frontend
cp .env.example .env
npm install
npm run dev
```
Frontend: http://localhost:5173

## Demo administrator
- Email: `admin@cybershield.local`
- Password: `CyberShield@123`

Change this password before using the application beyond a local demo. Registration creates analyst accounts. Admin account is created by the seed script.

## Main workflow
1. Sign in.
2. Open **Threat Simulation** and run synthetic events.
3. Check **Security Logs** to see ingested events.
4. Check **Alerts** for rule matches and severity/risk scores.
5. Create an incident from an alert.
6. Track investigation status and add notes under **Incidents**.
7. Add a custom detection pattern under **Detection Rules**.
8. Export a PDF from **Reports** and review **Audit Trail**.

## API overview
- `POST /api/auth/login`, `POST /api/auth/register`, `GET /api/auth/me`
- `GET/POST /api/logs`, `POST /api/logs/bulk`, `DELETE /api/logs/:id`
- `GET /api/alerts`, `PATCH /api/alerts/:id`, `POST /api/alerts/:id/create-incident`
- `GET/POST /api/incidents`, `PATCH /api/incidents/:id`, `POST /api/incidents/:id/notes`
- `GET/POST /api/rules`, `PATCH/DELETE /api/rules/:id`
- `GET /api/analytics/summary`, `GET /api/analytics/audit`, `GET /api/analytics/users`
- `GET /api/reports/pdf`, `POST /api/simulation`

All routes except `/api/health`, `/api/auth/login`, and `/api/auth/register` require `Authorization: Bearer <token>`.

## Important scope and production hardening
This is an academic/demo SIEM-style project, not a production SOC or a replacement for Wazuh/Splunk. Detection is regex/rule-based and needs tuning against real telemetry. The included simulator generates synthetic records only. Before deployment: enforce HTTPS, rotate secrets, change demo credentials, add request validation and stronger authorization policies, configure backups, add retention controls, protect report exports, add pagination to all large collections, and run security tests. Do not ingest secrets or personal data into a demo instance.
