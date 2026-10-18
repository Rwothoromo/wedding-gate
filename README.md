# Elijah & Blessed — gate check-in

A small web app for the ushers on 12 December 2026. Ushers sign in with a gate PIN, scan the QR on an invitation (or type the code under it, or find the guest by name), and admit up to the number the card allows. Every usher's phone shares one live record, so a card that has already been used is flagged at once.

- `guests.json` — the 453 cards: number, name on the card, admits, and a SHA-256 of each invitation code (the codes themselves aren't stored).
- `server.js` — the app (Node + Postgres).
- `public/index.html` — the usher screen.
- `render.yaml` — Render blueprint: one web service and one Postgres database.

## Deploy on Render
1. Push this repo to GitHub (keep it private).
2. In Render: **New → Blueprint**, pick the `wedding-gate` repo, and apply.
3. When asked, set `GATE_PIN` (for ushers) and `ADMIN_PIN` (for you: adds the arrivals CSV export).
4. Open the service's `.onrender.com` link on a phone and sign in.

Notes:
- Free web services sleep when idle; the first visit after a while takes up to a minute to wake. Open the link before the gates open, or use a paid instance on the day.
- Check Render's current free-database limits: historically a free database expires after about 30 days, so create it close to the date or use a paid plan for the event.
- After the event, sign in with the admin PIN and use **Download the arrivals list (CSV)**.

## Updating the guest list
Regenerate `guests.json` from the card generator's `door-list.csv`, commit and push; Render redeploys. Check-ins already recorded are kept.

## Run locally
```
npm install
DATABASE_URL=postgres://... GATE_PIN=1234 ADMIN_PIN=9999 SESSION_SECRET=anything node server.js
```
