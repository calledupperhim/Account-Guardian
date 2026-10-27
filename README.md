# 🛡️ Account Guardian

A local, open-source (MIT) tool that scans your inbox for **security-alert emails** ("new sign-in", "new device", "password changed"), extracts the IP / device / location, and helps you lock down any account you don't recognise.

- Python 3.9+ standard library only. No `pip install`.
- Runs on `127.0.0.1` only. Mailbox is opened **read-only**; your app password stays in memory.
- Only the IP address is sent to a third party (ip-api.com) for geolocation.

## Run (double-click)
- **Windows:** double-click `Start Account Guardian.bat` (needs free Python from python.org, tick "Add to PATH").
- **Mac:** double-click `Start Account Guardian.command` (first time: right-click > Open).
- **Linux:** `./start.sh`

Your browser opens at http://127.0.0.1:8765. Close the black window to stop it.

## Standalone .exe / .app (no Python needed)
Push this repo to GitHub, then Actions > "Build apps" > Run workflow. It builds Windows, Mac and Linux downloads automatically.

## Get an app password
Gmail/Yahoo/iCloud block normal passwords over IMAP. Turn on 2-step verification, create an **app password**, and enable IMAP. Outlook/Hotmail may require an app password too. Proton needs Proton Bridge.

## What it does
1. Finds sign-in alerts and shows service, time, IP, city/country, ISP, device, and a VPN/datacenter flag.
2. Lists accounts linked to your email (from welcome/verification/alert emails).
3. **It was me** dismisses an alert. **Not me** shows a checklist with that service's sessions page, security page and report links.

## Limits (by design)
- No website lets a third-party app remotely end sessions, so "kick" opens the service's own sign-out page.
- IP location is city-level at best, and VPNs distort it.
- Only services that email you alerts show up; it can't see accounts that never emailed you.
- Alerts in Spam/other folders are not scanned (yet).

## Ideas for contributors
Scan more folders, add more services to `SERVICES`, HaveIBeenPwned breach check, offline GeoIP database.

MIT licensed.
