# Running Mailwarden on Windows (local only, no server)

This runs entirely on your own machine. Nothing is hosted, nothing is exposed to the
network — the report viewer only listens on `127.0.0.1` (your own computer), and no
Workspace credentials or scan data leave your PC unless you share the files yourself.

Two ways to go: the **one-click script** (easiest) or the **manual commands** (if you
want to see exactly what's happening, or you're scripting this into something else).

---

## Option A — one-click script

### Step 1: Install Python

1. Go to **https://www.python.org/downloads/** and download Python 3.11 or newer.
2. Run the installer. On the first screen, **tick "Add python.exe to PATH"** before
   clicking Install — this is the step people usually miss.
3. Open a new **Command Prompt** (search "cmd" in the Start menu) and check it worked:
   ```
   py --version
   ```
   You should see `Python 3.11.x` or higher.

### Step 2: Get the Mailwarden folder onto your PC

Unzip `mailwarden.zip` anywhere you like, e.g. `C:\Users\you\mailwarden`.

### Step 3: Add your domains

Open the `mailwarden` folder in File Explorer. The first run will create a
`my-audit\domains.txt` file for you — but if you want to add your list now, create
`my-audit\domains.txt` yourself with one domain per line:

```
yourcompany.com
yourothersite.com
clientdomain.com
```

Only list domains you're authorized to assess.

### Step 4: Run it

Double-click **`scan.bat`** inside the `mailwarden` folder.

First run, it will:
- create a Python virtual environment (`.venv`) — a self-contained copy of the
  dependencies, kept inside the folder so it never touches the rest of your system
- install Mailwarden into it
- if `my-audit\domains.txt` doesn't exist yet, create example input files and stop,
  so you can edit the domain list

Edit `my-audit\domains.txt`, save it, then double-click `scan.bat` again. This time it
scans every domain in the list and opens the report in your default browser
automatically.

To view a report again later without re-scanning, double-click **`serve.bat`**.

### Want to know if your SMTP relay is open to any IP? Double-click **`probe.bat`**

`scan.bat` can only *screen* the relay from public DNS (it shows "Needs evidence"). To get a
real verdict without Admin-console access, double-click **`probe.bat`**. It actively tests
`smtp-relay.gmail.com`, but **only for domains you've marked authorized** in
`my-audit\authorization.json`, makes an unauthenticated connection, and **stops before sending
anything** (no mail is delivered). Results appear on the *SMTP relay exploitability* tab and as a
"Relay probe" chip under each domain.

To authorize your whole list in one step instead of hand-editing JSON, double-click
**`authorize.bat`**. It shows the domains from `my-audit\domains.txt`, asks you to type **YES** to
confirm you own them or are permitted to test them, and writes the authorization file. Then
double-click `probe.bat`.

So the fully click-driven flow is:

1. Put your domains in `my-audit\domains.txt` (one per line).
2. Double-click **`authorize.bat`** → type **YES**.
3. Double-click **`probe.bat`** (from an IP outside your sending ranges).

(Prefer a terminal? `mailwarden authorize --from my-audit\domains.txt --approved-ips <your/CIDR>`
does the same, with extra options like `--approved-ips` and `--expires-on`.)

> Run `probe.bat` from an internet connection whose IP is **not** in your own sending ranges
> (a home/mobile hotspot or a cloud VM). From inside an allowed range the "any IP" result can't
> be trusted — the tool warns you when it detects this.

---

## Option B — manual commands (PowerShell or Command Prompt)

Same result as Option A, run by hand so you can see each step.

```bat
:: 1. Open the mailwarden folder
cd C:\Users\you\mailwarden

:: 2. Create a virtual environment (first time only)
py -3 -m venv .venv

:: 3. Activate it — do this every time you open a new terminal
.venv\Scripts\activate
:: PowerShell instead: .venv\Scripts\Activate.ps1
:: your prompt should now start with "(.venv)"

:: 4. Install Mailwarden and its dependencies (first time only)
pip install -e ".[dev]"

:: 5. Check everything is set up correctly
mailwarden doctor

:: 6. See a sample report immediately — no domains needed, no network calls
mailwarden demo --serve

:: 7. Write example input files, or skip if you already made my-audit\domains.txt
mailwarden init my-audit

:: 8. Edit my-audit\domains.txt in Notepad — one domain per line
notepad my-audit\domains.txt

:: 9. Scan every domain in the list (public DNS checks only — no credentials needed)
mailwarden scan --domains my-audit\domains.txt --mode dns --output mailwarden-output

:: 10. View the report (opens your browser)
mailwarden serve --dir mailwarden-output
```

### PowerShell's execution-policy error

If step 3 fails in PowerShell with a message about "running scripts is disabled",
run this once (per-user, doesn't need admin rights):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then retry `.venv\Scripts\Activate.ps1`.

---

## What `--mode dns` actually checks

For a plain domain list, `--mode dns` is all you need. It reads each domain's public
DNS records only — SPF, DKIM, DMARC, MX, DNSSEC — and needs:
- no Google Workspace login
- no admin access
- no authorization file
- no credentials of any kind

It works for any domain, including ones you don't administer (though you should only
be assessing domains you're authorized to look at).

`workspace` and `full` modes go further (Workspace audit logs, SMTP relay settings)
and need an authorization file plus Google credentials — see the main `README.md` if
you want that later. You don't need it to scan a plain domain list.

---

## Where your results go

Everything stays inside the `mailwarden` folder:

| File | What it is |
|---|---|
| `mailwarden-output\summary.html` | The report — open it directly in any browser if you don't want to use `serve.bat`. Near the top it has two tabs: *Spoofing & bulk sending* and *SMTP relay exploitability* |
| `mailwarden-output\findings.csv` | One row per finding, for a spreadsheet |
| `mailwarden-output\spoofing_risk.csv` | One row per domain: could mail be forged *claiming* to be from it (weak SPF/DMARC) |
| `mailwarden-output\relay_exploit.csv` | One row per domain: could its Google SMTP relay (`smtp-relay.gmail.com`) be used to send from any IP (no IP range restriction) |
| `mailwarden-output\findings.json` | Full structured results |
| `mailwarden-output\raw\` | Saved per-domain results (used by `mailwarden report` to rebuild reports later without rescanning) |

To scan again later, just double-click `scan.bat` — it reuses the same `.venv` and
re-installs nothing, so after the first run it's fast.

## Re-running on a schedule (optional)

To scan automatically, e.g. every Monday morning:

1. Press `Win + R`, type `taskschd.msc`, press Enter (Task Scheduler).
2. **Create Basic Task** → name it "Mailwarden weekly scan" → set the weekly trigger.
3. Action: **Start a program** → Program/script: browse to `scan.bat` inside your
   mailwarden folder.
4. Finish. Windows will now run the scan on that schedule, same as double-clicking it.

## Troubleshooting

| Problem | Fix |
|---|---|
| `'py' is not recognized...` | Python isn't on PATH. Reinstall Python and tick "Add python.exe to PATH". |
| `scan.bat` flashes and closes immediately | Open Command Prompt, `cd` into the folder, and run `scan.bat` from there instead of double-clicking — the error will stay on screen. |
| Antivirus flags or blocks `.venv\Scripts\python.exe` | False positive some AV tools raise for any new venv. Add the `mailwarden` folder to your AV's exclusions, or run Option B manually instead of the .bat files. |
| Browser doesn't open automatically | Open `mailwarden-output\summary.html` directly from File Explorer — it's a normal file, no server needed to view it. |
| A domain's findings all say "not assessed" | Usually a network/DNS resolution issue (corporate VPN, firewall blocking DNS). Try from a different network, or check `mailwarden doctor`. |
| `pip install` fails with a compiler error | Some dependency needs a newer pip. Run `python -m pip install --upgrade pip` first, then retry `pip install -e ".[dev]"`. |
| `'mailwarden' is not recognized...` right after "Writing example input files" | The install step was skipped or failed. Run `.venv\Scripts\activate` then `pip install -e ".[dev]"` by hand and read the actual error it prints, then run `mailwarden init my-audit` again. |
| Colored output shows as raw text like `←[34m==>←[0m` | Your console doesn't support ANSI colour. This is fixed from v0.2.1 onward — colour is only used when the console actually confirms it supports it, otherwise plain text is printed instead. If you still see this, update to the latest `mailwarden.zip`. |
| Lots of `warning existence check failed: LifetimeTimeout resolving SOA ...` for domains you know are real and working | DNS queries are timing out — usually a slow/filtered network, a VPN, or antivirus/firewall intercepting DNS, not those domains actually being broken. Those domains come back "not assessed" (honest, not wrong) rather than a false "clean" result. From v0.2.2, `my-audit\mailwarden.toml` (created by `mailwarden init`) already sets a longer timeout and explicit public resolvers, and `scan.bat` uses it automatically — so this should no longer happen for most people. If it still does: <br>1. Check `my-audit\mailwarden.toml` exists and `scan.bat` printed no error about it. <br>2. Try an even longer timeout: edit the `timeout = 8.0` line in that file to `15.0`. <br>3. Test whether it's Windows-wide, not just this tool: run `nslookup yourdomain.com 1.1.1.1` in Command Prompt. If that also hangs, something (antivirus, corporate firewall, VPN) is blocking outbound DNS for everything, not just Mailwarden. |
| `warning ... NoNameservers resolving SOA ...` (not "LifetimeTimeout") for a few specific domains | Different from a timeout: the resolver got an actual *error* response for that domain, usually because the domain's own DNS delegation is broken or misconfigured — not something on your end. Those domains correctly show up as "not assessed". Nothing to fix on your side for this one. |
| Scan seems to hang for a long time on a big domain list, so you press Ctrl+C (shows `interrupted`) | `interrupted` just means it was stopped, not that it crashed. From v0.2.3, domains are checked several at once instead of one at a time, and a `X/Y domains checked` counter prints as it works, so a 137-domain scan now takes roughly 1–2 minutes instead of 10+. If you want it faster or slower, add `--dns-workers N` (default 8) to the scan command — higher finishes sooner, lower is gentler on your network. |

## Uninstalling

Delete the `mailwarden` folder. Nothing is installed outside it — the virtual
environment, dependencies, and all scan output live inside `.venv` and
`mailwarden-output`, both inside that one folder.
