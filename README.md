# SOC Threat Simulation Trainer: Student Activity

A hands-on, fully **simulated** lab where you play both sides of an attack: first as the attacker walking a five-stage attack chain, then as the SOC analyst who detects it using **Splunk-style logs** and **Wireshark-style packet views**.

> **Safety notice:** Everything in this lab is mocked. All hosts use reserved documentation IP ranges (RFC 5737 / RFC 1918), all credentials are fake, and the app never opens a real network connection or runs a real exploit. Do not use these techniques against systems you do not own or have written permission to test.

| | |
|---|---|
| **Estimated time** | 90 to 120 minutes |
| **Difficulty** | Beginner to intermediate |
| **Skills** | Recon, web/config exposure, secret harvesting, lateral movement, log and packet correlation, true/false positive triage |
| **Deliverable** | Completed worksheet + screenshots (see [Submission](#submission-google-classroom)) |

---

## 1. Learning objectives

By the end of this activity you will be able to:

1. Explain how an attacker maps DNS, IP, ports and banners, and why an exposed origin server can bypass a WAF.
2. Describe how web/config flaws lead to a web shell or reverse shell.
3. Explain why exposed `.env` files and process environment variables create lateral-access risk, and how to secure secrets.
4. Describe lateral movement, pivoting and persistence across ports 3306, 6379, 445/139, 22, 3389, 23, 21 and 25.
5. Use Splunk-style queries and Wireshark display filters to confirm each stage, and decide whether an alert is a **true positive (TP)** or **false positive (FP)**.
6. Recommend and verify remediations.

---

## 2. Requirements

- **Python 3.8 or newer** (no extra packages needed, standard library only)
- A modern web browser (Chrome, Edge, Firefox)
- Optional: Git

Check Python:

```bash
python3 --version      # macOS / Linux
python --version       # Windows (or try: py --version)
```

---

## 3. Get the lab

**Option A: Clone with Git**

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

**Option B: Download ZIP**

1. Open the repository page on GitHub.
2. Click **Code**, then **Download ZIP**.
3. Extract the ZIP and open a terminal in the extracted folder.

> Instructor note: replace `<your-username>/<repo-name>` above with your real repository path before sharing.

---

## 4. Run the lab

```bash
python3 soc_trainer.py          # macOS / Linux
python soc_trainer.py           # Windows (or: py soc_trainer.py)
```

Your browser should open at **http://127.0.0.1:5050**. If it does not, open that address manually. Leave the terminal window running while you work; press `Ctrl+C` there to stop the lab.

| Situation | What to do |
|---|---|
| Port 5050 is busy | `python3 soc_trainer.py --port 7777`, then open `http://127.0.0.1:7777` |
| You also run Splunk locally | Splunk Web uses port 8000. This lab uses 5050 by default, so there is no clash. |
| Browser does not open or the server will not start | `python3 soc_trainer.py --export` creates a standalone `index.html`. Double-click it to open it in your browser. |
| You want to start over | Type `reset` in the lab terminal (or refresh the page) |

---

## 5. Know your workspace

The screen has three panels:

| Panel | Purpose |
|---|---|
| **Left: Training Guide** | Tabs for Phases 1 to 5. Each has the objective, learner steps, why the weakness exists, how defenders detect it, and remediation. |
| **Center: Terminal and Target Inspector** | Type simulated commands in **Terminal**. Use the **Target: index.html**, **Target: .env** and **Target: nginx.conf** tabs to inspect the vulnerable target. |
| **Right: SOC Telemetry** | **Splunk** (pick a query from the dropdown and click Run), **Wireshark** (type a display filter or click a chip), **Alerts** (automatic alerts with analyst actions). |

Helpful extras:

- The header shows a **THREAT LEVEL** badge and an **ALERTS** counter. They rise as you complete attack stages.
- **Pop-up alerts** appear at the top-right as you work. Click one to open the Alerts tab.
- Each alert card has **Splunk**, **Packets** and **Acknowledge** buttons. Splunk and Packets jump to the matching query or filter.
- Type `help` in the terminal for the command list, and `phase 1` to `phase 5` to switch guide tabs.

### Lab map (all simulated)

| Role | Address |
|---|---|
| Attacker (you) | `192.0.2.5` |
| Edge / WAF | `203.0.113.10` |
| Origin web server | `198.51.100.20` |
| Database (MySQL 3306) | `10.0.0.12` |
| Redis cache (6379) | `10.0.0.13` |
| File share (SMB 445) | `10.0.0.14` |
| Jump host (SSH 22) | `10.0.0.15` |
| Remote desktop (RDP 3389) | `10.0.0.16` |
| Mail server (SMTP 25) | `10.0.0.17` |

> **Order matters.** Later phases depend on earlier ones. You need a foothold (Phase 2) and harvested secrets (Phase 3) before you can move laterally (Phase 4). Work the phases in order.

---

## 6. The activity

Each phase has two parts: **Attack** (run commands in the terminal) and **Detect** (find the evidence in Splunk, Wireshark and Alerts). Write your answers in the worksheet (Section 7) as you go, and take the screenshots marked 📸.

### Phase 1: External Reconnaissance and Traffic Path Mapping (about 20 min)

**Goal:** Map the target's footprint and find a path that bypasses the WAF.

**Attack: run these in the terminal**

```text
nslookup shop.lab.test
nslookup direct.shop.lab.test
curl -I http://shop.lab.test/
curl -I http://198.51.100.20/
curl -I http://shop.lab.test/.env
nmap 203.0.113.10
nmap 198.51.100.20
nmap -sV 198.51.100.20
nmap -A 198.51.100.20
nmap -p 3306,6379 198.51.100.20
```

What to notice: the public name resolves to the WAF, a stale DNS record leaks the origin, the WAF blocks `/.env` but the origin answers directly, and the edge shows far fewer open ports than the origin.

**Detect**

- Splunk: run **Port scan detection (P1)**, **Suspicious DNS (P1)** and **WAF blocks / 403 (P1)**.
- Wireshark: apply `tcp.flags.syn==1 && tcp.flags.ack==0`, then `dns`, then `http.host==198.51.100.20`.
- Alerts tab: read the Phase 1 alerts and their triage tags.

📸 **Screenshot 1:** your `nmap -A 198.51.100.20` output. 📸 **Screenshot 2:** the SYN-scan filter result in Wireshark.

### Phase 2: Initial Access and Shell Simulation (about 20 min)

**Goal:** Turn a web/config flaw into a simulated web shell and reverse shell.

**Attack**

1. Open the **Target: index.html** and **Target: nginx.conf** tabs. Find the weaknesses (dev comments, debug flag, dotfiles served, PUT enabled).
2. In the terminal:

```text
curl -X PUT http://198.51.100.20/uploads/cmd.php
curl http://198.51.100.20/uploads/cmd.php?c=id
revshell
```

The first command simulates an insecure upload, the second a web shell (command passed in a URL parameter), and `revshell` a simulated callback from the server to `192.0.2.5:4444`. The terminal prompt changes once you hold a shell.

**Detect**

- Splunk: **Web exposure & upload (P2)** and **Shell / callback (P2)**.
- Wireshark: `http.request.method=="PUT"` and `tcp.port==4444`.
- Alerts tab: note which alerts are CRITICAL and why a web process spawning a shell is so suspicious.

📸 **Screenshot 3:** the CRITICAL alerts in the Alerts tab.

### Phase 3: Credential and Secret Harvesting (about 15 min)

**Goal:** See how `.env` files and environment variables hand an attacker valid credentials.

**Attack**

```text
ls
cat .env
printenv
curl http://198.51.100.20/.env
```

Also open the **Target: .env** tab and list which services each credential unlocks.

**Detect**

- Splunk: **Secret access (P3)**.
- Wireshark: `http.request.uri contains ".env"`.
- Alerts tab: find the `.env` alert and its MITRE technique ID.

📸 **Screenshot 4:** the `cat .env` output next to the Secret access Splunk result.

### Phase 4: Lateral Movement, Pivoting and Persistence (about 25 min)

**Goal:** Use the stolen secrets to move across services, persist and stage data.

**Attack**

```text
mysql -h 10.0.0.12 -u app_rw
redis-cli -h 10.0.0.13
smbclient //10.0.0.14/finance
ssh svc_deploy@10.0.0.15
xfreerdp /v:10.0.0.16
nc 10.0.0.17 25
persist
```

**Detect**

- Splunk: **Lateral movement (P4)**, **New SSH/RDP logons (P4)**, **Egress / staging SMTP (P4)** and **Persistence (P4)**.
- Wireshark: `tcp.port==3306 || tcp.port==6379 || tcp.port==445`, then `tcp.port==22 || tcp.port==3389`, then `tcp.port==25`.
- Watch the **THREAT LEVEL** badge reach CRITICAL and the incident alerts fire after stages 3, 5 and 7.

📸 **Screenshot 5:** the Lateral movement query result. 📸 **Screenshot 6:** the Alerts tab showing the full kill chain incident.

### Phase 5: SOC Validation and Remediation (about 20 min)

**Goal:** Correlate logs with packets, triage alerts as TP or FP, and verify a fix.

1. In Splunk, run **All events** and read the timeline from first scan to persistence.
2. For each stage, find the matching packets in Wireshark (use the filter chips) and confirm the timestamps line up.
3. Complete the TP/FP table in the worksheet. Hint: web-to-database traffic on 3306 is normal on its own, so what makes it suspicious here?
4. Click **Acknowledge** on the alerts you have triaged.
5. Open **Target: nginx.conf** and click **Apply remediation**, then re-run:

```text
nmap -A 198.51.100.20
curl http://198.51.100.20/.env
```

Confirm the origin is no longer exposed, then check the Alerts tab for the remediation entry.

📸 **Screenshot 7:** the nmap output after remediation.

---

## 7. Worksheet (answer in your own words)

**Phase 1**

1. Which IP did `shop.lab.test` resolve to, and which did `direct.shop.lab.test` resolve to? Why is the second one a problem?
2. List the open ports on the edge vs the origin. Which origin ports are most dangerous to expose, and why?
3. Which Wireshark filter reveals the scan, and what flag pattern does it match?

**Phase 2**

4. Which two misconfigurations made the foothold possible?
5. Explain the difference between a web shell and a reverse shell. Why can a reverse shell work when inbound ports are blocked?
6. Name two log or packet signs that a web server has been compromised.

**Phase 3**

7. List three secrets in `.env` and the service each one unlocks.
8. Why is reading `.env` often quieter than brute-forcing passwords?
9. Give three ways to protect secrets.

**Phase 4**

10. Which ports did you use to move laterally and what did each give you?
11. Why does a logon with valid credentials look like normal activity, and how can a SOC still spot it?
12. What does the `persist` step add, and how would you find and remove it?

**Phase 5: TP/FP triage**

| Alert / event | TP or FP? | Evidence in Splunk | Evidence in Wireshark | Action taken |
|---|---|---|---|---|
| Scan of the WAF edge | | | | |
| Scan of the origin | | | | |
| Web host connecting to MySQL (3306) | | | | |
| Outbound connection to port 4444 | | | | |
| SMTP (25) from the web host | | | | |

13. Write a short incident summary (4 to 6 sentences): what happened, in what order, what was exposed, and what you would do first to contain it.
14. List five remediations, one per attack stage, and say which one stopped the most attacks in the lab after you applied the fix.

---

## 8. Command and filter quick reference

**Terminal commands**

| Command | What it simulates |
|---|---|
| `nslookup <host>` | DNS lookup (`shop.lab.test`, `direct.shop.lab.test`) |
| `nmap [-sV] [-A] [-p N,N] <ip>` | Port, version and banner scan (targets: `203.0.113.10`, `198.51.100.20`) |
| `curl [-I] [-X PUT] <url>` | HTTP requests to the edge or origin |
| `revshell` | Simulated outbound callback to the lab listener |
| `ls`, `cat .env`, `cat index.html`, `printenv` (or `env`) | Shell and secret inspection |
| `mysql`, `redis-cli`, `smbclient`, `ssh`, `xfreerdp`, `nc <ip> 25` | Lateral movement and mail egress |
| `persist` | Mock scheduled-task persistence |
| `splunk` / `wireshark <filter>` | Jump to the telemetry views |
| `phase <1-5>`, `clear`, `reset`, `help` | Navigation and housekeeping |

**Wireshark display filters**

| Filter | Finds |
|---|---|
| `tcp.flags.syn==1 && tcp.flags.ack==0` | Scan probes (SYN without ACK) |
| `http.request.method=="PUT"` | The upload |
| `http.request.uri contains ".env"` | `.env` requests |
| `http.host==198.51.100.20` | Requests using the raw origin IP |
| `tcp.port==4444` | Reverse shell callback |
| `tcp.port==3306 \|\| tcp.port==6379` | Database and Redis sessions |
| `dns` | DNS lookups |

You can combine filters with `&&`, `||`, `!` (or `and`, `or`, `not`), parentheses, `==`, `!=` and `contains`. An invalid filter turns the box red.

---

## 9. Submission (Google Classroom)

Submit **one file** (PDF or Google Doc) containing:

1. Your name and date.
2. The seven screenshots (labeled with the phase).
3. Your completed worksheet answers (questions 1 to 14), including the TP/FP table.

**How to submit:** open the assignment in Google Classroom, click **Add or create**, attach your file, then click **Turn in**.

### Suggested grading rubric (instructor may edit, 100 points)

| Criteria | Points |
|---|---|
| All seven screenshots present and clearly labeled | 20 |
| Phase 1 to 4 worksheet answers accurate and complete | 40 |
| TP/FP triage table with correct evidence | 20 |
| Incident summary and remediation recommendations | 15 |
| Clear writing and professionalism | 5 |

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| `python3: command not found` | On Windows use `python` or `py`. Otherwise install Python 3 from python.org. |
| Another app opens (for example Splunk) | You are on the wrong port. Use `http://127.0.0.1:5050`, or pass `--port`. |
| "Address already in use" | Another program uses the port. Run with `--port 7777`. |
| Command says "no foothold" or "permission denied" | Finish Phase 2 (web shell or `revshell`) and Phase 3 (secrets) first. |
| Command says "Out of lab scope" | Only the lab addresses in Section 5 are valid targets. |
| No Wireshark rows | Run the matching attack command first, then apply the filter. |
| Something looks stuck | Type `reset` or refresh the page. |

---

## 11. Repository contents

```text
.
├── soc_trainer.py    # The lab (Python standard library only)
└── README.md         # This activity guide
```

*For education only. All systems, addresses and credentials are fictional.*
