<div align="center">

# 🔐 OxWG Panel

**A modern, full-featured WireGuard management panel**

[![Version](https://img.shields.io/badge/version-1.1.0-blue?style=flat-square)](https://github.com/MasterALiReza/OxWG-Panel/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-latest-lightgrey?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/github/license/MasterALiReza/OxWG-Panel?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/MasterALiReza/OxWG-Panel?style=flat-square)](https://github.com/MasterALiReza/OxWG-Panel/stargazers)

<p>
  <a href="#-features">Features</a> •
  <a href="#-quick-install">Quick Install</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-configuration">Configuration</a> •
  <a href="#-telegram-bot">Telegram Bot</a> •
  <a href="README-fa.md">🇮🇷 فارسی</a>
</p>

---

</div>

## ✨ Features

<details open>
<summary><strong>📊 Dashboard & Monitoring</strong></summary>

- Full **Dashboard** for real-time server and panel status
- Live monitoring of **CPU**, **RAM**, **Disk**, **Network** and WireGuard stats
- HTTP Security Monitor to detect and block suspicious requests
- Temporary IP blocking with configurable duration (minutes / hours / days)

</details>

<details open>
<summary><strong>👥 Peer Management</strong></summary>

- Full peer management: **Create**, **Bulk Create**, **Edit**, **Enable/Disable**, **Delete**
- **Reset usage**, **Reset timer**, **QR Code**, **Config download**, **Short Link**, **Logs**
- Support for **Data Limit**, **Time Limit**, **Start timer on first use**, and **Unlimited** clients
- Display **data remaining**, **time remaining**, and **client status** in subscription page
- Add phone number and **Telegram ID** to peers
- **Advanced WireGuard options**: DNS, MTU, Keepalive, Allowed IPs, Server Endpoint, Fixed Client Endpoint

</details>

<details open>
<summary><strong>🌐 Interface Management</strong></summary>

- Create, enable/disable, delete WireGuard interfaces
- Configure DNS, MTU, Listen Port per interface
- Auto-configure WireGuard settings, **Forward** and **NAT** rules on interface creation
- Set a **default Endpoint** per interface (auto-detected from domain/IP, overridable)
- Apply new endpoint to existing peers with optional overwrite control

</details>

<details open>
<summary><strong>📦 Subscription System</strong></summary>

- **Multi-location subscriptions**: one client, multiple configs from local/node interfaces
- Use existing peers or auto-create new peers for selected interfaces
- **Public Subscription Page** per client: status, data/time remaining, configs, QR Code, download, support
- Download configs individually or as a full subscription bundle
- **Subscription Template Studio** with Live Preview (Desktop + Mobile)
- Per-user template customization: Layout, Background, Live Background, Animation, Motion, Colors, Surface, Radius, Shadow, Density, Font scale, Page width
- Configure columns, section order, and visibility (Usage, Configs, Install WireGuard, Support)
- Customizable Header, Title, Subtitle, Logo, Alignment
- Support links: Telegram, WhatsApp, Phone, Email, Website, Instagram
- **Dark / Light / Auto** mode support

</details>

<details open>
<summary><strong>🖧 Node Management</strong></summary>

- Manage multiple remote nodes from the main panel
- Per-node **API Key** authentication
- Node status: **Online / Offline / Disabled**
- View peer and interface counts, search, filter, refresh, test connection
- Manage node peers and interfaces **without logging into the node server**

</details>

<details open>
<summary><strong>🚦 Traffic Control</strong></summary>

- Per-peer **Traffic Policy** using `nftables`
- Block by **Domain**, **IP/CIDR**, or **Country (Geo Blocking)**
- Applies to both Local and Node peers; rules managed automatically
- **Policy Check** and **Test Destination** tools to verify active rules
- Per-policy **packet and traffic counters** with auto-humanized sizes (B → KiB → GiB → TiB)

</details>

<details open>
<summary><strong>💾 Backup & Restore</strong></summary>

- Full **Backup & Restore** of database, settings, subscriptions, short links, profiles, interfaces, peers, and WireGuard configs (local + node)
- **Manual** and **Auto Backup** with Telegram delivery
- Inspect backup before restoring; restore modes: **Auto**, **Full**, **Database**
- Use Full Backup to migrate panel and nodes to a new server

</details>

<details open>
<summary><strong>🤖 Telegram Bot & Admin</strong></summary>

- Manage local/node peers: Search, Create, Edit, Enable/Disable, Reset, Delete
- Receive config and QR Code via Telegram
- Manage profiles, backup, restore
- Receive notifications for panel/node events
- Multi-admin support

</details>

<details open>
<summary><strong>🔒 Security</strong></summary>

- Admin login with **2FA (TOTP)** — QR Code, Manual Key, Recovery Codes
- HTTPS support with custom domain, certificate, and private key
- HTTP → HTTPS redirect + **HSTS**
- Trusted CIDR whitelist to prevent accidental self-block
- Monitor-only or **Monitor + Block** mode for suspicious requests

</details>

<details open>
<summary><strong>📋 Logs & Settings</strong></summary>

- Full logs for Panel, Telegram Bot, Telegram Admin, and Interfaces
- Search, filter, log level selector, auto-refresh, local time, humanized output, export to CSV/NDJSON
- Configure Port, Worker, Thread, Timeout, and restart panel from within the UI
- Profile system for peers and subscriptions: save, apply, edit, delete, set default

</details>

---

## 🚀 Quick Install

### Panel Installation

```bash
sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/MasterALiReza/OxWG-Panel/main/wg.sh)"'
```

Then run the panel script anytime with:

```bash
wgpanel
```

---

### Node Installation

```bash
sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/MasterALiReza/OxWG-Panel/main/agent/node.sh)"'
```

Then run:

```bash
node
```

---

## ⚙️ Configuration

### Default Endpoint per Interface

The server endpoint written into client configs is auto-detected from the panel's domain or public IP.

If the panel is behind NAT, a Reverse Proxy, or a Load Balancer — or the server has multiple public IPs — you can set a **custom default endpoint** per interface:

| Setting | Description |
|--------|-------------|
| Host | Domain (e.g. `vpn.example.com`) or IP (e.g. `203.0.113.9`) |
| Port | The WireGuard UDP port of that interface (e.g. `51820`) |

> Clearing Host and Port re-enables automatic endpoint detection.
> Use **Apply to existing peers** to update previously created configs.

---

### Fixed Client Endpoint

Leave this blank for most users (mobile, laptop, CGNAT, dynamic IP).
Use only for clients with a **static public IP or DNS**.

```
client.example.com:51820
```

> ⚠️ Incorrect use of Fixed Client Endpoint may cause connection loss.

---

## 📸 Screenshots

<details>
<summary>📊 Dashboard</summary>

![Dashboard](https://github.com/user-attachments/assets/db92ea88-3b63-4bab-a2f6-5705200799d4)

</details>

<details>
<summary>👥 Peers</summary>

![Peers](https://github.com/user-attachments/assets/903ace8d-88a6-4e88-be49-4c30d7a82f98)

</details>

<details>
<summary>📦 Subscription</summary>

![Subscription](https://github.com/user-attachments/assets/e0a23cda-d94a-4c66-a47a-a20f043b8f0f)

</details>

<details>
<summary>📋 Logs</summary>

![Logs](https://github.com/user-attachments/assets/afc5b0dc-068f-4b9c-b287-d90b7e838881)

</details>

<details>
<summary>💾 Backup</summary>

![Backup](https://github.com/user-attachments/assets/611cf337-4703-4c2c-987d-e6104b45f51f)

</details>

<details>
<summary>⚙️ Settings — Telegram</summary>

![Settings Telegram](https://github.com/user-attachments/assets/bc528b71-9225-49f2-aa48-1ec14c56d8db)

</details>

<details>
<summary>🎨 Template Studio</summary>

![Template Studio](https://github.com/user-attachments/assets/b2bfc186-ba26-4c5f-b78d-a9889e168060)

</details>

---

## 🧩 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10+, Flask, SQLAlchemy |
| Auth | Flask-Login, TOTP 2FA, bcrypt |
| Network | WireGuard, nftables, iproute2 |
| Bot | python-telegram-bot ≥ 22.5 |
| Server | Gunicorn, systemd |
| Database | SQLite / MySQL (PyMySQL) |
| Security | Flask-WTF (CSRF), Flask-Limiter, cryptography |

---

## 📄 License

This project is licensed under the [GPL-3.0 License](LICENSE).

---

<div align="center">

Made with ❤️ · [GitHub](https://github.com/MasterALiReza/OxWG-Panel) · [Report an Issue](https://github.com/MasterALiReza/OxWG-Panel/issues) · [🇮🇷 نسخه فارسی](README-fa.md)

</div>
