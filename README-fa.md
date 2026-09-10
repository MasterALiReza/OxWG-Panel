<div dir="rtl" align="right">

<div align="center">

# 🔐 OxWG Panel

**پنل مدیریت حرفه‌ای WireGuard**

[![نسخه](https://img.shields.io/badge/نسخه-1.1.0-blue?style=flat-square)](https://github.com/MasterALiReza/OxWG-Panel/releases)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen?style=flat-square&logo=python)](https://python.org)
[![لایسنس](https://img.shields.io/github/license/MasterALiReza/OxWG-Panel?style=flat-square)](LICENSE)
[![ستاره‌ها](https://img.shields.io/github/stars/MasterALiReza/OxWG-Panel?style=flat-square)](https://github.com/MasterALiReza/OxWG-Panel/stargazers)

<p>
  <a href="#-امکانات">امکانات</a> •
  <a href="#-نصب-سریع">نصب سریع</a> •
  <a href="#-اسکرین‌شات">اسکرین‌شات</a> •
  <a href="#-تنظیمات">تنظیمات</a> •
  <a href="#-ربات-تلگرام">ربات تلگرام</a>
</p>

---

</div>

## ✨ امکانات

<details open>
<summary><strong>📊 داشبورد و مانیتورینگ</strong></summary>
<br>

- **داشبورد کامل** برای مشاهده وضعیت لحظه‌ای سرور و پنل
- نمایش زنده مصرف **CPU**، **RAM**، **Disk** و **Network**
- اطلاعات کامل رابط‌های WireGuard
- سیستم **HTTP Security Monitor** برای شناسایی درخواست‌های مشکوک
- قابلیت Block خودکار IP مهاجم با مدت زمان قابل تنظیم

</details>

---

<details open>
<summary><strong>👥 مدیریت Peer</strong></summary>
<br>

- ایجاد، ویرایش، حذف، فعال/غیرفعال کردن Peer
- **ایجاد گروهی** (Bulk Create)
- دانلود Config، نمایش QR Code و Short Link
- پشتیبانی از **محدودیت حجم** و **محدودیت زمانی**
- گزینه «شروع تایمر از اولین اتصال» و کلاینت‌های **نامحدود**
- افزودن شماره تلفن و آیدی تلگرام به هر Peer
- تنظیمات پیشرفته: DNS، MTU، Keepalive، Allowed IPs، Endpoint

</details>

---

<details open>
<summary><strong>🌐 مدیریت Interface</strong></summary>
<br>

- ایجاد، فعال/غیرفعال، حذف Interface
- تنظیم DNS، MTU و Listen Port برای هر Interface
- پیکربندی خودکار WireGuard، قوانین **Forward** و **NAT** هنگام ایجاد Interface
- تعیین **Endpoint پیش‌فرض** برای هر Interface (تشخیص خودکار یا دستی)
- اعمال Endpoint جدید روی Peerهای موجود با کنترل کامل

</details>

---

<details open>
<summary><strong>📦 سیستم Subscription</strong></summary>
<br>

- ساخت **اشتراک چند‌موقعیتی**: یک کلاینت، چند Config از چند سرور مختلف
- استفاده از Peerهای موجود یا ایجاد Peer جدید به‌صورت خودکار
- **صفحه عمومی Subscription** برای هر کلاینت شامل:
  - وضعیت، حجم باقی‌مانده، زمان باقی‌مانده
  - دانلود Config، نمایش QR Code
  - لینک‌های پشتیبانی (تلگرام، واتساپ، اینستاگرام و ...)
- **Subscription Template Studio** با پیش‌نمایش زنده Desktop و Mobile
- شخصی‌سازی کامل: رنگ، پس‌زمینه، انیمیشن، فونت، چیدمان و ...
- پشتیبانی از **Dark Mode**، **Light Mode** و **Auto Mode**

</details>

---

<details open>
<summary><strong>🖧 مدیریت Node</strong></summary>
<br>

- مدیریت چندین سرور Node از یک پنل مرکزی
- احراز هویت با **API Key** اختصاصی برای هر Node
- نمایش وضعیت: **Online / Offline / Disabled**
- مشاهده تعداد Peer و Interface هر Node
- مدیریت Peerها و Interfaceهای Node **بدون نیاز به ورود مستقیم به سرور**

</details>

---

<details open>
<summary><strong>🚦 کنترل ترافیک</strong></summary>
<br>

- تعریف **Policy اختصاصی** برای هر Peer با استفاده از `nftables`
- بلاک کردن بر اساس **دامنه**، **IP/CIDR** یا **کشور (Geo Blocking)**
- اعمال Policy روی Peerهای Local و Node به‌صورت خودکار
- ابزار **Policy Check** و **Test Destination** برای تست قوانین فعال
- نمایش تعداد پکت و حجم ترافیک مسدودشده برای هر Policy

</details>

---

<details open>
<summary><strong>💾 بکاپ و ریستور</strong></summary>
<br>

- **بکاپ کامل** از پایگاه داده، تنظیمات، Subscription‌ها، Interface‌ها، Peer‌ها و Config‌های WireGuard
- بکاپ **دستی** و **خودکار** با ارسال به تلگرام
- بررسی محتوای بکاپ قبل از ریستور
- حالت‌های مختلف ریستور: **Auto**، **Full**، **Database**
- قابل استفاده برای **انتقال کامل پنل** به سرور جدید

</details>

---

<details open>
<summary><strong>🤖 ربات تلگرام</strong></summary>
<br>

- مدیریت Peerهای Local و Node از طریق تلگرام
- جستجو، ایجاد، ویرایش، فعال/غیرفعال، ریست، حذف Peer
- دریافت Config و QR Code در تلگرام
- مدیریت Profile‌ها، بکاپ و ریستور
- دریافت اعلان برای رویدادهای پنل و Node
- پشتیبانی از **چند Admin** به‌صورت همزمان

</details>

---

<details open>
<summary><strong>🔒 امنیت</strong></summary>
<br>

- ورود Admin با **احراز هویت دو مرحله‌ای (2FA / TOTP)**
- نمایش QR Code، کلید دستی و Recovery Code برای 2FA
- پشتیبانی از **HTTPS** با دامنه و گواهی اختصاصی
- ریدایرکت خودکار HTTP به HTTPS و **HSTS**
- تعریف CIDR مورد اعتماد برای جلوگیری از بلاک شدن ادمین
- حالت **Monitor Only** یا **Monitor + Block** برای درخواست‌های مشکوک

</details>

---

<details open>
<summary><strong>📋 لاگ‌ها و تنظیمات</strong></summary>
<br>

- لاگ کامل برای پنل، ربات تلگرام، ادمین تلگرام و Interface‌ها
- جستجو، فیلتر، انتخاب سطح لاگ، رفرش خودکار و اکسپورت CSV/NDJSON
- تغییر Port، Worker، Thread، Timeout و ریستارت پنل از داخل UI
- سیستم **Profile** برای ذخیره و استفاده مجدد تنظیمات Peer و Subscription

</details>

---

## 🚀 نصب سریع

### نصب پنل

روی سرور لینوکس (Debian / Ubuntu) دستور زیر را اجرا کنید:

```bash
sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/MasterALiReza/OxWG-Panel/main/wg.sh)"'
```

بعد از نصب، با دستور زیر اسکریپت را اجرا کنید:

```bash
wgpanel
```

---

### نصب Node

برای نصب روی سرورهای Node:

```bash
sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/MasterALiReza/OxWG-Panel/main/agent/node.sh)"'
```

بعد از نصب:

```bash
node
```

---

## ⚙️ تنظیمات

### Endpoint پیش‌فرض Interface

آدرس Endpoint سرور که داخل Config کلاینت نوشته می‌شود، به‌صورت خودکار از Domain یا Public IP پنل تشخیص داده می‌شود.

اگر پنل پشت NAT، Reverse Proxy یا Load Balancer باشد، می‌توانید برای هر Interface یک Endpoint دستی تعیین کنید:

| فیلد | توضیح | مثال |
|------|-------|------|
| **Host** | دامنه یا IP سرور | `vpn.example.com` یا `203.0.113.9` |
| **Port** | پورت UDP وایرگارد همان Interface | `51820` |

> با خالی کردن Host و Port، تشخیص خودکار دوباره فعال می‌شود.

---

### Fixed Client Endpoint

این گزینه را **برای اکثر کاربران خالی بگذارید** (موبایل، لپ‌تاپ، CGNAT، IP متغیر).

فقط برای کلاینت‌هایی استفاده کنید که **IP عمومی ثابت** دارند:

```
client.example.com:51820
```

> ⚠️ استفاده اشتباه می‌تواند باعث قطع اتصال کلاینت شود.

---

## 📸 اسکرین‌شات

<details>
<summary>📊 داشبورد</summary>

![داشبورد](https://github.com/user-attachments/assets/db92ea88-3b63-4bab-a2f6-5705200799d4)

</details>

<details>
<summary>👥 مدیریت Peerها</summary>

![Peers](https://github.com/user-attachments/assets/903ace8d-88a6-4e88-be49-4c30d7a82f98)

</details>

<details>
<summary>📦 Subscription</summary>

![Subscription](https://github.com/user-attachments/assets/e0a23cda-d94a-4c66-a47a-a20f043b8f0f)

</details>

<details>
<summary>📋 لاگ‌ها</summary>

![Logs](https://github.com/user-attachments/assets/afc5b0dc-068f-4b9c-b287-d90b7e838881)

</details>

<details>
<summary>💾 بکاپ</summary>

![Backup](https://github.com/user-attachments/assets/611cf337-4703-4c2c-987d-e6104b45f51f)

</details>

<details>
<summary>⚙️ تنظیمات تلگرام</summary>

![Settings Telegram](https://github.com/user-attachments/assets/bc528b71-9225-49f2-aa48-1ec14c56d8db)

</details>

<details>
<summary>🎨 Template Studio</summary>

![Template Studio](https://github.com/user-attachments/assets/b2bfc186-ba26-4c5f-b78d-a9889e168060)

</details>

---

## 🧩 تکنولوژی‌های استفاده شده

| لایه | تکنولوژی |
|------|----------|
| Backend | Python 3.10+، Flask، SQLAlchemy |
| احراز هویت | Flask-Login، TOTP 2FA، bcrypt |
| شبکه | WireGuard، nftables، iproute2 |
| ربات | python-telegram-bot ≥ 22.5 |
| سرور | Gunicorn، systemd |
| پایگاه داده | SQLite / MySQL |
| امنیت | Flask-WTF (CSRF)، Flask-Limiter، cryptography |

---

## 📄 لایسنس

این پروژه تحت [لایسنس GPL-3.0](LICENSE) منتشر شده است.

---

<div align="center">

ساخته شده با ❤️ &nbsp;·&nbsp; [GitHub](https://github.com/MasterALiReza/OxWG-Panel) &nbsp;·&nbsp; [گزارش مشکل](https://github.com/MasterALiReza/OxWG-Panel/issues)

</div>

</div>
