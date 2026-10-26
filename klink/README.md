# KLINK v2 - پنل کنترل کامل، تطابق گواهی TLS و لوله‌کشی نامرئی (Pipe Architecture)

در نسخه دوم (**KLINK v2**)، صفر تا صد تمام تنظیمات پروتکل، تغییر سایت داخلی (آپارات، آنتن، تلوبیون، فیلیمو یا هر سایت دلخواه)، بازرسی و تحویل گواهی TLS واقعی سایت داخلی، و تنظیم لوله‌کشی به سرور خارج (Upstream Tunnel) **مستقیماً از داخل پنل وب و بدون نیاز به ریستارت یا دست زدن به ترمینال** انجام می‌شود.

همچنین تمام دستورات اجرایی در فایل `COMMANDS.txt` در ریشه این پوشه قرار داده شده است.

---

## نصب تک‌خطی از گیت‌هاب (ریپوزیتوری Labo)
```bash
git clone https://github.com/kankiturk8770/Labo.git && cd Labo/klink && sudo bash install.sh
```

یا نصب مستقیم با curl (کل ریپو کلون می‌شود و از زیرپوشه klink ساخته می‌شود):
```bash
curl -fsSL https://raw.githubusercontent.com/kankiturk8770/Labo/ccr-dc42377d-5ky57p/klink/install.sh | sudo KLINK_REPO_URL="https://github.com/kankiturk8770/Labo.git" bash
```
