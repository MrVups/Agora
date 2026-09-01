# Sub-Aggregator

سرویس تجمیع‌کننده‌ی لینک ساب‌اسکریپشن، نوشته‌شده به Go، برای کار در کنار
پنل Sanaei/3x-ui. کانفیگ‌های چند لینک مادر را دریافت، پالایش، ضدتکراری و
کش می‌کند و بر اساس اینباند هر کاربر، آن‌ها را به لینک ساب‌اسکریپشن شخصی‌اش
اضافه می‌کند.

## ویژگی‌ها
- پالایش خودکار کانفیگ‌های تبلیغاتی/فیک و حذف تکراری‌ها
- فیلتر per-inbound (هر کاربر فقط کانفیگ‌های مخصوص اینباند خودش یا `all` را می‌بیند)
- کش کامل در SQLite — کاربران هیچ‌وقت باعث فراخوانی زنده‌ی لینک‌های مادر نمی‌شوند
- خواندن خودکار مسیر/پورت/دامنه‌ی ساب‌اسکریپشن از تنظیمات x-ui (سازگار با تغییرات آینده در پنل)
- کنسول مدیریت وب با احراز هویت bcrypt، گروه‌بندی لینک‌ها بر اساس اینباند، و تقویم شمسی
- ارتباط با آپاچی از طریق Unix Socket (هرگز با پورت‌های اینباند x-ui تداخل پیدا نمی‌کند)
- سینک زمان‌بندی‌شده‌ی اینباند دسته‌بندی‌های ربات میرزا در MySQL (با query پارامتری، بدون SQL injection)

## نصب سریع (روی یک VPS اوبونتو با x-ui از قبل نصب‌شده)

```bash
curl -fsSL https://raw.githubusercontent.com/MrVups/Agora/main/install.sh | sudo bash
```

این دستور باینری آماده را از GitHub Releases دانلود می‌کند — نیازی به نصب Go روی سرور مقصد نیست.


### نصب سریع واقعی

پس از ایجاد اولین Release، فقط همین یک دستور کافی است:

```bash
curl -fsSL https://raw.githubusercontent.com/MrVups/Agora/main/install.sh | sudo bash
```

این bootstrap اسکریپت `panel-manager.sh` را می‌گیرد و Full Install را با باینری آماده‌ی GitHub Release اجرا می‌کند؛ کاربر روی سرور لازم نیست Go یا GCC نصب کند.

> این پروژه برای نصب خودکار، سرور Ubuntu/Debian با systemd و Apache را هدف می‌گیرد. برای PasarGuard نیز Docker/`.env` موجود باید در مسیر قابل تشخیص باشد.

## نصب دستی / بیلد از سورس

اگر می‌خواهید خودتان بیلد کنید (نیاز به Go 1.22+):

```bash
git clone https://github.com/MrVups/Agora.git
cd Agora
go mod download
go build -o sub_aggregator_go_bin main.go
sudo mkdir -p /opt/sub_aggregator
sudo cp sub_aggregator_go_bin /opt/sub_aggregator/
sudo cp systemd/sub_aggregator_go.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sub_aggregator_go
```

## تنظیم آپاچی

فایل `apache/000-sub-aggregator.conf.example` را ببینید و طبق دامنه‌ی خودتان تنظیم کنید.

## متغیرهای محیطی قابل تنظیم

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `SUB_AGG_DB_PATH` | `/opt/sub_aggregator/aggregator.db` | مسیر دیتابیس داخلی |
| `PANEL_TYPE` | `xui` | نوع پنل: `xui` یا `pasarguard` |
| `SANAEI_DB_PATH` | `/etc/x-ui/x-ui.db` | (فقط حالت xui) مسیر دیتابیس x-ui، فقط خواندن |
| `MYSQL_USER` / `MYSQL_PASS` / `MYSQL_DB` / `MYSQL_HOST` | — | اتصال به دیتابیس ربات میرزا |
| `SUB_AGG_SOCKET_PATH` | `/run/sub_aggregator/aggregator.sock` | مسیر Unix Socket |
| `SUB_AGG_FETCH_INTERVAL_MINUTES` | `30` | فاصله‌ی به‌روزرسانی خودکار کش کانفیگ‌ها |
| `PASARGUARD_PORT` | `8000` | (فقط حالت pasarguard) پورت داخلی پنل پاسارگارد |
| `PASARGUARD_SUB_PATH` | `/sub/` | (فقط حالت pasarguard) باید دقیقاً با `XRAY_SUBSCRIPTION_PATH`/`SUBSCRIPTION_PATH` در `.env` پاسارگارد یکی باشد |
| `PASARGUARD_SCHEME` | `http` | (فقط حالت pasarguard) پروتکل اتصال داخلی؛ اگر پاسارگارد با `UVICORN_SSL_CERTFILE` اجرا شده باشد، به `https` تغییر دهید |
| `PASARGUARD_ADMIN_USER` / `PASARGUARD_ADMIN_PASS` | — | (فقط حالت pasarguard، اختیاری) برای نمایش دراپ‌داون گروه‌های واقعی در کنسول. ادمین باید دسترسی `groups:read_simple` داشته باشد (ساده‌ترین حالت: یک ادمین sudo). بدون این مقادیر، سرویس همچنان کار می‌کند ولی باید Group ID را دستی در کنسول تایپ کنید |
| `BOT_INBOUND_FORMAT` | `plain` | فرمت نوشتن ستون `product.inbounds` هنگام سینک با ربات فروش: `plain` (مثل `2`) برای Faoxima/x-ui، یا `json_array` (مثل `[2]`) برای ربات میرزای قدیمی یا محصولات نوع مرزبان |

این مقادیر را با `sudo systemctl edit sub_aggregator_go` تنظیم کنید (نه داخل کد).

## پشتیبانی از پنل PasarGuard

با `PANEL_TYPE=pasarguard`، سرویس به‌جای x-ui.db، مستقیم از API عمومی پاسارگارد
(`/{token}/info` و `/{token}`) استفاده می‌کند — بدون نیاز به لاگین ادمین یا
دسترسی مستقیم به دیتابیس.

**دسته‌بندی کانفیگ‌های مادر بر اساس روز خرید (شمسی)، نه Group واقعی:**
هر لینک مادری که در کنسول ثبت می‌شود، به یک عدد ۱ تا ۳۱ (روز شمسی) یا `all`
وصل می‌شود. وقتی کاربری لینک ساب خودش را باز می‌کند، سرویس تاریخ ساخت
اکانتش (`created_at` که پاسارگارد خودش نگه می‌دارد) را به شمسی تبدیل کرده
و فقط کانفیگ‌های همان روز + `all` را به او تحویل می‌دهد. این کاملاً مستقل
از Group واقعی پاسارگارد است — یعنی دسترسی به Host های واقعی VPN دست‌نخورده
می‌ماند و نیازی به ساخت ۳۰-۳۱ گروه در پاسارگارد نیست. `PASARGUARD_ADMIN_USER/PASS`
دیگر برای این قابلیت لازم نیستند (فقط اگر بخواهید دراپ‌داون گروه‌های واقعی
را برای مقاصد دیگر ببینید).

**محدودیت شناخته‌شده:** تزریق کانفیگ‌های اضافه در نمای مرورگری (صفحه‌ی HTML
که کاربر با مرورگر می‌بیند) فعلاً فقط برای x-ui پیاده شده؛ در حالت پاسارگارد
کانفیگ‌های اضافه فقط برای کلاینت‌های VPN (v2rayNG، Clash، و غیره) در فرمت
base64 تزریق می‌شوند، نه در صفحه‌ی وب.

## انتشار نسخه‌ی جدید (برای نگهدارنده‌ی ریپو)

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions خودکار باینری‌های `linux/amd64` و `linux/arm64` را می‌سازد و در بخش
Releases منتشر می‌کند.

## امنیت
- پسورد کنسول ادمین با bcrypt هش می‌شود؛ اولین بار با `admin`/`admin` وارد شوید و فوراً عوض کنید.
- x-ui.db همیشه read-only باز می‌شود تا با خود پنل x-ui روی نوشتن تداخل نکند.
- توصیه می‌شود پورت‌های Listen پنل x-ui (مثل 2096) روی `127.0.0.1` محدود شوند تا فقط از طریق این سرویس در دسترس باشند.
