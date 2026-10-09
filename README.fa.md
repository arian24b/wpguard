<div dir="rtl">

# wpguard

[English](README.md) | **فارسی**

ابزار خط فرمان تک‌فایلی (پایتون ۳.۱۴ + [uv](https://docs.astral.sh/uv/)) برای اسکن، پاکسازی، سخت‌سازی و پایش سایت‌های وردپرسی هک‌شده، با استفاده از [wp-cli](https://wp-cli.org/).

همه چیز در یک فایل است: `wpguard.py`. فقط از کتابخانه استاندارد استفاده می‌کند، به‌جز `pymysql` که uv از روی هدر اسکریپت نصب می‌کند و `recover` فقط برای اتصال به MySQL زنده (نه `--dump`) لازم دارد.

## پیش‌نیازها

- لینوکس، `uv`، `php` و کلاینت MySQL/MariaDB در `PATH` (دستورهای `baseline`، `watch` و `logs` به php و mysql نیاز ندارند)
- اجرا با **کاربر مالک فایل‌های سایت** (مثلاً `sudo -u www-data ...`) تا مالکیت فایل‌های جدید درست بماند
- دسترسی شل به فایل‌ها و دیتابیس سایت

## شروع سریع

```bash
uv run wpguard.py setup                              # دانلود wp-cli با بررسی sha512
uv run wpguard.py scan /var/www/site                 # ۱. اول فقط ببینید، چیزی تغییر نمی‌کند
sudo -u www-data uv run wpguard.py fix /var/www/site --url https://your.site
uv run wpguard.py harden /var/www/site --lock --url https://your.site   # بعد از به‌روزرسانی کامل
uv run wpguard.py baseline /var/www/site             # عکس‌برداری از وضعیت تمیز
# کرون، هر ۱۵ دقیقه:
*/15 * * * * /path/uv run /path/wpguard.py watch /var/www/site --notify
```

## دستورها

| دستور | کار |
|---|---|
| `setup` | دانلود wp-cli در `~/.local/share/wpguard/` |
| `scan SITE...` | فقط گزارش: امضای وب‌شل، PHP داخل uploads، فایل‌های اضافه نسبت به checksum هسته/افزونه، دست‌کاری `wp-config.php`/`.htaccess`/`.user.ini`، فایل‌های مخفی، mu-plugins، ClamAV (در صورت نصب)، تزریق در دیتابیس، ادمین‌های جدید، کرون‌های مشکوک، افزونه‌های قدیمی/رهاشده/آسیب‌پذیر |
| `fix SITE...` | بکاپ ← اسکن ← قرنطینه ← حذف کاربران انتخابی ← نصب مجدد هسته/افزونه/پوسته از wordpress.org ← پاکسازی دیتابیس ← سخت‌سازی ← salt جدید ← اسکن مجدد ← baseline |
| `harden SITE...` | مسدود کردن PHP در uploads، اعمال ثابت‌های سخت‌سازی (`HARDEN` در اسکریپت)، دسترسی‌ها 755/644؛ `--prune` افزونه/پوسته‌های غیرفعال را حذف می‌کند |
| `baseline SITE...` | ذخیره SHA-256 همه فایل‌ها (رسانه‌های uploads مستثنی؛ PHP و `.htaccess` آنجا لحاظ می‌شود) |
| `watch SITE...` | مقایسه با baseline؛ با تغییر، کد خروج ۱ و هشدار |
| `logs [SITE...]` | یافتن راه نفوذ از روی لاگ دسترسی (brute force، xmlrpc، POST به افزونه‌ها، درخواست به شل‌ها) |
| `backup SITE...` | بکاپ کامل: dump دیتابیس (`wp db export`) + همه فایل‌های سایت در یک فایل `wpguard-backup-<site>-<time>.tar.zst` (فشرده‌سازی zstd) همراه با `.sha256`، دسترسی 600 و بدون بازنویسی بکاپ قبلی. به پایتون ۳.۱۴ نیاز دارد (uv خودش می‌گیرد) |
| `restore SITE` | بازگردانی دیتابیس و فایل‌ها از آخرین بکاپ (یا `--from FILE.tar.zst`)؛ ابتدا `.sha256` را بررسی می‌کند |
| `audit SITE...` | خروجی کامل موجودی سایت (نسخه‌ها، تنظیمات، افزونه‌ها، پوسته‌ها، کاربران، کرون، mu-plugins، ثابت‌های wp-config بدون اطلاعات محرمانه) به‌علاوه یافته‌های اسکن، به صورت Markdown یا JSON |
| `wp [--unsafe] SITE ARGS...` | اجرای **هر** دستور wp-cli روی سایت، مثلاً `wpguard wp /var/www/x plugin list`. افزونه‌ها و پوسته‌ها بارگذاری نمی‌شوند (روی سایت آلوده امن است) مگر با `--unsafe` |
| `wpscan [URL] ARGS...` | اجرای خود [WPScan](https://wpscan.com/) با همه گزینه‌هایش (برنامه محلی `wpscan` یا docker `wpscanteam/wpscan`). اگر `WPSCAN_TOKEN` تنظیم باشد به‌صورت `--api-token` اضافه می‌شود؛ بدون آن حالت رایگان است (بدون داده آسیب‌پذیری) |
| `recover ARGS...` | بازسازی سایت پاک‌شده از دیتابیس یا dump (`recover --help`) |

## گزینه‌ها

| گزینه | معنی |
|---|---|
| `--sites-file F` | مسیر سایت‌های بیشتر، جداشده با فاصله/خط |
| `-j N` | اسکن موازی N سایت |
| `--report out.{json,html,txt}` | ذخیره گزارش |
| `--notify` | هشدار هنگام یافته (متغیرهای محیطی پایین) |
| `--sigs FILE` | امضاهای regex اضافه، هر خط یکی (مثلاً از مجموعه‌های maldet/Wordfence) |
| `--since DAYS` | پرچم‌گذاری PHP تغییرکرده / ادمین ساخته‌شده در N روز اخیر |
| `--hashdb FILE` | (`scan`/`fix`/`audit`) پایگاه هش‌های **مخرب** شناخته‌شده؛ قابل تکرار. هر فایلی که هش‌های hex از نوع md5/sha1/sha256 داشته باشد: `.csv`، `.tsv`، `.txt`، خروجی `md5sum`/`sha256sum`، `.json`، `.gz`، SQLite (`.db`/`.sqlite`). نوع هش از روی طول تشخیص داده می‌شود؛ فایل‌های منطبق گزارش (و در `fix` قرنطینه) می‌شوند |
| `--hashdb-good FILE` | پایگاه هش‌های **سالم** شناخته‌شده (همان قالب‌ها)؛ فایل‌های منطبق نادیده گرفته می‌شوند و false positive کم می‌شود |
| `--no-net` | بدون جست‌وجوی آنلاین wordpress.org / WPScan |
| `--clean-db` | اعمال واقعی پاکسازی دیتابیس (در `fix` به‌صورت پیش‌فرض فقط dry-run است) |
| `--delete-user ID` | (`fix`) حذف ادمین مشکوک، قابل تکرار |
| `--prune` | (`harden`/`fix`) حذف افزونه و پوسته غیرفعال |
| `--url URL` | تثبیت `WP_HOME`/`WP_SITEURL` (جلوی تغییر siteurl در دیتابیس را می‌گیرد) |
| `--lock` | اعمال `DISALLOW_FILE_MODS` و `AUTOMATIC_UPDATER_DISABLED` (جلوی به‌روزرسانی را می‌گیرد؛ آخر کار استفاده شود) |
| `--log F` / `--top N` | (`logs`) فایل‌های لاگ (متن ساده یا `.gz`) / تعداد ردیف هر بخش |
| `--format md\|json` / `--out FILE` | (`audit`) قالب و مقصد خروجی؛ اگر `--out` به `.json` ختم شود json، وگرنه md |
| `--out DIR` | (`backup`) پوشه مقصد (پیش‌فرض: کنار سایت، باید بیرون از آن باشد). در `audit` همین گزینه فایل خروجی است |
| `--no-uploads` | (`backup`) بدون `wp-content/uploads` |
| `--from FILE` | (`restore`) فایل بکاپ مشخص |

متغیرهای محیطی: `WPGUARD_TELEGRAM_TOKEN` و `WPGUARD_TELEGRAM_CHAT`، `WPGUARD_EMAIL` (SMTP محلی)، `WPSCAN_TOKEN` (کلید رایگان wpscan.com برای جست‌وجوی CVE).

## راهنما: پاکسازی سایت هک‌شده

1. **ایزوله کنید.** سایت را در حالت تعمیر یا محدود به IP قرار دهید.
2. **اول اسکن.** `scan SITE --since 14 --report before.html`. همه خطوط را بخوانید؛ ادمین‌های ناشناس و موارد `VULN` / `abandoned` / `source` را یادداشت کنید (احتمالاً راه نفوذ).
3. **راه نفوذ را پیدا کنید.** `logs SITE` (برای مسیرهای غیرپیش‌فرض از `--log`). به POSTهای مستقیم به فایل‌های PHP افزونه‌ها و درخواست‌ها به فایل‌های قرنطینه‌شده نگاه کنید.
4. **ترمیم.** `fix SITE --url https://your.site --delete-user 7`. خروجی dry-run پاکسازی دیتابیس را بخوانید و فقط اگر واقعاً مخرب بود با `--clean-db` دوباره اجرا کنید.
5. **افزونه/پوسته‌های پولی یا سفارشی** که `SKIP` شدند در wordpress.org نیستند: دستی از سایت سازنده نصب کنید. هرگز از نسخه کرک‌شده (nulled) استفاده نکنید.
6. **کارهای دستی که `fix` نمی‌کند:** تغییر رمز دیتابیس، FTP/SSH، هاستینگ و وردپرس؛ بازبینی `wp-config.php`؛ حذف کاربران ناشناس؛ بررسی پوشه قرنطینه برای false positive.
7. **قفل کردن.** پس از همه به‌روزرسانی‌ها: `harden SITE --lock --url ...`. برای به‌روزرسانی بعدی موقتاً `wp config delete DISALLOW_FILE_MODS` را اجرا کنید.
8. **پایش.** همین حالا `baseline SITE`، سپس `watch` در کرون. بعد از هر به‌روزرسانی مجاز دوباره `baseline` بگیرید.
9. **بازگشت** اگر چیزی خراب شد: `restore SITE`؛ فایل‌های قرنطینه در `../wpguard-quarantine/` هستند (دستی برگردانید).

## راهنما: wp-cli، WPScan و پایگاه هش

```bash
uv run wpguard.py wp /var/www/site plugin list --status=active --format=json
uv run wpguard.py wp /var/www/site user list --role=administrator
uv run wpguard.py wp --unsafe /var/www/site cron event list      # افزونه‌ها را بارگذاری می‌کند: فقط روی سایت مطمئن

export WPSCAN_TOKEN=xxxx                                           # کلید رایگان از wpscan.com/api (۲۵ درخواست در روز)؛ اختیاری
uv run wpguard.py wpscan https://your.site --enumerate vp,vt,u --plugins-detection mixed

uv run wpguard.py scan /var/www/site --hashdb malware.csv --hashdb-good vendor-clean.sha256
```
`wpscan` به `gem install wpscan` یا docker نیاز دارد و سایت زنده را از طریق HTTP بررسی می‌کند؛ فقط روی سایت خودتان استفاده کنید. هش پایگاه با همه فایل‌ها (تا ۵۰ مگابایت) مقایسه می‌شود، پس پایگاه بزرگ روی سایت بزرگ کندتر است؛ فقط از فهرست‌های معتبر (maldet یا نمونه‌های حادثه خودتان) استفاده کنید.

## راهنما: بکاپ و بازگردانی

```bash
uv run wpguard.py backup /var/www/site --out /srv/backups          # دیتابیس + فایل‌ها (+ uploads)
uv run wpguard.py backup /var/www/site --no-uploads                # سبک: فقط کد و دیتابیس
uv run wpguard.py restore /var/www/site --from /srv/backups/wpguard-backup-site-20261009-113206.tar.zst
```
آرشیو شامل `db.sql` و درخت سایت زیر `site/` است و `wp-config.php` (رمز دیتابیس) را هم دارد؛ پس خصوصی نگهش دارید. `fix` پیش از هر تغییر خودکار یک بکاپ بدون uploads می‌گیرد. `restore` فایل‌ها را روی سایت می‌نویسد و دیتابیس را دوباره import می‌کند؛ فایل‌هایی که در آرشیو نیستند را حذف نمی‌کند.

## راهنما: خروجی audit

```bash
uv run wpguard.py audit /var/www/site --out site-audit.md
uv run wpguard.py audit /var/www/a /var/www/b -j 2 --format json --out audits.json
```
فقط‌خواندنی است (همان بررسی‌های `scan` به‌علاوه موجودی). رمز دیتابیس، نام کاربری دیتابیس و saltها حذف می‌شوند، اما ایمیل و نام کاربران می‌ماند؛ با احتیاط به اشتراک بگذارید.

## راهنما: سایت کاملاً پاک شده

```bash
uv run wpguard.py recover --dump /backup/site.sql --db NAME --user U --password 'P' --host 127.0.0.1 --out site --list   # فقط فهرست
uv run wpguard.py recover --dump /backup/site.sql ... --out site     # دانلود هسته/افزونه/پوسته با نسخه‌های ثبت‌شده در دیتابیس
```
سپس `uploads/` و کدهای پولی را از بکاپ برگردانید، vhost را به `site/` اشاره دهید و از مرحله ۴ بالا ادامه دهید.

## توسعه

`pyproject.toml` ابزار ruff را با `select = ["ALL"]` تنظیم می‌کند (موارد ignore شده با دلیل همان‌جا نوشته شده‌اند).

```bash
uv run ruff check .
uv run ruff format .
```

## محدودیت‌ها

- روش‌ها heuristic هستند. افزونه‌های تجاری مبهم‌سازی‌شده ممکن است false positive بدهند و شل‌های جدید ممکن است جا بمانند. جایگزین WAF یا اسکن سطح سرور نیست.
- پاکسازی دیتابیس مبتنی بر regex است؛ همیشه dry-run را بخوانید.
- قرنطینه و بکاپ‌ها بیرون از وب‌روت هستند: `<پوشه والد سایت>/wpguard-quarantine/` و `wpguard-backup-*`. وقتی لازم نیستند پاکشان کنید (فایل مخرب قدیمی و dump دیتابیس دارند).
- `fix` **آخرین** نسخه افزونه/پوسته را نصب می‌کند؛ جهش نسخه بزرگ ممکن است ناسازگاری ایجاد کند.
- اسکن هرگز کد سایت را اجرا نمی‌کند: wp-cli با `--skip-plugins --skip-themes` اجرا می‌شود.

## نکات ایمنی

فقط روی سایت‌هایی استفاده کنید که مالک آن‌ها هستید یا مجوز مدیریتشان را دارید. پیش از هر `fix`/`restore` بکاپ داشته باشید (ابزار خودش بکاپ می‌گیرد، ولی غیرخالی بودن `db.sql` را بررسی کنید).

</div>
