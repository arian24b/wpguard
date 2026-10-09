<div dir="rtl">

# wpguard

[![CI](https://github.com/arian24b/wpguard/actions/workflows/ci.yml/badge.svg)](https://github.com/arian24b/wpguard/actions/workflows/ci.yml)

[English](README.md) | **فارسی**

ابزار خط فرمان برای اسکن، پاکسازی، سخت‌سازی، بکاپ و پایش سایت‌های وردپرسی هک‌شده، بر پایه [wp-cli](https://wp-cli.org/). پایتون ۳.۱۴، بدون وابستگی اجباری (`boto3` برای S3 و `pymysql` برای `recover` اختیاری‌اند).

## نصب

```bash
uvx wpguard --help                 # اجرا بدون نصب (uv خودش پایتون ۳.۱۴ را می‌گیرد)
uv tool install wpguard            # یا: pipx install wpguard
pip install 'wpguard[s3]'          # بکاپ روی S3   |   'wpguard[mysql]' برای recover روی MySQL زنده
wpguard setup                      # دانلود wp-cli (با بررسی sha512) و ساخت ~/.config/wpguard/wpguard.toml
wpguard init                       # (اختیاری) ساخت ./wpguard.toml نمونه برای همین پروژه
```

پیش‌نیاز: لینوکس، `php` و کلاینت MySQL/MariaDB برای دستورهای سایت (نه برای `baseline`، `watch`، `logs`، `verify`). با **کاربر مالک فایل‌های سایت** اجرا کنید (`sudo -u www-data wpguard ...`). ابزارهای اختیاری که در صورت وجود استفاده می‌شوند: `yara` (یا `yr`)، `clamscan`، `age`، `rsync`، `ssh`، `wpscan`/docker.

## شروع سریع

```bash
wpguard scan /var/www/site                       # ۱. اول فقط ببینید، چیزی تغییر نمی‌کند
wpguard fix  /var/www/site --dry-run             # ۲. طرح کامل را ببینید
wpguard fix  /var/www/site --url https://your.site     # ۳. اجرا (تأیید می‌گیرد؛ --yes برای رد کردن)
wpguard undo /var/www/site                       #    false positive بود؟ فایل‌های قرنطینه را برگردانید
wpguard harden /var/www/site --lockdown --url https://your.site   # بعد از به‌روزرسانی کامل
wpguard baseline /var/www/site                   # عکس‌برداری از وضعیت تمیز
wpguard schedule add watch /var/www/site --every 15m --install    # هشدار با هر تغییر
```

`SITE` می‌تواند مسیر، **نام پروفایل** در `wpguard.toml`، **نام میزبان (hostname)** مثل `blog.example.com` یا **`host:/path`** / **`host:domain`** (اجرا از طریق ssh) باشد.

## دستورها

| دستور | کار |
|---|---|
| `scan` | فقط‌خواندنی: امضا، پایگاه هش، YARA، امتیاز رفتاری، دست‌کاری `wp-config.php`/`.htaccess`/`.user.ini`، فایل‌های مخفی، mu-plugins، ClamAV، فایل‌های اضافه نسبت به checksum، تزریق در دیتابیس، ادمین جدید، کرون مشکوک، افزونه قدیمی/رهاشده/آسیب‌پذیر |
| `fix` | اسکن ← **طرح** ← تأیید ← بکاپ ← قرنطینه ← نصب مجدد هسته/افزونه/پوسته (نسخه‌های قفل‌شده اگر باشد) ← پاکسازی دیتابیس ← سخت‌سازی ← salt جدید ← اسکن مجدد ← baseline. با `--dry-run` بعد از طرح متوقف می‌شود |
| `undo` | برگرداندن فایل‌های قرنطینه‌شده (آخرین قرنطینه، `--from DIR`، `--only GLOB`) |
| `harden` | مسدود کردن PHP در uploads، ثابت‌های wp-config، دسترسی 755/644؛ `--prune` موارد غیرفعال را حذف می‌کند |
| `diff` | diff یکپارچه هر فایل تغییریافته هسته/افزونه با فایل رسمی wordpress.org |
| `backup` | dump دیتابیس + همه فایل‌ها ← `wpguard-backup-<site>-<time>.tar.zst`، رمزگذاری اختیاری، آپلود هم‌زمان به چند مقصد، نگهداری (retention)، راستی‌آزمایی |
| `verify` | بررسی بکاپ (checksum، آرشیو خوانا، `db.sql` معقول، وجود فایل‌های وردپرس) |
| `restore` | بازگردانی دیتابیس و فایل‌ها از بکاپ (ابتدا checksum بررسی می‌شود) |
| `baseline` / `watch` | عکس SHA-256 / مقایسه با آن؛ با فایل جدید، تغییریافته یا حذف‌شده کد خروج ۱ و هشدار |
| `lock` | نوشتن `wpguard.lock` (نسخه‌های قفل‌شده هسته/افزونه/پوسته و digest فیدها)؛ `lock --check` انحراف را گزارش می‌دهد |
| `updates` | هر به‌روزرسانی در انتظار را روی **نسخه staging** امتحان می‌کند و می‌گوید کدام سایت را خراب می‌کند؛ `--apply` موارد امن را اعمال می‌کند |
| `logs` | یافتن راه نفوذ از روی لاگ: brute force، xmlrpc، POST به افزونه‌ها، درخواست به شل‌های قرنطینه‌شده |
| `audit` | موجودی کامل + یافته‌ها به صورت Markdown یا JSON (اطلاعات محرمانه حذف می‌شود) |
| `sigs list` / `sigs update` | فیدهای امضا (هش‌های maldet، قوانین YARA) |
| `schedule add\|remove\|show JOB SITE` | خط cron یا تایمر systemd برای `watch backup scan sigs updates` |
| `wp [--unsafe] SITE ARGS...` | اجرای **هر** دستور wp-cli (افزونه‌ها و پوسته‌ها بارگذاری نمی‌شوند مگر با `--unsafe`) |
| `wpscan [URL] ARGS...` | اجرای خود [WPScan](https://wpscan.com/) (برنامه محلی یا docker)؛ `WPSCAN_TOKEN` به‌صورت `--api-token` اضافه می‌شود |
| `recover ARGS...` | بازسازی سایت پاک‌شده از دیتابیس یا dump (`recover --help`) |
| `setup` | دانلود wp-cli و ساخت `~/.config/wpguard/wpguard.toml` اگر config وجود نداشته باشد |
| `init` | ساخت `./wpguard.toml` نمونه با کامنت (یا `--config FILE`؛ `--force` بازنویسی می‌کند) |
| `discover [HOST...]` | پیدا کردن سایت‌های وردپرس با hostname روی همین ماشین یا هاست‌های ssh؛ `--save` آن‌ها را به config اضافه می‌کند |

## فایل پیکربندی و پروفایل‌ها

`wpguard setup` (سراسری، `~/.config/wpguard/wpguard.toml`) یا `wpguard init` (همین پوشه) یک فایل نمونه با کامنت می‌سازد و `wpguard discover --save` سایت‌ها را خودش اضافه می‌کند. فایل در `./` سپس `~/.config/wpguard/` جست‌وجو می‌شود، یا `--config FILE`:

```toml
[defaults]
since = 14
keep = 7

[sites.blog]
path = "/var/www/blog"
url = "https://blog.example.com"
to = ["/srv/backups", "s3://my-bucket/blog", "rsync:backup:/srv/backups/blog"]

[sites.mina]
ssh = "mina"                      # یک host از ~/.ssh/config
path = "/var/www/mina"            # مسیر روی سرور راه دور
```

حالا `wpguard scan blog`، `wpguard backup --all` و `wpguard fix mina --dry-run` کار می‌کنند. هر گزینه CLI می‌تواند کلید config باشد (نام بلند، خط تیره ← زیرخط). اولویت: خط فرمان > `[sites.NAME]` > `[defaults]`. کلید ناشناس خطا است. `[notify]` شامل `telegram_token`، `telegram_chat`، `email` است (متغیرهای محیطی `WPGUARD_TELEGRAM_TOKEN`، `WPGUARD_TELEGRAM_CHAT`، `WPGUARD_EMAIL` اولویت دارند؛ فایل را خصوصی نگه دارید).

### wpguard.lock

`wpguard lock blog` نسخه‌های هسته، افزونه‌ها و پوسته‌ها (و digest فیدهای دانلودشده) را در `wpguard.lock` کنار config ثبت می‌کند؛ آن را commit کنید. سپس:

- `fix` به‌جای «آخرین نسخه»، **نسخه‌های قفل‌شده** را نصب می‌کند (بدون جهش ناگهانی نسخه هنگام پاکسازی)،
- `lock --check` هنگام انحراف (افزونه جدید، تغییر نسخه، تغییر فید) کد خروج ۱ می‌دهد: برای cron عالی است،
- `updates --apply` قفل موارد به‌روزشده را تازه می‌کند.

## سایت با hostname

هر دستور سایت به‌جای مسیر، **نام میزبان** سایت را هم می‌پذیرد:

```bash
wpguard discover                         # فهرست سایت‌های وردپرس همین ماشین (vhost های nginx/apache + wp-config.php)
wpguard discover mina --save             # همین کار روی هاست ssh به نام mina و افزودن به wpguard.toml
wpguard scan blog.example.com            # با hostname (از domain/url پروفایل، یا از vhost های همین ماشین)
wpguard backup mina:blog.example.com     # hostname روی هاست ssh: مسیر از طریق ssh پیدا می‌شود و دستور همان‌جا اجرا می‌شود
```

ترتیب تشخیص `SITE`: نام پروفایل ← host مربوط به `domain`/`url` پروفایل ← `host:/path` ← `host:domain` ← مسیر محلیِ موجود ← دامنه‌ای که در تنظیمات وب‌سرور همین ماشین پیدا شود. اگر پروفایل `domain` داشته باشد می‌تواند `path` نداشته باشد (و اختیاراً `ssh`)؛ مسیر از روی vhost ها پیدا می‌شود. Discovery فایل‌های `/etc/nginx`، `/etc/apache2`، `/etc/httpd` (`server_name`/`ServerName`/`ServerAlias` به‌علاوه `root`/`DocumentRoot`) و `wp-config.php` زیر `/var/www /srv /home /opt` را می‌خواند؛ چینش‌های غیرعادی را می‌توان دستی ثبت کرد. نسخه‌های `www.` هم تطبیق داده می‌شوند.

## سایت‌های راه دور با SSH

```bash
wpguard scan mina:/var/www/site          # موردی: host از ~/.ssh/config، مسیر روی سرور راه دور
wpguard scan mina                        # پروفایل با ssh = "mina"
wpguard backup mina --to s3://bkt/mina --pull ./pulled     # بکاپ راه دور، آرشیو با rsync برمی‌گردد
```

wpguard همان دستور را از طریق `ssh <host> <remote_cmd> ...` روی ماشین راه دور اجرا می‌کند، پس `~/.ssh/config` شما (کلید، ProxyJump، پورت) همان‌طور استفاده می‌شود. سرور راه دور به `uv` نیاز دارد (پیش‌فرض `remote_cmd` برابر `uvx wpguard` است؛ اگر نصب شده، در پروفایل `remote_cmd = "~/.local/bin/wpguard"` بگذارید). گزینه‌ها و مقادیر config فرستاده می‌شوند؛ `--config`، `--report`، `-j`، `--pull` محلی می‌مانند. کد خروج منتقل می‌شود (۱ = یافته). مسیرهای گزینه‌هایی مثل `--hashdb` **روی سرور راه دور** خوانده می‌شوند.

## تشخیص

- **امضاهای** داخلی و `--sigs FILE` (regex خودتان؛ خط خالی/نامعتبر نادیده گرفته می‌شود).
- **پایگاه هش**: `--hashdb` مخرب، `--hashdb-good` سالم (یافته را حذف می‌کند). هر فایلی با هش hex از نوع md5/sha1/sha256: csv، txt، json، `.gz`، `.hdb` مربوط به ClamAV، SQLite.
- **امتیاز رفتاری** (`--behavior-threshold` پیش‌فرض ۵؛ `--no-behavior`): تراکم فراخوانی‌های خطرناک، مبهم‌سازی hex/chr، آنتروپی بالا، خطوط بسیار بلند، پسوند دوگانه، PHP در پوشه‌های asset، نام‌های بدافزارهای شناخته‌شده، mtime بسیار جدیدتر از هم‌پوشه‌ای‌ها یا در آینده. **فقط بازبینی**: `fix` یافته‌های behavior و YARA را قرنطینه نمی‌کند مگر با `--aggressive`.
- **YARA**: `--yara RULES.yar` (قابل تکرار) از طریق برنامه `yara` یا `yr`.
- **فیدها**: `wpguard sigs update` هش‌های md5 مجموعه maldet ([rfxn](https://www.rfxn.com/projects/linux-malware-detect/))، [php-malware-finder](https://github.com/nbs-system/php-malware-finder) (LGPL-3.0) و قوانین webshell مجموعه [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) (Detection Rule License 1.1: ذکر منبع) را می‌گیرد. در `~/.local/share/wpguard/feeds` کش می‌شوند، خودکار در `scan`/`fix` استفاده می‌شوند (`--no-feeds` غیرفعال می‌کند) و digest آن‌ها با `lock` قفل می‌شود. فید خودتان را با `[feeds.NAME]` در config اضافه کنید.
- **diff هسته/افزونه**: `wpguard diff SITE [--core] [--plugin SLUG]` نشان می‌دهد مهاجم در فایل رسمی چه تغییری داده است.
- `--ignore GLOB` (قابل تکرار، یا `ignore = [...]` در config) مسیرهای سالم را ساکت می‌کند.

## fix امن‌تر

`fix` همیشه اول طرح را چاپ می‌کند (چه چیزی قرنطینه می‌شود، چه چیزی *فقط برای بازبینی* علامت خورده، کدام کاربران حذف می‌شوند، چه نسخه‌هایی نصب می‌شود) و بعد `Proceed? [y/N]` می‌پرسد. اجرای غیرتعاملی بدون `--yes` رد می‌شود؛ `-j > 1` به `--yes` یا `--dry-run` نیاز دارد. فایل‌های قرنطینه **جابه‌جا** می‌شوند (هرگز حذف نمی‌شوند) به `<پوشه والد سایت>/wpguard-quarantine/<site>-<time>/files/` همراه `manifest.json`؛ `wpguard undo` آن‌ها را برمی‌گرداند. `wp-config.php` و `.htaccess` بیرون از uploads فقط گزارش می‌شوند. پیش از هر تغییر یک بکاپ (بدون uploads) گرفته می‌شود.

## بکاپ

```bash
wpguard backup blog                                   # به مقصدهای پروفایل (یا کنار سایت)
wpguard backup /var/www/site --out /srv/backups --verify --keep 7
wpguard backup blog --to s3://bkt/blog --to rsync:backup:/srv/b --encrypt-to age1... --keep 14
wpguard verify blog --out /srv/backups                # آخرین بکاپ محلی
wpguard restore /var/www/site --from /srv/backups/wpguard-backup-site-20261009-113206.tar.zst
```

ساختار آرشیو: `db.sql` + `site/...` در tar با zstd، دسترسی 600، همراه `.sha256`؛ بکاپ موجود هرگز بازنویسی نمی‌شود. **مقصدها** (`--to`، قابل تکرار): پوشه محلی، `s3://bucket/prefix` (با `boto3`، متغیرهای معمول `AWS_*`، و `AWS_ENDPOINT_URL` برای MinIO/R2)، `rsync:HOST:/path` (HOST می‌تواند نام مستعار ssh باشد). آپلود به همه مقصدها **هم‌زمان** انجام می‌شود؛ پس از آپلود اندازه بررسی می‌شود و خرابی یک مقصد بقیه را متوقف نمی‌کند (کد خروج ۱). **Retention** (`--keep N`) جدیدترین N بکاپ هر مقصد و سایت را نگه می‌دارد و فقط پس از آپلود تأییدشده اجرا می‌شود. `--verify` آرشیو را پیش از آپلود بررسی می‌کند. `--encrypt-to` به [`age`](https://age-encryption.org) نیاز دارد؛ restore/verify چنین فایل‌هایی به `--age-identity KEY` نیاز دارد. `--no-uploads` پوشه `wp-content/uploads` را کنار می‌گذارد. آرشیو `wp-config.php` (رمز دیتابیس) دارد: خصوصی نگهش دارید.

## مشاور به‌روزرسانی

`wpguard updates SITE` به‌روزرسانی‌های در انتظار هسته/افزونه/پوسته را فهرست می‌کند و **هر کدام** را روی یک کپی موقت امتحان می‌کند: فایل‌ها (بدون uploads) + دیتابیس کلون‌شده، با سرور داخلی PHP روی 127.0.0.1. بعد از هر به‌روزرسانی `/`، `/wp-login.php`، `/wp-admin/` (با `--check-url` بیشتر کنید) را درخواست می‌کند و لاگ سرور را می‌خواند؛ صفحه 5xx و خطای fatal پی‌اچ‌پی `BREAKS` گزارش می‌شود، سپس همان افزونه برگردانده شده و مورد بعدی جداگانه امتحان می‌شود. در این کپی ایمیل خروجی و HTTP خروجی (جز wordpress.org) مسدود و WP-Cron خاموش است، پس بارگذاری افزونه‌ها نمی‌تواند به مشتری ایمیل بزند. به `php` و کاربر MySQL با اجازه `CREATE DATABASE` نیاز دارد (یا `--stage-db` یک دیتابیس خالی موجود). `--apply` ابتدا بکاپ می‌گیرد و فقط موارد موفق را به‌روز می‌کند. `--keep-stage` کپی را برای بررسی نگه می‌دارد.

## زمان‌بند

```bash
wpguard schedule show backup blog --daily 03:30          # فقط خط cron را چاپ می‌کند
wpguard schedule add watch blog --every 15m --install    # در crontab شما می‌نویسد (idempotent، با کامنت نشانه)
wpguard schedule add backup blog --daily 03:30 --systemd --install    # تایمر کاربر systemd
wpguard schedule remove watch blog
```

Jobها: `watch backup scan sigs updates`؛ `watch`، `scan` و `updates` با `--notify` اجرا می‌شوند. تنظیمات هشدار را در `[notify]` بگذارید (cron متغیر محیطی ندارد). برای اجرای تایمرهای کاربر systemd وقتی لاگین نیستید: `loginctl enable-linger $USER`.

## راهنماهای دیگر

**پاکسازی سایت هک‌شده**: سایت را ایزوله کنید ← `scan --since 14` ← `logs` (راه نفوذ: POST به PHP افزونه‌ها، درخواست به فایل‌هایی که بعداً قرنطینه می‌کنید) ← اول `fix --dry-run` سپس `fix` ← افزونه‌های پولی با برچسب `SKIP` را از سایت سازنده نصب کنید ← رمز دیتابیس/FTP/SSH/وردپرس را عوض و ادمین‌های ناشناس را حذف کنید ← بعد از به‌روزرسانی `harden --lockdown` ← `baseline` و `schedule add watch`.

**سایت پاک‌شده**: `wpguard recover --dump site.sql --db NAME --user U --out site --list` (فقط فهرست)، سپس بدون `--list` برای دانلود هسته/افزونه/پوسته با نسخه‌های ثبت‌شده در دیتابیس؛ uploads و کدهای پولی را از بکاپ برگردانید و ادامه دهید.

**audit**: `wpguard audit blog --out blog.md` (یا `.json`): نسخه‌ها، تنظیمات، افزونه‌ها، پوسته‌ها، کاربران به تفکیک نقش، کرون، mu-plugins، drop-ins، ثابت‌های `wp-config.php` بدون رمز/نام کاربری دیتابیس/saltها، و همه یافته‌ها.

## توسعه

```bash
uv sync
uv run ruff check . && uv run ruff format --check .      # ruff با select = ["ALL"] (موارد ignore با دلیل در pyproject.toml)
uv run pytest
uv build
```

GitHub Actions (`.github/workflows/ci.yml`) با هر push و pull request ابزار ruff، pytest و یک smoke test از wheel را اجرا می‌کند. push کردن تگ `v*` فایل `release.yml` را اجرا و با trusted publishing روی PyPI منتشر می‌کند (publisher را یک بار در pypi.org تنظیم کنید).

## محدودیت‌ها

- تشخیص heuristic است. افزونه‌های تجاری مبهم‌سازی‌شده ممکن است false positive بدهند و شل‌های جدید ممکن است جا بمانند؛ جایگزین WAF یا اسکن سطح سرور نیست.
- پاکسازی دیتابیس مبتنی بر regex است: dry-run را بخوانید. `fix` اگر قفل باشد نسخه‌های قفل‌شده، وگرنه **آخرین** نسخه را نصب می‌کند (جهش نسخه بزرگ ممکن است ناسازگاری ایجاد کند؛ `updates` برای امتحان همین است).
- مشاور به‌روزرسانی به محیط واقعی PHP + MySQL نیاز دارد؛ مهاجرت دیتابیس که توسط به‌روزرسانی افزونه انجام می‌شود ممکن است دیتابیس staging را بین کاندیداها تغییر دهد.
- حالت راه دور به `uv` (یا `wpguard` نصب‌شده) روی سرور مقصد نیاز دارد.
- قرنطینه و بکاپ‌ها کنار سایت (بیرون از وب‌روت) هستند؛ وقتی لازم نیستند پاکشان کنید، فایل مخرب قدیمی و dump دیتابیس دارند.

## ایمنی و مجوز

فقط روی سایت‌هایی استفاده کنید که مالک آن‌ها هستید یا مجوز مدیریتشان را دارید. مجوز MIT (`LICENSE`). فیدهای امضای شخص ثالث مجوز خودشان را دارند (بالا را ببینید).

</div>
