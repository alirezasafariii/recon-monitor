# راهنمای Recon Monitor 8.1.0



## آپدیت خودکار از GitHub Private در نسخه 8.1.0

در نسخه 8.1.0 دیگر برای ارتقا لازم نیست ZIP نسخه جدید را دستی جابه‌جا کنی. Recon Monitor با استفاده از GitHub CLI احراز هویت‌شده (`gh`) آخرین Release خصوصی ریپوی `alirezasafariii/recon-monitor` را پیدا می‌کند و ZIP و فایل SHA-256 متناظر را دانلود می‌کند. توکن GitHub داخل `config.env` ذخیره نمی‌شود و مدیریت credential به خود `gh`/سیستم‌عامل سپرده می‌شود.

```bash
./recon-monitor.sh update check
./recon-monitor.sh update install
./recon-monitor.sh update rollback
```

قبل از نصب، Backup داده و Backup برنامه ساخته می‌شود. بعد از نصب نیز init، compile، کل Unit Testها و Integration Test اجرا می‌شوند. اگر Validation شکست بخورد، کد و دیتابیس به وضعیت قبل از آپدیت برمی‌گردند. نصب دستی با `--package` و مسیر قدیمی `RECON_UPDATE_MANIFEST` نیز همچنان پشتیبانی می‌شوند. Schema دیتابیس همچنان **16** است.

راهنمای ارتقا: `MIGRATION-v8.1.md`.

## کنسول تحقیق چهار-بخشی در نسخه 8.0

Recon Monitor 8.0 تجربه کاربری را بدون حذف Engineهای زیرساختی حول چهار Workspace اصلی ساده می‌کند: **Recon**، **Analysis**، **Potential Findings** و **Alerts**. بخش Recon همه داده‌های کشف‌شده سطح حمله را با جستجو و فیلتر یکپارچه جمع می‌کند. Analysis خروجی Engineها و Reasoning را در یک مسیر متمرکز می‌کند. Potential Findings کاندیداهای بررسی‌شده را با Confidence و وضعیت Triage نمایش می‌دهد. Alerts اجرای مجدد Recon را با Baseline تارگت مقایسه می‌کند و موارد جدید یا تغییرکرده مهم مثل Endpoint، Subdomain، URL، Port/Service، JavaScript، Technology، Response Fingerprint، Authentication Boundary و Response Shape را اعلام می‌کند.

نسخه 8 همچنان از Schema دیتابیس **16** استفاده می‌کند و مدل ایمنی نسخه 7 را حفظ می‌کند: Vulnerability را خودکار تأیید نمی‌کند، Authorization Gateها را دور نمی‌زند و Active Moduleها را خودکار فعال نمی‌کند. Commandها و Compatibility Moduleهای نسخه 7 نیز حفظ شده‌اند.

```bash
./recon-monitor.sh dashboard restart --open
./recon-monitor.sh workspace sync
./recon-monitor.sh workspace cockpit --target example.com
```

راهنمای گذار 7.0 به 8.0: `MIGRATION-v8.0.md`.


## محیط یکپارچه تحقیق امنیتی در نسخه 7.0

نسخه 7 قابلیت‌های Recon، تحلیل، Case، Safe Validation و عملیات را به یک Workspace تحلیل‌گرمحور تبدیل می‌کند. قابلیت‌های جدید شامل Evidence Gap Engine، Case Autopilot، Authentication Context، Differential Intelligence، Attack Surface Graph، Change Intelligence، Recon Confidence، Target Memory، یادگیری تحت نظارت از False Positive، Smart Recon Planner، سنجش ارزش Stageها، Report Builder متصل به Evidence، Browser Capture فقط-متادیتا، Cockpit، Universal Search، Command Palette، Error ID ساختاریافته، Repair محدود و Safety Center است. Schema دیتابیس **16** است.

نسخه 7 هیچ Vulnerability را خودکار تأیید نمی‌کند و هیچ Active Module را خودکار فعال نمی‌کند. خانواده‌های حساس مثل BOLA/BFLA همچنان Manual-only/Controlled باقی می‌مانند. Cookie، Authorization و Body خام حساس در Browser Capture یا بسته Burp ذخیره نمی‌شوند.

```bash
./recon-monitor.sh workspace sync
./recon-monitor.sh workspace cockpit --target example.com
./recon-monitor.sh workspace evidence-gap --case-id CASE_ID
./recon-monitor.sh workspace autopilot --case-id CASE_ID
./recon-monitor.sh workspace coverage --target example.com
./recon-monitor.sh workspace safety
./recon-monitor.sh dashboard restart --open
```

راهنمای ارتقا: `MIGRATION-v7.0.md` و مستند اصلی: `docs/UNIFIED_SECURITY_RESEARCH_WORKSPACE.md`.

## پلتفرم Intelligence، Automation و Hardening در نسخه 6.0

نسخه 6 حلقه Recon، تحلیل، اعتبارسنجی محدود، تصمیم تحلیل‌گر و عملیات را کامل می‌کند. قابلیت‌های اصلی شامل سنجش اعتبار نتیجه Validation، تشخیص Blind Spot، صف بررسی هزینه‌محور، بسته رفت‌وبرگشت Burp، همبستگی Story نسل دوم، Revalidation آفلاین، زمان‌بندی macOS با Quiet Hours، اعلان هوشمند، Tokenهای Scopeدار و تاریخ‌دار، زنجیره تمامیت Audit، Retention امن، Performance Diagnostics، Target Template و کنترل کیفیت گزارش است. Schema دیتابیس 15 است. جزئیات در `docs/RECON_MONITOR_6_PLATFORM.md` و `MIGRATION-v6.0.md` آمده است.

```bash
./recon-monitor.sh platform sync
./recon-monitor.sh suite data-quality
./recon-monitor.sh suite review-queue --apply
./recon-monitor.sh suite security-posture
```

Recon Monitor یک سامانه محلی برای **پایش تغییرات سطح حمله در Scopeهای دارای مجوز** است. نسخه 3.1 علاوه بر معماری پایدار نسخه 3، داشبورد را به یک محیط حرفه‌ای تحلیل‌گر با Workbench، سلسله‌مراتب بصری جدید و صفحات تحلیل یکپارچه تبدیل می‌کند.

این برنامه مجوز تست ایجاد نمی‌کند. فقط دامنه‌ها و سرویس‌هایی را وارد کن که مالک آن‌ها هستی یا برای ارزیابی‌شان مجوز صریح داری. ماژول‌های فعال همچنان پیش‌فرض خاموش هستند.

## شروع سریع پس از نصب یا ارتقا

```bash
cd ~/Downloads/recon-monitor

./recon-monitor.sh --version
./recon-monitor.sh setup
./recon-monitor.sh doctor
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
```

قبل از هر اجرای واقعی، Scope و بودجه را بدون ارسال درخواست بررسی کن:

```bash
./recon-monitor.sh run \
  --target abercrombie.com \
  --dry-run
```

اجرای واقعی:

```bash
./recon-monitor.sh run \
  --target abercrombie.com
```

---




## اعتبارسنجی امن و بازخورد تحلیل‌گر در نسخه 5.1

نسخه 5.1 برای هر پرونده امنیتی یک طرح اعتبارسنجی Scope-aware می‌سازد. اجرای خودکار فقط در دو سطح آفلاین و Passive Live مجاز است و درخواست زنده به `GET`، `HEAD` و `OPTIONS` در Scope محدود می‌شود؛ Cookie یا Credential بازپخش نمی‌شود، Redirect دنبال نمی‌شود، Query حساس تکرار نمی‌شود و Body خام ذخیره نمی‌شود. خانواده‌های Authorization کنترل‌شده فقط طرح بررسی دریافت می‌کنند و SSRF، XSS اجرایی، Upload، Path Traversal، Race، پرداخت، بازیابی حساب، تغییر Role و عملیات تخریبی Manual-only هستند. Import فایل HAR و Burp XML نیز با فیلتر Scope و Redaction انجام می‌شود. Schema دیتابیس 14 است. راهنمای کامل در `docs/SAFE_VALIDATION_ENGINE.md` و `MIGRATION-v5.1.md` قرار دارد.

```bash
./recon-monitor.sh validation eligibility --case-id CASE_ID
./recon-monitor.sh validation plan --case-id CASE_ID --level offline
./recon-monitor.sh validation run --plan-id PLAN_ID
```

## پلتفرم عملیاتی نسخه 5.0

نسخه 5.0 هسته‌های 4.5 تا 4.6 را با Engine Quality، پرونده‌های امنیتی، Security Story، Scope و Operations Center، Noise Budget، Target Learning، Incremental Reasoning، Plugin Governance و داشبورد Case-first یکپارچه می‌کند. Schema دیتابیس 13 است. راهنمای ارتقا در `MIGRATION-v5.0.md` و مستندات تفصیلی در پوشه `docs` قرار دارند.

## هسته استدلال امنیتی نسخه 4.6

نسخه 4.6 یک لایه استدلال امنیتی قابل‌توضیح به Candidate Engine اضافه می‌کند: مدل یکپارچه شواهد و منشأ آن‌ها، جلوگیری از دوباره‌شماری شواهد هم‌ریشه، پیش‌شرط اختصاصی هر خانواده باگ، تفکیک رسمی Unknown از Evidence مخالف، Falsification، رتبه‌بندی سه خانواده محتمل، Likelihood کالیبره‌شده، Exploitability مستقل، Evidence Coverage، Golden Dataset، Calibration هر خانواده، Shadow Rule و Regression Gate. Schema دیتابیس 12 است. راهنمای کامل در `docs/SECURITY_REASONING_CORE.md` و `MIGRATION-v4.6.md` قرار دارد.

## نسخه پایدارسازی 4.5.1

این نسخه Schema را تغییر نمی‌دهد و روی پایداری تمرکز دارد: Analysis شکست‌خورده دیگر در حالت `running` باقی نمی‌ماند، JSONهای قدیمی یا ناقص باعث Crash نمی‌شوند، وضعیت‌های قدیمی Run/Stage/Work Item قابل مشاهده و Repair هستند، Doctor نسخه صحیح Schema 11 را بررسی می‌کند و Backup به‌صورت عمیق Verify و در محیط موقت Restore Drill می‌شود.

```bash
./recon-monitor.sh repair --dry-run --json-health
./recon-monitor.sh repair --max-age-hours 24
./recon-monitor.sh backup verify latest
./recon-monitor.sh backup drill latest
```

راهنمای کامل: `docs/STABILITY_AND_RECOVERY.md` و `MIGRATION-v4.5.1.md`.

## تغییرات رابط و محیط تحلیل در نسخه 3.1

نسخه 3.1 هیچ تغییری در Schema 7 ایجاد نمی‌کند و داده‌های قبلی را حفظ می‌کند. قابلیت‌های اصلی رابط جدید:

- سایدبار گروه‌بندی‌شده برای Workspace، Intelligence و Operations
- Analyst Workbench برای صف بررسی، Incidentها، JS Diffها، Endpointها و Noteها
- Dark و Light theme با ذخیره محلی انتخاب کاربر
- جست‌وجوی سریع با `Command/Ctrl + K` یا کلید `/`
- نمایش یکپارچه Severity، Priority، Status، Lifecycle و Confidence
- صفحه حرفه‌ای Alert با Risk rationale، Workflow، شواهد مرتبط و تاریخچه
- صفحه حرفه‌ای Asset با DNS، HTTP/TLS، Endpoint، Graph، Note و Evidence
- Diff جاوااسکریپت با رنگ‌بندی semantic برای خطوط اضافه، حذف و Hunk
- جدول‌های دارای Header ثابت، Filterهای خواناتر و طراحی Responsive

صفحه Workbench:

```bash
./recon-monitor.sh dashboard restart --open
```

سپس از منوی Dashboard وارد `Workbench` شو یا آدرس `/workbench` را باز کن. راهنمای فنی این محیط در `docs/ANALYST_WORKSPACE.md` قرار دارد.

---



## انجین Behavioral Intelligence در نسخه 4.5.0

نسخه 4.5 بدون ارسال درخواست شبکه‌ای جدید، Analysisهای ذخیره‌شده را با یکدیگر مقایسه می‌کند. تغییر مرز احراز هویت، تغییر ساختاری پاسخ، شواهد تخصصی REST، GraphQL، WebSocket، OAuth/OIDC و Cache و همچنین روابط هویت، Tenant، Role و Object استخراج می‌شوند. این داده‌ها می‌توانند Candidate را تقویت یا تضعیف کنند، اما هیچ Candidate به‌صورت خودکار تأیید نمی‌شود.

```bash
./recon-monitor.sh analysis replay --run RUN_ID --profile balanced
./recon-monitor.sh analysis behavioral
./recon-monitor.sh analysis boundary-diffs
./recon-monitor.sh analysis response-diffs
./recon-monitor.sh analysis protocols
./recon-monitor.sh analysis identity-graph
```

صفحه داشبورد: `/behavioral-intelligence`  
مستندات: `docs/BEHAVIORAL_INTELLIGENCE_ENGINE.md`  
راهنمای ارتقا: `MIGRATION-v4.5.md`

## داشبورد تصمیم‌محور در نسخه 4.3.1

نسخه 4.3.1 ساختار Dashboard را از نمایش هم‌زمان ده‌ها نوع داده به یک جریان سه‌مرحله‌ای تبدیل می‌کند:

```text
Command center → Review queue → Technical drill-down
```

صفحه اصلی ابتدا موارد نیازمند تصمیم، Candidateهای قوی، موارد نیازمند Evidence و سلامت سیستم را نشان می‌دهد. Inventory کامل همچنان موجود است، اما در بخش Explore و Advanced tools قرار گرفته تا صف بررسی شلوغ نشود.

صفحه `/workbench` دارای Viewهای زیر است:

```text
Review now
Needs evidence
Watchlist
Confirmed
All active
```

صفحه `/bug-candidates` به‌صورت پیش‌فرض Card-based است و Table view نیز برای مرور حجمی حفظ شده است. Breadcrumb، Focus target، Compact density و Focus mode نیز اضافه شده‌اند. Schema همچنان 10 است و هیچ رفتار Recon یا Active testing تغییر نکرده است. جزئیات در `docs/DECISION_CENTERED_DASHBOARD.md` و `MIGRATION-v4.3.1.md` قرار دارد.

## ۱. Dry Run و Scope Preview

دستور `--dry-run` هیچ درخواست شبکه‌ای ارسال نمی‌کند و این اطلاعات را نشان می‌دهد:

- Root، Include و Exclude تارگت
- ماژول‌های فعال و غیرفعال
- فعال یا غیرفعال بودن مراحل Active
- Rate limit و Workerها
- سقف زمان، درخواست HTTP، DNS، دانلود و Asset جدید
- گیت‌های مجوز

خروجی JSON برای اتوماسیون:

```bash
./recon-monitor.sh run \
  --target abercrombie.com \
  --dry-run \
  --json-plan
```

## ۲. Run Budget

برای هر تارگت بودجه‌های زیر قابل تنظیم‌اند:

```text
max_runtime_minutes
max_http_requests
max_dns_queries
max_download_mb
max_new_assets
```

اگر بودجه تمام شود، مرحله با خطای کنترل‌شده متوقف می‌شود و وضعیت Run، Budget و Work Itemها در دیتابیس باقی می‌مانند.

نمونه Policy:

```json
{
  "limits": {
    "max_runtime_minutes": 120,
    "max_http_requests": 10000,
    "max_dns_queries": 5000,
    "max_download_mb": 500,
    "max_new_assets": 5000
  }
}
```

## ۳. Queue، Worker و Resume آیتمی

جدول `work_items` وضعیت هر کار را نگه می‌دارد:

```text
queued
running
completed
retry_pending
failed
skipped
```

در نسخه 3، Queue آیتمی برای دانلود و تحلیل JavaScript و اعتبارسنجی Endpoint فعال است. پس از قطع اجرا، موارد کامل‌شده دوباره پردازش نمی‌شوند. ابزارهای Batch مانند Subfinder، Katana و httpx همچنان Batch داخلی خودشان را مدیریت می‌کنند.

ادامه یک Run قطع‌شده:

```bash
./recon-monitor.sh run --resume RUN_ID
```

## ۴. Database Writer و SQLite مقاوم

SQLite دیتابیس اصلی برنامه باقی مانده است. تنظیمات پایداری شامل:

```text
WAL mode
busy_timeout
foreign_keys
transactions
thread-safe connections
single writer service for queued mutations
```

این معماری احتمال خطاهای هم‌زمانی و Threading را کاهش می‌دهد.

## ۵. Ignore Rules

برای کاهش نویز می‌توان Rule تعریف کرد:

```bash
./recon-monitor.sh ignore add \
  --type url \
  --pattern '*/analytics/*'
```

دستورات:

```bash
./recon-monitor.sh ignore list
./recon-monitor.sh ignore test 'https://example.com/analytics/a.js'
./recon-monitor.sh ignore disable RULE_ID
./recon-monitor.sh ignore enable RULE_ID
./recon-monitor.sh ignore remove RULE_ID
```

Ruleها قبل از ایجاد Event و Alert بررسی می‌شوند.

## ۶. URL Canonicalization

URLها پیش از ذخیره نرمال می‌شوند:

- Host و Scheme به lowercase تبدیل می‌شوند.
- Portهای پیش‌فرض حذف می‌شوند.
- Fragment حذف می‌شود.
- Queryها مرتب می‌شوند.
- پارامترهای رایج Tracking و Cache Busting حذف می‌شوند.
- مسیر و Slashهای تکراری اصلاح می‌شوند.

این کار تعداد URLهای منطقیِ تکراری را کم می‌کند.

## ۷. تحلیل هوشمند و Confidence

نسخه 3 قابلیت‌های نسخه 2.2 را نگه داشته و تکمیل کرده است:

- Detailed و Redacted JavaScript Diff
- Endpoint classification
- Technology confidence و Evidence
- Explainable risk score
- Discovery confidence چندمنبعی
- Asset Graph
- DNS و TLS history

Confidence دارایی بر اساس شواهدی مانند Sourceهای Passive، DNS resolution، HTTP response و مشاهده تکراری محاسبه می‌شود.

## ۸. Endpoint Validation محدود

ماژول `endpoint_validation` پیش‌فرض خاموش است. وقتی در Policy فعال شود:

- فقط URLهای داخل Scope بررسی می‌شوند.
- فقط درخواست `HEAD` ارسال می‌شود.
- Payload، Fuzzing یا دورزدن Authentication انجام نمی‌شود.
- Rate limit و Run budget رعایت می‌شوند.
- پاسخ‌هایی مانند `401` و `403` به‌عنوان Endpoint موجود ولی محافظت‌شده ثبت می‌شوند.

فعال‌سازی در Wizard:

```bash
./recon-monitor.sh setup
```

قبل از اجرا حتماً Dry Run را ببین.

## ۹. Change Correlation و Asset Lifecycle

تغییرات مرتبط به یک Incident گروه‌بندی می‌شوند؛ مثلاً تغییر هم‌زمان IP، TLS، JS و Endpointهای یک Host.

چرخه عمر Asset:

```text
new
active
inactive
retired
reappeared
```

صفحات Dashboard:

```text
Incidents
Lifecycle
```

## ۱۰. Evidence Integrity و Content-Addressed Storage

فایل‌های JavaScript و Source Map بر اساس SHA-256 در مسیر Object Store ذخیره می‌شوند:

```text
state/objects/sha256/...
```

فایل تکراری فقط یک بار ذخیره می‌شود و دیتابیس Reference نگه می‌دارد.

Evidence ZIP شامل این فایل‌هاست:

```text
MANIFEST.json
MANIFEST.sha256
```

Manifest برای هر فایل Hash و Size ثبت می‌کند تا تغییر بعدی قابل تشخیص باشد.

## ۱۱. Plugin SDK

مشاهده Pluginها:

```bash
./recon-monitor.sh plugins list
./recon-monitor.sh plugins health
```

ساختار Plugin خارجی:

```text
plugins/my-plugin/plugin.json
```

نمونه Manifest:

```json
{
  "name": "my-safe-plugin",
  "version": "1.0",
  "category": "passive",
  "enabled": false,
  "requires_authorization": false,
  "capabilities": ["metadata"]
}
```

Plugin SDK در این نسخه Registry و Health Check ارائه می‌کند. اجرای Plugin سفارشی باید محدود، قابل بازبینی و Scope-aware طراحی شود.

## ۱۲. Dashboard با Session و RBAC

ساخت مدیر اولیه:

```bash
./recon-monitor.sh dashboard auth-set \
  --username admin
```

شروع:

```bash
./recon-monitor.sh dashboard start --open
```

مدیریت:

```bash
./recon-monitor.sh dashboard status
./recon-monitor.sh dashboard logs --lines 200
./recon-monitor.sh dashboard restart --open
./recon-monitor.sh dashboard stop
```

نسخه 3 از این موارد استفاده می‌کند:

- Session login
- نقش‌های `viewer`، `analyst` و `admin`
- HttpOnly و SameSite Cookie
- CSRF token برای عملیات POST
- Session expiration
- Login throttling
- Audit log

مدیریت کاربران:

```bash
./recon-monitor.sh users add \
  --username analyst1 \
  --role analyst

./recon-monitor.sh users list
./recon-monitor.sh users disable --username analyst1
```

Dashboard پیش‌فرض فقط روی `127.0.0.1` اجرا می‌شود. برای دسترسی شبکه‌ای از VPN، SSH tunnel یا TLS reverse proxy استفاده کن.

## ۱۳. API محلی و Tokenهای دارای نقش

ساخت Token:

```bash
./recon-monitor.sh api token-create \
  --name local-admin \
  --role admin
```

Token فقط هنگام ساخت نمایش داده می‌شود؛ آن را مانند رمز نگهداری کن.

شروع API:

```bash
./recon-monitor.sh api start
./recon-monitor.sh api status
```

آدرس پیش‌فرض:

```text
http://127.0.0.1:8790/api/v1/status
```

نمونه درخواست:

```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8790/api/v1/assets
```

مدیریت Tokenها:

```bash
./recon-monitor.sh api token-list
./recon-monitor.sh api token-revoke --id TOKEN_ID
./recon-monitor.sh api stop
```

نقش‌ها:

```text
viewer
analyst
worker
admin
```

## ۱۴. Remote Worker محدود

Remote Worker فقط Taskهای محدود و ازپیش‌تعریف‌شده را قبول می‌کند:

```text
http_head
download_url
```

Worker قبل از اجرا Rootهای مجاز را بررسی می‌کند و Command دلخواه Shell اجرا نمی‌کند.

```bash
./recon-monitor.sh worker run \
  --server http://127.0.0.1:8790 \
  --token "$WORKER_TOKEN" \
  --name mac-worker
```

برای یک بار Poll:

```bash
./recon-monitor.sh worker run \
  --server http://127.0.0.1:8790 \
  --token "$WORKER_TOKEN" \
  --once
```

## ۱۵. Saved Views

```bash
./recon-monitor.sh views add \
  --name high-risk \
  --type alerts \
  --query '{"minimum_score":80,"status":"new"}'

./recon-monitor.sh views list
./recon-monitor.sh views remove --name high-risk
```

Saved Viewها در Dashboard و API قابل استفاده‌اند.

## ۱۶. macOS Keychain

ذخیره Secret:

```bash
./recon-monitor.sh secrets set telegram-token
```

مشاهده فقط نام Secretها:

```bash
./recon-monitor.sh secrets list
```

حذف:

```bash
./recon-monitor.sh secrets delete telegram-token
```

برای خواندن خودکار Token تلگرام از Keychain:

```text
USE_MACOS_KEYCHAIN="yes"
TELEGRAM_BOT_TOKEN=""
```

نام‌های پشتیبانی‌شده خودکار شامل `telegram-token`، `github-token`، `notify-webhook` و `dashboard-secret` هستند. مقدار Secret در خروجی `list` نمایش داده نمی‌شود.

## ۱۷. Backup و Restore

ساخت Backup:

```bash
./recon-monitor.sh backup create
```

همراه Object Store:

```bash
./recon-monitor.sh backup create --include-objects
```

مدیریت:

```bash
./recon-monitor.sh backup list
./recon-monitor.sh backup verify BACKUP_ID
./recon-monitor.sh backup restore BACKUP_ID --force
```

Restore قبل از جایگزینی داده‌ها یک Safety Backup جدید می‌سازد.

## ۱۸. Update و Rollback

بررسی Manifest قابل‌اعتماد:

```bash
./recon-monitor.sh update check
```

نصب بسته محلی با Hash:

```bash
./recon-monitor.sh update install \
  --package /path/to/recon-monitor-v3.x.zip \
  --sha256 EXPECTED_SHA256 \
  --signature /path/to/release.sig \
  --public-key /path/to/release-public-key.pem
```

Rollback:

```bash
./recon-monitor.sh update rollback
```

امضای OpenSSL اختیاری است، اما برای Releaseهای رسمی پیشنهاد می‌شود. Updater عمومی میزبانی‌شده داخل بسته وجود ندارد. برای `check` باید `RECON_UPDATE_MANIFEST` را روی یک URL HTTPS یا فایل Manifest مورد اعتماد تنظیم کنی.

## ۱۹. PostgreSQL اختیاری

SQLite دیتابیس اصلی و Transactional باقی می‌ماند. PostgreSQL در این نسخه فقط Mirror تحلیلی اختیاری است.

در `config.env`:

```text
POSTGRES_DSN="postgresql://user:pass@127.0.0.1/recon"
```

سپس:

```bash
./recon-monitor.sh postgres status
./recon-monitor.sh postgres init
./recon-monitor.sh postgres sync
```

این قابلیت به پکیج Python `psycopg` نیاز دارد.

## ۲۰. Integration Test و Benchmark

Unit test:

```bash
./recon-monitor.sh test --verbose
```

Integration test محلی بدون اسکن دامنه عمومی:

```bash
./recon-monitor.sh test --integration
```

Benchmark:

```bash
./recon-monitor.sh benchmark
```

Integration Fixture تغییر JS، Endpoint و پاسخ محافظت‌شده `401` را روی وب‌سرور محلی بررسی می‌کند.

## ۲۱. Doctor

```bash
./recon-monitor.sh doctor
```

علاوه بر ابزارهای Recon، موارد زیر هم بررسی می‌شوند:

- Schema و Integrity دیتابیس
- Plugin registry
- Dashboard و API
- Keychain
- PostgreSQL mirror
- فضای دیسک
- Lock
- Telegram
- LaunchAgent

## ۲۲. Audit Log

اعمال مدیریتی حساس در دیتابیس و فایل JSONL ثبت می‌شوند؛ مانند:

```text
Policy change
API token creation
User management
Backup/restore
Update/rollback
Active-module changes
```

فایل Audit در مسیر State نگهداری می‌شود و نباید همراه اطلاعات عمومی منتشر شود.

## محدودیت‌های آگاهانه نسخه 3.0

- Queue آیتمی فعلاً برای JavaScript و Endpoint Validation است؛ ابزارهای Batch خارجی Batch خودشان را دارند.
- PostgreSQL فقط Mirror تحلیلی است.
- Worker از اجرای Command دلخواه پشتیبانی نمی‌کند.
- Endpoint Validation فقط `HEAD` و داخل Scope است و پیش‌فرض خاموش است.
- API و Dashboard به‌صورت پیش‌فرض TLS ندارند و باید روی Loopback یا تونل امن استفاده شوند.
- Updater به Manifest مورد اعتماد یا بسته محلی نیاز دارد.

## روال پیشنهادی روزمره

```bash
cd ~/Downloads/recon-monitor

./recon-monitor.sh doctor
./recon-monitor.sh run --target abercrombie.com --dry-run
./recon-monitor.sh run --target abercrombie.com
./recon-monitor.sh dashboard start --open
```

قبل از Update یا تغییر مهم:

```bash
./recon-monitor.sh backup create
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
```

## انجین تحلیل 4.0

Recon Monitor اکنون یک انجین آفلاین مبتنی بر شواهد و فرضیه دارد. این نسخه Baseline مخصوص هر تارگت، یادگیری آماری از تصمیم تحلیل‌گر، شواهد موافق و مخالف، خوشه‌بندی موارد مشابه، Replay، Endpoint Schema، Playbook، Deployment Signature، تحلیل استاتیک Data-flow جاوااسکریپت، Source Map، GraphQL، Secret confidence، روابط API، Business Context و Calibration را اضافه می‌کند.

```bash
./recon-monitor.sh analyze --run RUN_ID
./recon-monitor.sh analysis replay --run RUN_ID
./recon-monitor.sh analysis quality
./recon-monitor.sh analysis calibration
```

صفحات جدید داشبورد: `/analysis`، `/hypotheses`، `/clusters`، `/dataflows` و `/analysis-quality`.

Analysis و Replay آفلاین هستند و درخواست جدیدی به تارگت ارسال نمی‌کنند. Candidateها و Hypothesisها به معنی تأیید آسیب‌پذیری نیستند. بخش AI عمداً در این نسخه وجود ندارد.

جزئیات کامل در `docs/ANALYSIS_ENGINE.md` قرار دارد.

## انجین Bug Candidate در نسخه 4.1

Replay تحلیل اکنون شواهد موجود را به خانواده‌های احتمالی باگ نگاشت می‌کند، بدون اجرای تست تهاجمی. برای هر Candidate امتیازهای جداگانه احتمال، قدرت شواهد و اثر احتمالی، شواهد موافق و مخالف، اطلاعات مفقود و اقدام بعدی امن ثبت می‌شود. ابزار هیچ Candidate را خودکار تأیید نمی‌کند.

```bash
./recon-monitor.sh analyze --run RUN_ID
./recon-monitor.sh analysis candidates --limit 100
```

صفحات جدید داشبورد: `/bug-candidates` و `/bug-candidate`. راهنمای کامل در `docs/BUG_CANDIDATE_ENGINE.md` قرار دارد.


## کیفیت Candidate و تحلیل معنایی در نسخه 4.3

این نسخه برنامه‌های 4.2 و 4.3 را یکجا پیاده می‌کند. Candidate Engine اکنون برای هر خانواده باگ شرط‌های شواهد اختصاصی دارد، سیگنال‌های هم‌ریشه را دوباره‌شماری نمی‌کند و علاوه بر احتمال و اثر، کیفیت Observation، ارزش بررسی، تازگی، نویز تاریخی، Lifecycle و Profile تحلیل را ثبت می‌کند.

Profileهای آفلاین:

```text
quiet
balanced
research
```

نمونه Replay بدون ارسال درخواست جدید:

```bash
./recon-monitor.sh analysis replay \
  --run RUN_ID \
  --profile balanced
```

Semantic Intelligence نیز این داده‌ها را از شواهد ذخیره‌شده می‌سازد:

```text
Endpoint contract
Authentication boundary
Response-shape fingerprint
Semantic JavaScript units
Feature flags
Parameter relationships
Candidate bundles
```

دستورات مدیریتی:

```bash
./recon-monitor.sh analysis candidate-calibration
./recon-monitor.sh analysis candidate-evaluate
./recon-monitor.sh analysis bundles --limit 100
./recon-monitor.sh analysis semantic --limit 200
```

صفحات جدید Dashboard:

```text
/candidate-quality
/candidate-bundles
/semantic-intelligence
```

Schema دیتابیس در این نسخه 10 است. هیچ AI، Exploit خودکار یا تأیید خودکار آسیب‌پذیری اضافه نشده است. جزئیات در `docs/CANDIDATE_RELIABILITY_ENGINE.md`، `docs/SEMANTIC_CANDIDATE_INTELLIGENCE.md` و `MIGRATION-v4.3.md` قرار دارد.

## بهینه‌سازی داشبورد در نسخه 5.0.1

برای معماری Cache، صفحه‌بندی و Deep Refresh به `docs/DASHBOARD_PERFORMANCE.md` مراجعه کنید.
