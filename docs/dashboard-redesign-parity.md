# معیارهای حفظ قابلیت‌ها در بازطراحی داشبورد

طرح منتخب: صفحهٔ اصلی «مینیمال متعادل»، با نمای مستقل و دقیق برای بررسی اجرای Run. مرجع بررسی، کد نسخهٔ 8.8.3 در `app/dashboard_core.py`، افزونه‌های زمان اجرا در `app/dashboard.py` و `app/progress_tracking.py`، جست‌وجو در `app/workspace_v7.py` و قراردادهای موجود در تست‌های داشبورد است.

این سند، فهرست مرجع نسخهٔ قبلی و معیار پذیرش پیاده‌سازی جدید است. بازطراحی اکنون به داده‌های واقعی برنامه متصل است؛ وضعیت آزمون‌ها و محدودیت‌های بررسی در انتهای سند آمده‌اند. ثبت یک قابلیت در ماتریس، به‌تنهایی اثبات رفتار آن در مرورگر نیست.

## اصل حفظ اطلاعات

صفحهٔ اصلی، خلاصه و موارد نیازمند توجه را نمایش می‌دهد. داده‌ها، دسته‌ها، فیلترها، عملیات و مسیرهای تخصصی فعلی باید در صفحهٔ مرتبط یا نمای جزئیات، با عنوان روشن و مسیر قابل کشف، در دسترس بمانند. هیچ قابلیت تخصصی با یک فیلتر عمومی جایگزین نمی‌شود. مقصدی که از صفحهٔ اصلی جمع می‌شود باید پیش از حذف نمایش قدیمی، در نقشهٔ زیر ثبت و قابل دسترسی باشد.

فیلترهای فعال حتی هنگام بسته بودن پنل پیشرفته دیده می‌شوند. پاک‌سازی فیلتر، نمایش همهٔ رکوردها، تعداد نتایج، ترتیب نمایش، حالت خالی و تفاوت آن با خطای بارگذاری باید روشن باشند. جابه‌جایی بین جدول، کارت، دسته‌ها و دادهٔ خام باید Target و فیلترهای سازگار را حفظ کند؛ فیلتر ناسازگار با نمای مقصد نباید به شکل نامرئی نتایج را محدود کند.

## دسته‌ها و نوع‌های دادهٔ فعلی

۹ دستهٔ معنایی Recon باید با شناسه‌های فعلی حفظ شوند:

| شناسه | عنوان فعلی | مفهوم |
|---|---|---|
| hosts | Hosts & Subdomains | میزبان‌ها و زیردامنه‌ها |
| apis | APIs | API، GraphQL، WebSocket و مسیرهای مشابه |
| authentication | Authentication | ورود، نشست، توکن، بازیابی و هویت |
| admin_internal | Admin / Internal | مدیریت، داخلی، Debug و کنسول |
| file_upload | File & Upload | بارگذاری، دریافت، Import، Export و فایل |
| data_object | Data / Object | شناسهٔ اشیا و دسترسی به دادهٔ کسب‌وکار |
| client_side | Client-side / JavaScript | JavaScript، Source Map و مسیرهای سمت کاربر |
| infrastructure | Infrastructure | پورت، سرویس، HTTP/TLS و فناوری |
| other | Other | دادهٔ مشاهده‌شده با طبقه‌بندی نامشخص |

دسته‌ها چندبرچسبی‌اند؛ یک مشاهده می‌تواند در چند دسته باشد. تعداد دسته‌ها نباید به عنوان تعداد یکتای کل مشاهدات جمع زده شود. دستهٔ Other و داده‌های بدون طبقه‌بندی باید قابل مشاهده و جست‌وجو باشند.

۶ نوع دادهٔ خام مستقل‌اند و نباید زیر یک عنوان مبهم ادغام شوند: Hosts، URLs، Endpoints، Ports، JavaScript و Fingerprints. تب‌های Overview، Categories و Raw Data حفظ می‌شوند. طبقه‌بندی، تفسیر دادهٔ خام است و جایگزین مشاهدهٔ اصلی و منبع آن نمی‌شود.

## نقشهٔ حفظ فیلترها و مسیرهای تخصصی

فیلترهای زیر در نسخهٔ مرجع وجود دارند و کنترل‌های بومی آن‌ها در پیاده‌سازی جدید حفظ شده‌اند. نام پارامترها و مقصدها در فایل `dashboard-redesign-baseline.json` ثبت شده‌اند و آزمون عدم پسرفت با آن‌ها مقایسه می‌شود.

| بخش فعلی | فیلترها و قابلیت‌های لازم برای حفظ | محل پیشنهادی در طرح جدید |
|---|---|---|
| Recon / Categories | Target، جست‌وجوی مقدار/شرح/دسته/منبع، دسته، بازهٔ مشاهده | تب Categories با فیلترهای محلی |
| Recon / Raw Data | Target، جست‌وجو، نوع خام، بازهٔ مشاهده؛ Confidence، منبع، اولین/آخرین مشاهده و Run | تب Raw Data؛ جزئیات هر ردیف |
| Assets / DNS | متن، Target، Lifecycle، وضعیت Resolution، Wildcard، Tag، حداقل Confidence، زمان، Sort | دادهٔ خام Hosts و صفحهٔ تخصصی Assets |
| URLs | متن، Target، Kind، Source، زمان، Sort | دادهٔ خام URLs و صفحهٔ تخصصی URLs |
| Endpoints | متن، Target، Category/Class، Kind، Source، Confidence، زمان، Sort | دادهٔ خام Endpoints و نمای تخصصی |
| JavaScript | متن، Target، Kind، Redacted، زمان، Sort؛ نسخه‌ها، Diff و منبع Run | دادهٔ خام JavaScript؛ جزئیات و Diff |
| HTTP / TLS | متن، Target، Status، Status class، Server، Technology، CDN، TLS، زمان، Sort | دادهٔ خام Fingerprints و نمای تخصصی |
| Potential Findings | Actionable/Strong/Needs review/Needs evidence/All، متن، Target، Family، State، Decision، Reachability، حداقل Likelihood/Evidence/Exploitability/Investigation، Sort، کارت/جدول | فهرست یافته‌ها با فیلترهای پایه و پنل پیشرفته |
| Investigation queue | Target، Family، Cluster، صف کامل، دلایل اولویت، زمینهٔ همبستگی و تغییرات اخیر | تب یا بخش مستقل در Potential Findings؛ جزئیات Cluster |
| Reviewed cases | متن، Target، Family، State، Owner/Unassigned، Validation، Scope، حداقل Priority/Readiness، Sort، Page | بخش Cases داخل فضای یافته‌ها |
| Review workbench | View، متن، Target، Family، State، Lifecycle، Assignee، حداقل Investigation | نمای Review queue با فیلترهای تخصصی |
| Safe validation | متن، Target، Family، Case state، Validation state، Level، Plan status، Result و انتخاب Case/Plan | بخش Validation با همان کنترل‌های تأیید |
| Security stories | متن، Target، Status، حداقل Priority، زمان، Sort | نمای Stories در Analysis یا یافته‌ها |
| Change alerts | Attention/All، متن، Target، Kind، Added/Changed/Removed، Priority، زمان، Sort، پیش‌تنظیم‌ها | فضای Alerts و مقایسهٔ Runها |
| Signal workflow | متن، Target، Status، Severity، Priority، Owner، Tag، حداقل Risk، زمان، Sort | تب Signals مستقل از Change alerts |
| Runs | متن/شناسه/خطا، Target، Status، Has error/No error، زمان، Sort؛ Resumed from، Review، Report | تاریخچهٔ Run و نمای جزئیات اجرای منتخب |
| Compare / Daily | Run قدیم/جدید، Target، ساعات اخیر، نمونهٔ Added/Removed | نمای Compare و Recent changes |
| کیفیت و اولویت | Family/Parser/Rule/View/حداقل Total در Engine quality؛ Target/Result/Confidence در Validation intelligence؛ Target/Effort/Value در Review priority | زیرصفحه‌های تخصصی مرتبط با Analysis و یافته‌ها |
| عملیات و ممیزی | Saved views، Notes، Actor/Action در Audit، هدف/Run در Data quality، سلامت ذخیره‌سازی، Performance، Retention، Templates و Plugins | زیرمنوهای روشن در فضای مرتبط و System |

فیلتر Owner متعلق به Signal workflow است. اشارهٔ تاریخی به `name='owner'` در یک کامنت HTML صفحهٔ Change alerts، کنترل واقعی آن صفحه محسوب نمی‌شود. قراردادهای قدیمی مبتنی بر وجود رشته در HTML به تنهایی اثبات حفظ رفتار نیستند.

## اطلاعات مهمی که نباید در مینیمال‌سازی پنهان شوند

| اطلاعات | خلاصهٔ لازم | جزئیات قابل دسترسی |
|---|---|---|
| وضعیت Run و ابزار | Running / Success / Partial / Timeout / Failed / Not run؛ آخرین خطای مهم | زمان شروع/پایان، مدت، Return code، علت توقف، ورودی، خروجی، کار ناقص، Attempt و Resume lineage |
| پیشرفت زنده | مرحلهٔ فعلی، کار انجام‌شده/کل در صورت معلوم بودن، وضعیت سلامت | Heartbeat age، آخرین پیشرفت، مدت هر مرحله، خطا و محدودیت دید اجرای قدیمی |
| پوشش و نقاط کور | هشدار واضح برای ورودی ناقص و پوشش نامعلوم | Coverage / Blind Spots و محدودیت منبع؛ درصد تنها با تعریف و مخرج معتبر |
| یافته‌ها | عنوان، Target/Endpoint، وضعیت بررسی، اولویت و قوت شواهد | Likelihood، Evidence strength، Exploitability، Impact، Investigation و Reachability با نام روشن |
| Cluster و صف بررسی | اولویت بررسی و وضعیت تأییدنشده | Queue score، Bug proximity، Target evidence، Cluster strength، Recent change، خانواده‌های جایگزین و دلایل |
| شواهد و استدلال | منبع و لینک جزئیات | Supporting/Missing/Counter evidence، فرضیه‌ها، دلیل رد/پذیرش، نسخهٔ Engine/Rule و Audit snapshot/hash |
| تغییرات | نوع تغییر، شدت/اولویت، Target و زمان | Run قبلی/جدید، Added/Removed/Changed، زمینهٔ پاسخ/فناوری/Authentication/Response shape |
| JavaScript | شمار کشف/انتخاب/دریافت و وضعیت ورودی | مسیر کشف → انتخاب → طبقه‌بندی → Fetch، خطا و دلیل صفر شدن هر مرحله |
| دادهٔ خام | مشاهده و نوع داده | Confidence، Sources، First seen، Last seen، Run، نسخه‌ها و فایل مرتبط |

اولویت بررسی، نزدیکی به یک خانوادهٔ باگ و تغییرات اخیر، جایگزین شواهد یا احتمال تأیید آسیب‌پذیری نیستند. نمایش جدید باید این تمایز فعلی را نگه دارد و امتیاز همبستگی را دوباره به شواهد اضافه نکند.

## عملیات و مسیرهایی که باید قابل کشف باقی بمانند

- Command Center و چهار فضای Recon، Analysis، Potential Findings و Alerts؛ صفحهٔ مرتبط فعال باشد.
- زیرمسیرهای Recon شامل Assets، Endpoints، URLs، JavaScript/Diff، HTTP/TLS، Runs، Attack surface، Graph، Coverage، Target memory، Smart recon، Browser capture و Lifecycle.
- زیرمسیرهای یافته‌ها شامل Cases، Validation، Autopilot، Report builder، Candidate quality/Bundles، Workbench، Validation intelligence، Review priority، Report quality و False-positive learning.
- زیرمسیرهای Analysis شامل کیفیت تحلیل، استدلال، Hypotheses، Clusters، Dataflows، Semantic/Behavioral/Differential intelligence، Auth contexts و Evidence gaps. این مسیرها فقط با خواندن منوی اصلی قابل فهرست‌برداری نیستند.
- Alerts، Signal workflow، Alert detail، Change intelligence، Compare، Daily و Incidents.
- تمام مقصدهای فعلی System در سه گروه Operations، Safety & governance و System quality & configuration.
- جزئیات دارایی، یادداشت و برچسب؛ ثبت تصمیم، مالک و وضعیت؛ تاریخچهٔ Workflow، Saved views، Export evidence و Report.
- کنترل‌های Run review، Attempt، Target و Stage؛ عملیات Stop/Next/Resume و هر فرم موجود باید همان روش POST، نقش مجاز، CSRF، تأیید و پیام نتیجه را حفظ کند. پنل نمایشی نباید خودکار عملیاتی را اجرا کند.
- ورود/خروج، نام کاربر و نقش، میان‌بر جست‌وجو و فرمان، Light/Dark، Density، Focus، ناوبری موبایل و تنظیم‌های ذخیره‌شده.

تغییر عنوان یا محل نمایش نباید Deep link، Query parameter، Alias قدیمی، Export، Report یا رفتار Back/Forward را بشکند. مسیر گزارش `/report/<run_id>` و مسیرهای افزوده‌شده در Runtime جداگانه ثبت شده‌اند.

## جست‌وجوی نسخهٔ مرجع و پیاده‌سازی جدید

`universal_search()` در نسخهٔ مرجع Cases، Stories، Candidates، Endpoints، Assets، JavaScript indicators، Evidence و Browser captures را روی فیلدهای منتخب جست‌وجو می‌کند. قرارداد هشت‌گروهی آن برای CLI حفظ شده است. جست‌وجوی جدید داشبورد در `dashboard_search.py` قرار دارد و پاسخ API قدیمی را تغییر نمی‌دهد.

فهرست جدید ۴۶ گروه SQL مشخص، گروه مشتق‌شدهٔ Change alerts و گروه اختیاری Stored text دارد. علاوه بر هشت گروه قبلی، داده‌های خام URL/Port/Fingerprint/DNS/JS، Run و Stage و Analysis، Notes و Tags، یافته‌ها و هشدارها، Hypotheses و Clusters و Dataflows، شواهد معنایی و رفتاری، وضعیت و تغییرات Authentication/Response، Validation، Target memory و گزارش‌ها قابل جست‌وجو هستند. فهرست دقیق جدول‌ها و فیلدهای مجاز در `SEARCH_GROUPS` ثبت شده است؛ این قابلیت ادعای جست‌وجوی تمام جدول‌های داخلی برنامه را ندارد.

جست‌وجو، تعداد واقعی هر گروه و صفحه‌بندی سراسری ۱۰۰ردیفی دارد؛ انتخاب گروه، Target، Source Run و بازهٔ زمانی حفظ می‌شود. `%` و `_` متن واقعی‌اند؛ `*` فرمان صریح نمایش همه است. هر نتیجه منبع و لینک صفحهٔ مرتبط دارد و «Stored details» تمام فیلدهای مجاز همان رکورد را با Escape مناسب نمایش می‌دهد. داده‌های حساب و اطلاعات احراز هویت داشبورد، Hash گذرواژه/توکن و Hash عبارت تأیید Validation در فهرست نیستند.

جست‌وجوی محتوای فایل اختیاری و محلی است: فایل‌های JavaScript ارجاع‌شده در دیتابیس و خروجی متنی Runهای موجود را بدون دریافت شبکه می‌خواند. خواندن در قطعه‌های کوچک انجام می‌شود و سقف پنهان طول محتوا ندارد. فایل بیرون از مسیرهای مجاز و Symlink رد می‌شود؛ تعداد فایل‌های غیرقابل‌خواندن اعلام می‌شود. این گزینه شامل تمام فایل‌های لپ‌تاپ، Config یا هر لاگ دلخواه نیست.

سقف‌های قبلی منابع Recon و Change alerts برداشته شده‌اند. فهرست‌های اصلی Recon، Assets، URLs، Endpoints، Fingerprints، Runs، Potential Findings، Signal alerts و Notes صفحه‌بندی ۱۰۰ردیفی دارند؛ JS indicators نیز ۱۰۰ردیفی و Diffها با پارامتر مستقل ۵۰ردیفی‌اند. سایر نماهای تخصصی همچنان قراردادهای قبلی خود را دارند؛ همهٔ ۷۵ Handler به صفحه‌بندی جدید تبدیل نشده‌اند. گردآوری Recon برای طبقه‌بندی همچنان رکوردهای منطبق را در سرور می‌سازد، هرچند مرورگر تنها صفحهٔ منتخب را دریافت می‌کند. کارایی دیتابیس‌های بسیار بزرگ باید جداگانه اندازه‌گیری شود.

صفحهٔ اصلی عمداً پیش‌نمایش محدود تغییرات را نشان می‌دهد و عنوان آن «High-interest preview» است؛ شمار کامل در Alerts و Search قرار دارد. پوشش All targets به‌صورت Unknown نمایش داده می‌شود؛ برای درصد معتبر باید Target مشخص انتخاب شود.

## رفتار، سلامت و معیار پذیرش

1. ماتریس قبل/بعد برای هر مسیر، Query parameter، کنترل، عملیات و اطلاعات مهم تکمیل شود. هر مورد باید مقصد مشخص و نتیجهٔ قابل بررسی داشته باشد؛ «در نظر گرفته شده» به معنی «انجام شده» نیست.
2. ترکیب فیلترها، حالت All و دستهٔ Other، مرتب‌سازی، تغییر نما، بازگشت از جزئیات و حفظ Target/فیلتر بررسی شود. فیلتر پیشرفتهٔ فعال باید در حالت بسته قابل مشاهده و حذف باشد.
3. شمار نتایج با شمار واقعی مقایسه شود؛ صفحه‌بندی، نتایج فراتر از سقف قبلی، حالت بدون نتیجه و خطای بارگذاری از هم جدا باشند.
4. یافتهٔ احتمالی/تأییدنشده، تغییر مشاهده‌شده، کار تکمیل‌شده و پوشش کامل از هم متمایز باشند. Timeout با خروجی ذخیره‌شده باید Partial بماند. صفر فایل JS نباید بدون علت به عنوان مرحلهٔ کامل نشان داده شود.
5. هویت Run/Target/Analysis، زمان‌ها و منابع در خلاصه و جزئیات سازگار باشند؛ مقایسهٔ هشدار همچنان از Baseline موفق استفاده کند.
6. مسیرهای GET/POST، مجوز نقش‌ها، CSRF، تأیید عملیات، Redaction و Export فعلی حفظ شوند. تغییر نما و بازکردن جزئیات نباید خودکار عملیات اجرا کند.
7. به‌روزرسانی زنده فقط پنل مرتبط را تغییر دهد و محل اسکرول، فوکوس، انتخاب متن و فیلتر را حفظ کند. وجود کد ذخیرهٔ اسکرول، به تنهایی اثبات رفع همهٔ پرش‌های صفحه نیست.
8. صفحهٔ Analysis همچنان خلاصهٔ سریع را بارگذاری کند و محاسبات سنگین شواهد/همبستگی درخواستی بمانند. خواندن همهٔ داده‌ها در مرورگر یا بارگذاری تمام نماهای سنگین برای خلوت شدن ظاهر قابل قبول نیست.
9. بررسی بصری در حالت روشن/تاریک، نمای عادی/فشرده، عرض لپ‌تاپ و موبایل انجام شود؛ برچسب‌ها خوانا، کنترل‌ها با صفحه‌کلید قابل استفاده و جزئیات بدون Hover قابل دسترسی باشند.
10. تست‌های رفتاری موجود و بررسی‌های متناسب با تغییر نهایی اجرا شوند. تست‌های قدیمی که فقط برچسب یا رشته را بررسی می‌کنند، برای ادعای حفظ کامل قابلیت‌ها کافی نیستند. اسکن شبکه برای این مرحله لازم نیست.

## وضعیت این مرحله

صفحهٔ اصلی از بخش‌های تزئینی و دسترسی‌های تکراری خلوت شده است. خلاصهٔ Run، موارد نیازمند توجه، اقدام بعدی، تغییرات اخیر و تاریخچه قابل مشاهده‌اند. فیلترهای پایه ثابت‌اند و کنترل‌های پیشرفته در Details بومی قرار دارند؛ فیلتر فعال حتی در حالت بسته دیده می‌شود و کنترل اصلی آن همچنان فعال است. مسیرهای تخصصی از «Workspace views»، منوی System و Command palette قابل کشف‌اند. Target در جابه‌جایی فضای اصلی و نماهای سازگار حفظ می‌شود.

Run review جدول دائمی Stage outcomes دارد: وضعیت اجرای مرحله از کیفیت جمع‌آوری جداست؛ Partial / Timeout، Exit code، زمان، علت توقف، تعداد مبدأهای Katana و کار باقی‌مانده در خلاصه دیده می‌شوند. زنجیرهٔ ورودی/انتخاب/دریافت JS و دلیل صفر شدن نیز نمایش داده می‌شود. Metrics کامل، Attempt و عملیات Next stage همچنان در دسترس‌اند. دادهٔ قدیمی بدون زمان معتبر، زمان ساختگی دریافت نمی‌کند.

پنل‌های Quality/Review در Runtime داخل Details جمع شده‌اند و کنترل‌های فعلی آن‌ها حفظ شده‌اند. صفحهٔ Analysis همچنان Snapshot سریع دارد و محاسبات سنگین را خودکار اجرا نمی‌کند. به‌روزرسانی زنده از جایگزینی کنترل دارای فوکوس یا متن انتخاب‌شده پرهیز می‌کند و تغییر ارتفاع پنل بالای صفحه را جبران می‌کند. بازگشت به لینک Anchor، اسکرول ذخیره‌شدهٔ فیلتر را تحمیل نمی‌کند و Details مربوط به Anchor باز می‌شود.

| بررسی | نتیجه و دامنه |
|---|---|
| مرجع عدم حذف قابلیت‌ها | مسیرهای GET، ۷۵ Handler، ۹ دسته، ۶ نوع خام و ۶ افزونهٔ Runtime ثبت شده‌اند؛ کنترل‌ها و POSTهای مرجع با کد جدید مقایسه می‌شوند |
| آزمون‌های جدید | ۲۴ تست برای دیتابیس واقعی آزمایشی، ۲۰۵۵ رکورد، صفحه‌بندی و شمار کامل، مرز Target/Run، جست‌وجوی متن، Snapshot، جزئیات Escapeشده، POST/CSRF و محدودیت مسیر فایل |
| مجموعهٔ کامل برنامه | ۱۶۱۷ تست اجرا شد؛ بدون شکست، با یک Skip؛ آزمون‌های جدید داخل همین مجموعه هستند |
| رفتار JavaScript | اجرای بخش‌های واقعی Script در Node با DOM/Fetch کنترل‌شده: اسکرول، فوکوس، انتخاب متن، فرم GET، Hash و Polling؛ بدون درخواست شبکه |
| رندر Runtime | ۱۰ صفحه با Renderer واقعی و دادهٔ ساختگی، با جلوگیری از اتصال به شبکه، بدون خطا ساخته شده‌اند |
| یکپارچگی بسته‌بندی | checksum فایل‌های تغییرکرده و ثبت فایل‌های جدید در `MANIFEST.sha256` بررسی شده‌اند؛ کنترل strict manifest پاس شده است |
| Integration | آزمون موجود Endpoint validation روی سرور Loopback، بدون اتصال به Target بیرونی، پاس شده است |
| تست‌های Cleanup در CI | چهار سناریوی پردازهٔ والدِ خارج‌شده، پیش از اندازه‌گیری Deadline با Pipe واقعی آماده می‌شوند تا هزینهٔ راه‌اندازی مفسر روی Intel جای سناریوی اصلی را نگیرد؛ Timeout و Assertionهای خروجی/مدت/بسته‌شدن منابع حفظ شده‌اند. مجموعهٔ ۲۶تستی با `ResourceWarning` به‌عنوان خطا پاس شده است |
| نسخه و Schema | بررسی سازگاری Release پاس شده: برنامه 8.8.3 و Schema 18؛ Collector و Timeout تغییر نکرده‌اند |
| بررسی مرورگر | باقی مانده: ظاهر روشن/تاریک، عادی/فشرده، عرض لپ‌تاپ/موبایل، Safari و تعامل واقعی با صفحه‌کلید؛ مرورگر نصب‌شده در محیط محلی اجرا نشد و سیاست امنیتی مرورگر ابری بازکردن فایل پیش‌نمایش را مسدود کرد. تست DOM جایگزین بررسی ظاهری نیست |

فرمان آزمون مجموعهٔ کامل همان Discovery استفاده‌شده در فرمان CLI است، با `PYTHONPATH=app`:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

تغییرها برای بررسی در PR پیش‌نویس آماده‌اند. Main و Release این بازطراحی را دریافت نکرده‌اند؛ پیش از Merge، بازبینی مرورگر و نتیجهٔ CI باید ثبت شوند. هیچ اسکن شبکه‌ای برای این مرحله اجرا نشده است.
