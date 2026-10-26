<div dir="rtl" align="right">

<p align="center"><img src="docs/icon.png" width="120" alt="Rat"></p>

<h1 align="center">Rat</h1>

<p align="center">
<a href="./README.md">🇬🇧 English</a> | 🇮🇷 فارسی
</p>

<p align="center">
<a href="https://github.com/ImanMontajabi/Rat/releases/latest"><img alt="آخرین نسخهٔ پایدار" src="https://img.shields.io/github/v/release/ImanMontajabi/Rat?label=stable&sort=semver"></a>
<a href="https://github.com/ImanMontajabi/Rat/releases"><img alt="نسخهٔ شبانه" src="https://img.shields.io/github/v/release/ImanMontajabi/Rat?include_prereleases&label=nightly&sort=date"></a>
<a href="https://github.com/ImanMontajabi/Rat/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ImanMontajabi/Rat/actions/workflows/ci.yml/badge.svg"></a>
<img alt="macOS 14+ arm64" src="https://img.shields.io/badge/macOS-14%2B%20arm64-lightgrey?logo=apple">
<a href="LICENSE"><img alt="مجوز MIT" src="https://img.shields.io/github/license/ImanMontajabi/Rat"></a>
</p>

‏Rat یک نمایشگر شبکه و فایروال برنامه‌محور برای macOS است، با الهام از Little Snitch. Rat نشان می‌دهد هر برنامه، و هر پردازهٔ آن، با کدام سرور حرف می‌زند و موقعیت سرورها را روی نقشهٔ جهان (کاملاً آفلاین) می‌کشد. مشخص می‌کند کدام اتصال از VPN یا پروکسی رد می‌شود و مقصد واقعی پشت پروکسی‌های محلی و تانل‌های SSH را آشکار می‌کند. برنامه‌هایی را هم که مسدود کنید، با فیلتر بستهٔ خود macOS قطع می‌کند. Rat رایگان و متن‌باز (MIT) است: بدون دورهٔ آزمایشی و بدون هیچ پرداختی.

![نمایشگر شبکه: Telegram و Firefox، فیلترشده به اتصال‌های VPN و پروکسی](docs/screenshots/monitor-hierarchy-tags.png)
<sub>داده‌های نمایشی. فیلتر روی «Through a VPN or Proxy» است: Telegram تا اتصالِ پردازهٔ کمکی‌اش از طریق Windscribe باز شده و اتصال‌های Firefox از `ssh -D` و Tor رد می‌شوند. نقشه مسیر «این Mac ← سرور پروکسی (استکهلم) ← مقصد واقعی (مادرید)» را نشان می‌دهد و Summary فقط آنچه را فیلتر نگه داشته می‌شمارد. موقعیت سرورها از یک پایگاه‌دادهٔ آفلاینِ داخل برنامه خوانده می‌شود و هیچ اطلاعاتی از Mac شما خارج نمی‌شود.</sub>

> **محدودیت‌ها را صادقانه بگوییم.** Little Snitch هر اتصال را *پیش از* برقراری متوقف می‌کند و برای این کار به مجوز Network Extension اپل نیاز دارد که فقط با حساب توسعه‌دهندهٔ پولی داده می‌شود. Rat چنین مجوزی ندارد، پس **واکنشی** کار می‌کند: اتصال را بعد از شروع می‌بیند و اتصال‌های برنامهٔ مسدودشده را از راه پورت‌های محلی‌شان قطع می‌کند. یک پردازهٔ تازه ممکن است پیش از قطع‌شدن، چند بستهٔ اول را بفرستد. برنامه امضای ad-hoc دارد و notarize نشده است. جزئیات در [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (بخش‌های ۷، ۸ و ۱۰).

## چرا Rat؟ مشکلاتی که هر روز با آن‌ها درگیرید

اگر در ایران برای دسترسی به اینترنت از **تانل SSH** (`ssh -D`)، **پروکسی HTTP/SOCKS5** (مثل v2ray، Xray، Clash، sing-box) یا **VPN** (مثل Windscribe، WireGuard، OpenVPN، Cloudflare WARP) استفاده می‌کنید، احتمالاً این مشکلات برایتان آشناست:

### ۱. دیدن دامنه و مقصد واقعی پشت پروکسی و تانل SSH
وقتی در ترمینال یا کل سیستم از پروکسی یا تانل SSH استفاده می‌کنید، ابزارهای معمولِ پایش شبکه که فقط سوکت‌ها را می‌بینند، معمولاً فقط `127.0.0.1:<port>` یا آدرس IP سرور واسط (VPS) را نشان می‌دهند. معلوم نیست برنامه واقعاً به کجا وصل شده است. Rat **هر دو** را نشان می‌دهد:
- **پروکسی**، مثلاً *via ssh proxy (127.0.0.1:1080 → سرور شما)*؛
- **مقصد نهایی**: دامنه، آدرس، شبکهٔ مالک و کشور و شهر آن روی نقشه.

روی نقشه هم مسیر دومرحله‌ای کشیده می‌شود: این Mac ← سرور پروکسی ← مقصد واقعی.

این کار بدون بازرسی محتوای ترافیک انجام می‌شود. Rat با Helper نصب‌شده فقط **درخواست آغازینی** را می‌خواند که برنامه روی loopback برای پروکسی محلی می‌فرستد (HTTP `CONNECT`، HTTP ساده، SOCKS5، SOCKS4/4a). بدون Helper، تنظیمات پروکسیِ خط فرمان و متغیرهای محیطی برنامه را می‌خواند: `http_proxy`، `https_proxy`، `ALL_PROXY` و آرگومان‌هایی مثل `curl -x`.

### ۲. تگ‌گذاری هوشمند ترافیک VPN و پروکسی در سه سطح
Rat تونل‌های فعال (`utun*`) را خودکار پیدا می‌کند و هر کدام را به نام برنامه‌ای که صاحب آن است می‌شناسد، مثلاً Windscribe، WireGuard، OpenVPN، WARP، Tailscale یا Mullvad. پروکسی سیستم و پروکسی‌های محلی مثل ssh، Tor و Clash را هم تشخیص می‌دهد.

سه سطح برچسب می‌گیرند: **ردیف برنامه**، **زیرپردازه‌ها** و **تک‌تک اتصال‌ها**. برچسب‌ها چنین‌اند: `VPN · Windscribe`، `Proxy · ssh`، و `VPN server · Windscribe` برای اتصال خودِ کلاینت VPN به سرورش.

این تشخیص به بازرسی سنگین بسته‌ها (DPI) نیاز ندارد. یک اتصال وقتی «از VPN» حساب می‌شود که سوکتش به آدرس تونل بسته شده باشد، یا اگر آدرس محلی ندارد، جدول مسیریابی آن را به تونل بفرستد.

برای فیلتر کردن کافی است در جست‌وجو `vpn` یا `proxy` تایپ کنید یا از دکمهٔ فیلتر مسیر استفاده کنید. نقشه و Summary هم همراه فیلتر عوض می‌شوند.

### ۳. جلوگیری از مصرف پنهان حجم VPN توسط برنامه‌های پس‌زمینه
بعضی برنامه‌ها در پس‌زمینه بی‌صدا حجم VPN یا اینترنت را مصرف می‌کنند، مثل Steam، مرورگرهای پرمصرف یا ابزارهای همگام‌سازی. با یک کلیک **Deny**، Rat آن برنامه و **همهٔ زیرپردازه‌هایش** (helperها، فرایندهای WebKit، `steam_osx` و …) را قطع می‌کند:
- **چطور:** دیمون `rat-enforcerd` پورت‌های محلی سوکت‌های برنامهٔ مسدودشده را با قوانین بی‌حالت `pf` می‌بندد.
- **با چه سرعتی:** تا وقتی برنامهٔ مسدودشده در حال اجراست، هر ۳ میلی‌ثانیه سوکت‌های آن را دوباره می‌خواند.
- **چه چیزی دست نمی‌خورد:** Rat **هرگز آدرس سرورها را مسدود نمی‌کند**. پس DNS (مثل `1.1.1.1` و `8.8.8.8`) و اینترنتِ برنامه‌های مجاز دست نمی‌خورد.
- **راه دور زدن بسته است:** برنامهٔ مسدودشده از راه یک پروکسی محلی یا `ssh -L` هم نمی‌تواند بیرون برود، چون اتصال‌های loopback آن به برنامه‌های دیگر هم قطع می‌شود.

برای سرویس‌های خودِ macOS دکمهٔ مسدودسازیِ یک‌جا وجود ندارد، چون DNS همهٔ برنامه‌ها را از کار می‌انداخت. برای یک سرویس مشخص می‌توانید در پنجرهٔ Rules قانون بسازید.

### ۴. رایگان، متن‌باز و بدون محدودیت زمانی
بدون دورهٔ آزمایشی، بدون اشتراک و بدون قفل‌کردن امکانات. Rat کاملاً بومیِ پردازنده‌های Apple Silicon (`arm64`) است و پایگاه‌دادهٔ موقعیت IP آن آفلاین است. هیچ آدرسی از Mac شما برای سرویس دیگری فرستاده نمی‌شود.

## امکانات دیگر

- **درخت پردازه‌ها:** هر برنامه به اتصال‌های مستقیمش و زیرپردازه‌هایش باز می‌شود و هر پردازه به اتصال‌های خودش. هر سطح شمارندهٔ ترافیک خودش را دارد. نمونه‌ها: `com.apple.WebKit.Networking` زیر Safari، `Google Chrome Helper` زیر Chrome، و سرویس‌هایی مثل `mDNSResponder` زیر macOS.
- **نمایشگر سه‌بخشی هماهنگ:**
  - **سمت چپ:** فهرست برنامه‌ها و نمودار ترافیک (۵ دقیقه، ۱ ساعت، ۱ روز، ۱ هفته).
  - **وسط:** نقشهٔ جهان که فقط همان چیزی را می‌کشد که فهرست نشان می‌دهد.
  - **سمت راست:** Inspector برای برنامه، پردازه یا اتصالِ انتخاب‌شده، یا Summary (پردازه‌ها، دامنه‌ها، کشورها و شبکه‌های پرترافیک) که با فیلتر عوض می‌شود.
- **هشدار اتصال:** حالت پیش‌فرض **Silent Allow** است، پس نصبِ تازه هیچ مزاحمتی ندارد. در **Alert Mode** برای اتصال‌های ناشناخته یک پنجرهٔ شناور باز می‌شود. دامنهٔ قانون (برنامه، دامنه، میزبان، پورت) و مدت آن (یک‌بار، تا بسته‌شدن برنامه، همیشه) را خودتان انتخاب می‌کنید.
- **پنجرهٔ Rules** (⇧⌘R):
  - **قانون‌ها:** بر اساس برنامه، Team ID، Signing ID، دامنه، میزبان، IP، بازهٔ پورت و پروتکل. دقیق‌ترین قانون برنده است و در تساوی، Deny بر Allow مقدم است.
  - **سازمان‌دهی:** گروه قانون‌ها، پروفایل‌ها (Home، Work، Public Wi-Fi) با تعویض خودکار بر اساس شبکه، و صف بازبینیِ قانون‌های تأییدنشده.
  - **اشتراک‌گذاری:** ورود و خروج JSON.
- **اتصال‌های خوانا:** سرویس معمول هر پورت (`TCP 443 · HTTPS`، `UDP 443 · QUIC`)، شبکهٔ مالک (`AS13335 Cloudflare, Inc.`)، و DNS معکوس که هیچ‌وقت نمایشگر را معطل نمی‌کند.
- **GeoIP آفلاین:** پایگاه‌داده‌های DB-IP Lite (شهر و ASN) داخل برنامه است. از Settings > GeoIP می‌توانید فایل DB-IP یا MaxMind خودتان را هم بدهید.
- **نوار منو:** سرعت لحظه‌ای، انتخاب پروفایل و تغییر حالت.
- **به‌روزرسانی:** منوی Rat ← *Check for Updates…* نسخه‌های GitHub را بررسی می‌کند.

| پنجرهٔ Rules (⇧⌘R) | تنظیمات (⌘,) |
|---|---|
| ![پنجرهٔ Rules](docs/screenshots/rules-window.png) | ![پنجرهٔ تنظیمات](docs/screenshots/settings-window.png) |

تنظیمات ده زبانه دارد: General، Control Center، Alert، Monitor، APS، Security، GeoIP، Notifications، Update و Advanced.

## نصب

۱. فایل `Rat-v<version>-arm64.dmg` را دانلود کنید:
   - **نسخهٔ پایدار:** از [آخرین انتشار](https://github.com/ImanMontajabi/Rat/releases/latest).
   - **نسخهٔ شبانه (جدیدترین تغییرات):** از [پیش‌انتشارها](https://github.com/ImanMontajabi/Rat/releases). این نسخه با هر ادغام در `main` ساخته می‌شود و پنج نسخهٔ آخر نگه داشته می‌شود.

کنار هر DMG یک فایل `.sha256` هست که با آن می‌توانید سالم بودن فایل را بررسی کنید:

<div dir="ltr" align="left">

```sh
shasum -a 256 -c Rat-*.dmg.sha256
```

</div>

۲. DMG را باز کنید و Rat را به Applications بکشید. Rat به Mac با پردازندهٔ Apple Silicon و macOS 14 یا جدیدتر نیاز دارد.

۳. چون Rat امضای ad-hoc دارد و notarize نشده (حساب توسعه‌دهندهٔ پولی در کار نیست)، بار اول آن را با راست‌کلیک ← **Open** باز کنید یا این فرمان را اجرا کنید:

<div dir="ltr" align="left">

```sh
xattr -dr com.apple.quarantine /Applications/Rat.app
```

</div>

## راه‌اندازی Helper فایروال (اختیاری)

برای اینکه **Deny** واقعاً جلوی برنامه را بگیرد، Settings (⌘,) ← زبانهٔ **Security** ← **Install Helper…** را بزنید و رمز مدیر سیستم را وارد کنید. دو LaunchDaemon با دسترسی root نصب می‌شود:
- `rat-enforcerd`: Deny را اجرا می‌کند و درخواست‌های پروکسی روی loopback را می‌خواند.
- یک Helper دیگر که فهرست اتصال‌های همهٔ پردازه‌ها را می‌دهد، تا Rat پردازه‌های سیستمی و کاربران دیگر را هم ببیند.

بعد از به‌روزرسانی، همین زبانه گزینهٔ **Update Helper…** را نشان می‌دهد و **Remove Helper…** هر دو را حذف می‌کند. بدون Helper، Rat همچنان پردازه‌های خودتان را نمایش می‌دهد، ولی چیزی را مسدود نمی‌کند.

برای دیدن آنچه همین حالا مسدود است:

<div dir="ltr" align="left">

```sh
scripts/rat-status.sh          # فهرست برنامه‌های مسدود و وضعیت Helper
sudo scripts/rat-status.sh     # به‌همراه قوانین زندهٔ pf
```

</div>

## ساخت از سورس

پیش‌نیازها: Xcode (آخرین نسخهٔ پایدار) و [XcodeGen](https://github.com/yonaskolb/XcodeGen). `create-dmg` اختیاری است و بدون آن `hdiutil` به کار می‌رود.

<div dir="ltr" align="left">

```sh
brew install xcodegen
./scripts/fetch-geoip.sh                    # once: the ~125 MB DB-IP databases into App/Vendor
xcodegen generate                           # Rat.xcodeproj is generated from project.yml
./scripts/build-release.sh /tmp/out         # the same Release build as CI → /tmp/out/Rat.app
./scripts/make-dmg.sh /tmp/out/Rat.app /tmp/out/Rat.dmg
```

</div>

## تست‌ها

<div dir="ltr" align="left">

```sh
xcodebuild -scheme Rat test                                            # app, rules and snapshot tests
(cd RatFilter && RAT_GEOIP_DB=../App/Vendor/dbip-city-lite.mmdb swift test)   # the packages
scripts/test-ui.sh                  # XCUITest on demo data + snapshot goldens (needs a GUI session)
scripts/readme-screenshots.sh       # retakes this page's screenshots from demo data
sudo scripts/verify-blocking.sh     # live end-to-end blocking test
```

</div>

تست‌های رابط کاربری و تصویرها با یک نسخهٔ نمایشی جداگانه (شناسهٔ `com.imanmontajabi.Rat.uitest`) و داده‌های ثابت اجرا می‌شوند. به Rat در حال اجرای شما، قانون‌ها و تنظیماتش دست نمی‌زنند. اگر چیدمان صفحه‌کلید فارسی فعال باشد، اسکریپت آن را برای مدت اجرا به U.S./ABC تغییر می‌دهد و بعد برمی‌گرداند. در این مدت به صفحه‌کلید و ماوس دست نزنید.

## معماری

| ماژول | محتوا |
|---|---|
| `App/` | برنامهٔ SwiftUI. `Ledger` هر ۱٫۵ ثانیه نمونه می‌گیرد، پردازه‌ها را در برنامه‌ها گروه می‌کند، هر اتصال را با قانون‌ها می‌سنجد، هشدار می‌دهد و فهرست برنامه‌ها و پورت‌های مسدود را به Helper می‌دهد. نمایشگر، پنجره‌های Rules و Settings، پنجرهٔ هشدار و نوار منو هم این‌جاست. |
| `RatFilter/Sources/RatFilterCore` | موتور قانون‌ها: قانون، پروفایل، گروه، تریگرهای شبکه، ورود و خروج. Swift خالص. |
| `RatFilter/Sources/RatMonitor` | نمونه‌گیر اتصال با `libproc`، نمونه‌گیر ترافیک با `nettop`، گروه‌بندی پردازه‌ها، نام پورت‌ها، و تشخیص VPN، مسیر و پروکسی. |
| `RatFilter/Sources/RatGeo` | خوانندهٔ MaxMind DB (`.mmdb`) برای شهر و ASN، مقاوم در برابر فایل‌های نامعتبر. |
| `RatFilter/Sources/RatEnforce` + `Enforcerd/` | دیمون root به نام `rat-enforcerd`: anchor ‏`pf` برای پورت‌های محلی برنامه‌های مسدود، و خوانندهٔ درخواست‌های پروکسی روی `lo0` (‏BPF). هرگز آدرس سرورها را مسدود نمی‌کند. |
| `RatFilter/Sources/RatFilterExtension` | یک `NEFilterDataProvider` غیرفعال که به مجوز Network Extension نیاز دارد. |

طراحی کامل، از جمله اینکه چرا Rat به جای آدرس سرورها پورت‌های محلی را می‌بندد، در [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) آمده است (به انگلیسی).

## روند توسعه و انتشار

- **Pull Request:** هر تغییر با یک Pull Request به `main` وارد می‌شود، از شاخه‌ای با پیشوند `feat/`، `fix/`، `ci/`، `test/` یا `docs/`. هر شاخه یک قطعهٔ تغییرات در [`changelog.d/`](changelog.d/README.md) اضافه می‌کند. CI این قطعه و فایل `Version` را بررسی می‌کند، تست‌ها را اجرا می‌کند و DMG می‌سازد.
- **نسخهٔ شبانه:** هر ادغام در `main` یک پیش‌انتشار شبانه (`v<Version>-nightly.<date>.<sha>`) منتشر می‌کند.
- **نسخهٔ پایدار:** یک Pull Request از `main` به `release` نسخهٔ پایدار `v<Version>` را منتشر می‌کند. بعد یک Pull Request خودکار به `main` باز می‌شود که قطعه‌ها را در [CHANGELOG.md](CHANGELOG.md) جمع می‌کند و `Version` را بالا می‌برد.

## مجوز و منابع

مجوز MIT؛ متن کامل در [LICENSE](LICENSE). داده‌های موقعیت IP و شبکه از [DB-IP.com](https://db-ip.com) است: پایگاه‌داده‌های IP to City Lite و IP to ASN Lite با مجوز [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

</div>
