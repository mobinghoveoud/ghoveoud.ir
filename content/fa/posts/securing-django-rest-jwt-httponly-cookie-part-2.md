---
slug: "securing-django-rest-jwt-httponly-cookie-part-2"
title: "افزایش امنیت API با استفاده از JWT و کوکی‌ HttpOnly در Django Rest - بخش دوم"
tags: ["django", "drf", "jwt", "auth", "httponly-cookie", "csrf"]
categories: ["django"]
date: "2025-01-10"
thumbnail: "/images/posts/securing-django-rest-jwt-httponly-cookie-part-2/drf-jwt-httponly-part-2.jpeg"
---

## مروری بر بخش اول
در [بخش اول]({{< relref "posts/securing-django-rest-jwt-httponly-cookie-part-1.md" >}}) با مفاهیم پایه‌ای JWT آشنا شدیم و  APIهای مربوط به Login و Refretsh Token رو پیاده‌سازی کردیم. همچنین یاد گرفتیم که چجوری میشه توکن‌های JWT رو برای امنیت بیشتر در کوکی‌های HttpOnly ذخیره کرد.

در این بخش، قصد داریم به پیاده‌سازی `Logout API` بپردازیم و نگاهی به حملات `CSRF` و روش‌های مقابله با اون داشته باشیم.

{{< figure src="/images/posts/securing-django-rest-jwt-httponly-cookie-part-2/drf-jwt-httponly-part-2.jpeg" alt="Django JWT CSRF" >}}

## پیاده‌سازی Logout API

در این قسمت قصد داریم یک API جدید برای logout کاربران پیاده‌سازی کنیم اما قبل از اون باید برخی پیش نیازها رو به پروژه اضافه کنیم.

### 1. حذف توکن‌های JWT از کوکی

مشابه تابعی که برای ذخیره توکن‌ها در کوکی استفاده کردیم، به یک تابع برای حذف کوکی‌ها هم نیاز داریم.

```python
# accounts/jwt.py

from django.conf import settings
from rest_framework.response import Response


def delete_token_cookies(response: Response) -> None:
    # Delete Access token
    response.delete_cookie(
        settings.SIMPLE_JWT["AUTH_COOKIE_ACCESS"],
        domain=settings.SIMPLE_JWT["AUTH_COOKIE_DOMAIN"],
        samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
    )
    # Delete Refresh token
    response.delete_cookie(
        settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
        path=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH_PATH"],
        domain=settings.SIMPLE_JWT["AUTH_COOKIE_DOMAIN"],
        samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
    )

```

{{< notice tip >}}
شاید براتون جالب باشه که بدونید متود `delete_cookie` در واقع کوکی رو حذف نمی‌کنه. بلکه یک کوکی جدید با همون مشخصات، اما با تاریخ انقضای قدیمی (timestamp=0) تنظیم میکنه تا مرورگر اون رو نادیده بگیره.
{{< /notice >}}


### 2. مدیریت توکن‌های JWT

یکی از نکات مهم در استفاده از توکن‌های JWT مدیریت صحیح Refresh Token است. زمانی که کاربر از سیستم خارج میشه، ما توکن‌ها رو از کوکی‌های او حذف می‌کنیم. اما ممکنه این کاربر عزیز قبل از خروج، Refresh Token رو ذخیره کرده باشه و با استفاده از آن، دوباره Access Token جدیدی بگیره.

برای جلوگیری از این مسئله، کتابخانه SimpleJWT راهکار `Blacklist` رو ارائه میده. این روش به ما اجازه میده تا هرگاه نیاز بود، Refresh Token رو در لیست سیاه قرار بدیم (ذخیره در دیتابیس) و اگر کاربر تلاش کرد با استفاده از Refresh Token قدیمی، Access Token جدیدی دریافت کنه، با بررسی دیتابیس از این کار جلوگیری کنیم.

برای اضافه کردن این روش، تنها کافیه فایل `settings.py` به این شکل تغییر بدیم:

```python
# backend/settings.py

INSTALLED_APPS = [
    ...
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    ...
]
```

{{< notice warning >}}
پس از اضافه کردن این تغییرات، حتما دستور `python manage.py migrate` رو اجرا کنید تا تغییرات در دیتابیس هم اعمال بشه.
{{< /notice >}}

{{< notice tip >}}
برای مدیریت Refresh Token روش دیگه‌ای به نام `Whitelist` هم وجود داره که پیشنهاد می‌کنم در این مورد مطالعه کنید و بهترین روش رو نسبت به شرایط پروژه انتخاب کنید.
{{< /notice >}}

### 3. اضافه کردن Logout API

در نهایت باید یک API جدید برای عملیات logout ایجاد کنیم. در صورتی که کاربر لاگین کرده بود، توکن‌های JWT رو از کوکی حذف می‌کنیم و همچنین Refresh Token رو حتما به blacklist اضافه می‌کنیم.

برای این کار، ابتدا Refresh Token رو از کوکی می‌خونیم و به `TokenBlacklistSerializer` (مربوط به کتابخانه SimpleJWT) می‌دیم تا توکن رو اعتبارسنجی و در نهایت به لیست سیاه اضافه کنه.

```python
# accounts/views.py

from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenBlacklistSerializer
from rest_framework_simplejwt.tokens import Token

from accounts.jwt import delete_token_cookies


class LogoutAPIView(APIView):
    serializer_class = TokenBlacklistSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data={"refresh": self.get_refresh_token_from_cookie()})

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0]) from e

        response = Response({}, status=status.HTTP_200_OK)

        # Delete jwt cookies
        delete_token_cookies(response)

        return response

    def get_refresh_token_from_cookie(self) -> Token:
        refresh = self.request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        if not refresh:
            raise PermissionDenied

        return refresh
```

```python
# accounts/urls.py

from django.urls import path

from accounts import views

app_name = "accounts"
urlpatterns = [
    ...
    path("auth/logout/", views.LogoutAPIView.as_view(), name="logout"),
    ...
]
```

## جلوگیری از حمله CSRF

همونطور که قبلا اشاره کردیم، استفاده از کوکی‌ها می‌تونه احتمال مواجهه با حملات `CSRF` رو افزایش بده. بنابراین، لازمه برای جلوگیری از این نوع حمله، اقدامات مناسبی رو انجام بدیم. در ابتدا به بررسی مفهوم این حمله و روش‌های جلوگیری از اون می‌پردازیم.

### 1. CSRF و راه‌های جلوگیری از آن

حمله **CSRF (Cross-Site Request Forgery)** یکی از رایج‌ترین حملات در وب است که در آن، مهاجم تلاش می‌کنه کاربر رو به انجام عملیاتی ناخواسته در یک سایت معتبر وادار کنه. این حمله با سوءاستفاده از اعتبار کاربر انجام میشه و معمولا کاربر اصلا متوجه این موضوع نمیشه.

برای جلوگیری از CSRF، از روش‌های مختلفی میشه استفاده کرد:

- **توکن CSRF:** این توکن یک مقدار یکتا و غیرقابل پیش‌بینی است که توسط سرور تولید و به کلاینت داده میشه. هنگام ارسال درخواست‌های حساس مانند فرم‌ها، کلاینت این توکن رو به همراه دیگر اطلاعات ارسال می‌کنه. این روش باعث میشه تا ایجاد یک درخواست معتبر از طرف قربانی برای مهاجم بسیار سخت بشه.
- **کوکی SameSite:** این ویژگی در کوکی‌ها، مکانیسم امنیتی مرورگر است که مشخص می‌کنه تا کوکی‌ها تنها در درخواست‌های همان سایت ارسال بشن. این روش می‌تونه تا حدی از حملات CSRF جلوگیری کنه، چون درخواست‌های مهاجم بدون کوکی‌های احراز هویت کاربر ارسال خواهند شد. با این حال، این روش به تنهایی کافی نیست، چرا که برخی از مرورگرها از این قابلیت به درستی پشتیبانی نمی‌کنن.
- **بررسی Referer:** یکی دیگر از روش‌های مقابله، بررسی هدر `Referer` در درخواست‌های HTTP است تا منبع درخواست تایید بشه. با این حال این روش نسبت به توکن CSRF ضعیف‌تر است، چون مهاجم به راحتی می‌تونه این هدر رو تغییر بده و امنیت کامل رو تضمین نمی‌کنه.

### 2. پیاده‌سازی در جنگو

همونطور که می‌دونین، جنگو به صورت پیشفرض یک middleware برای پیاده‌سازی توکن CSRF داره. در این پیاده‌سازی، علاوه بر بررسی `توکن CSRF` در درخواست‌ها، هدر `Referer` هم بررسی میشه. توجه داشته باشید که این بررسی برای درخواست‌ها با متودهای امن (`GET`، `HEAD`، `OPTION` و `TRACE`) انجام نمیشه.

با استفاده از این مکانیسم، جنگو به صورت خودکار برای هر کاربر یک توکن CSRF تولید و در کوکی کاربر ذخیره می‌کنه. هنگام ارسال درخواست، این توکن باید در اطلاعات فرم ارسالی وجود داشته باشه. سپس middleware جنگو توکن ارسال شده و توکن ذخیره شده در کوکی رو مقایسه می‌کنه و در صورت عدم تطابق، درخواست رد میشه.

{{< notice tip >}}
توکنی که در فرم کاربر قرار می‌گیره، `Masked Token` هست که با استفاده از توکن اصلی CSRF و با الگوریتم‌های خاصی ایجاد میشه و دو برابر توکن اصلی هست. این روش برای جلوگیری از [BRECH Attack](https://www.breachattack.com) استفاده میشه که اگر دوست داشتین می‌تونین در این مورد بیشتر بخونین.
{{< /notice >}}

حالا برای مدیریت CSRF، باید تنظیمات زیر رو به پروژه اضافه کنیم:

```python
# backend/settings.py

# CSRF
CSRF_TRUSTED_ORIGINS = [
    "https://example.com",
    "https://admin.example.com",
    "http://localhost", # just for local
]
CSRF_COOKIE_DOMAIN = None  # ".example.com" or None for standard domain cookie
CSRF_COOKIE_SECURE = False  # Whether the auth cookies should be secure (https:// only).
```

### 3. بررسی CSRF در API

در DRF به طور پیش‌فرض بررسی CSRF انجام نمیشه و مدیریت توکن CSRF در APIها کمی متفاوت است. برای انجام این کار، باید بررسی CSRF رو در کلاس Authentication که در بخش قبلی نوشته بودیم، اضافه کنیم. توجه داشته باشید در مواردی که API نیاز به احراز هویت نداره یا کاربر لاگین نکرده است، این بررسی ضرورتی نداره.

برای تکمیل کلاس `JWTCookieAuthentication` به این صورت عمل می‌کنیم:

```python
# backend/settings.py

# Simple JWT
SIMPLE_JWT = {
    ...
    "AUTH_COOKIE_USE_CSRF": True,
}
```

```python
# accounts/authentication.py

from django.conf import settings
from rest_framework.authentication import CSRFCheck
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.authentication import JWTAuthentication


class CSRFPermissionDeniedError(PermissionDenied):
    default_code = "csrf_permission_denied"


class JWTCookieAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)

        if header is None:
            raw_token = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE_ACCESS"]) or None
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None

        if settings.SIMPLE_JWT["AUTH_COOKIE_USE_CSRF"]:
            self.enforce_csrf(request)

        validated_token = self.get_validated_token(raw_token)

        return self.get_user(validated_token), validated_token

    def enforce_csrf(self, request):
        def dummy_get_response(_):
            return None

        check = CSRFCheck(dummy_get_response)
        # populates request.META['CSRF_COOKIE'], which is used in process_view()
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise CSRFPermissionDeniedError(f"CSRF Failed: {reason}")
```

اگر مقدار `AUTH_COOKIE_USE_CSRF` در تنظیمات SimpleJWT رو برابر با `False` قرار بدین، بررسی CSRF انجام نخواهد شد اما این کار **اصلا پیشنهاد نمیشه!**

### 4. توکن CSRF چه زمانی منقضی می‌شود؟

توکن CSRF عملا منقضی نمیشه و تا زمانی که کوکی مربوطه در مرورگر کاربر وجود داشته باشه، قابل استفاده است. (به `CSRF_COOKIE_AGE` در تنظیمات توجه کنید)

همچنین در مستندات جنگو پیشنهاد شده تا به خاطر مسائل امنیتی، توکن CSRF پس از هر عملیات لاگین کاربر، تغییر کنه. بنابراین می‌تونیم Login API که در بخش قبلی نوشتیم رو به شکل زیر تکمیل کنیم:

```python
from django.middleware.csrf import rotate_token


class LoginAPIView(APIView):
    def post(self, request):
        ...

        # Rotate CSRF token
        # Django: For security reasons, CSRF tokens are rotated each time a user logs in.
        rotate_token(request)

        return response
```

### 5. پیاده‌سازی CSRF Token API

همونطور که توضیح دادیم، در DRF بررسی CSRF به صورت پیش‌فرض انجام نمیشه و طبیعتاً کوکی توکن CSRF هم به طور خودکار برای کاربر تنظیم نخواهد شد. (مگر در هنگام ورود) در برخی مواقع ممکنه نیاز داشته باشیم تا توکن CSRF جدیدی برای کاربر تنظیم بشه. برای این کار یک API جدید به شکل زیر تعریف می‌کنیم:

```python
# accounts/views.py

from django.middleware.csrf import get_token
from rest_framework.response import Response
from rest_framework.views import APIView


class CSRFAPIView(APIView):
    permission_classes = ()
    authentication_classes = ()

    def get(self, request):
        return Response({"token": get_token(request)})
```

```python
# accounts/urls.py

from django.urls import path

from accounts import views

app_name = "accounts"
urlpatterns = [
    ...
    # CSRF
    path("csrf_token/", views.CSRFAPIView.as_view(), name="csrf-token"),
]
```

دقت کنید که در این حالت، `توکن CSRF` در کوکی ذخیره میشه و `Masked Token` هم در پاسخ API برمی‌گرده.

### 6. نحوه ارسال درخواست به API

در درخواست‌هایی که هیچ فرمی وجود نداره، جنگو نمی‌تونه به طور خودکار توکن CSRF رو در فرم قرار بده تا به صورت خودکار با اطلاعات مورد نظر به سمت سرور ارسال بشه. برای این منظور، جنگو پیشنهاد استفاده از یک هدر مشخص در درخواست را ارائه داده. برای این کار کافیه که فرانت‌اند توکن CSRF رو از کوکی بخونه و در هدر `X-CSRFToken` قرار بده. با این کار، جنگو توکن رو از هدر می‌خونه و با مقداری که در کوکی وجود داره، بررسی می‌کنه.

## بلاخره تموم شد!

در این دو بخش از مقاله سعی کردیم مهم‌ترین نکات در پیاده‌سازی یک سیستم احراز هویت با استفاده از JWT و کوکی‌های HTTPOnly رو یاد بگیریم. اما فراموش نکنید که همیشه جزئیات بیشتری وجود داره که نیاز به مطالعه و تجربه بیشتر داره. _پس هیچوقت از یادگیری و ارتقاء مهارت‌هاتون دست نکشید!_

در انتهای مقاله می‌خوام یک سری سوال در ذهن شما ایجاد کنم که شاید بهشون فکر کنید. اگر جوابش رو پیدا کردید، خوشحال میشم در کامنت‌های لینکدین با بقیه به اشتراک بگذارید.

{{< notice question >}}
در جایی اشاره کردیم که کتابخانه SimpleJWT از استراتژی Blacklist برای مدیریت توکن‌ها استفاده می‌کنه اما اگر جزئی‌تر بررسی کنیم، متوجه می‌شیم که این حرف کاملا هم درست نیست. به نظرتون این کتابخانه دقیقا چطور این قسمت رو پیاده‌سازی کرده؟
{{< /notice >}}

{{< notice question >}}
در قسمت آخر توضیح دادیم که فرانت‌اند می‌تونه توکن CSRF رو از کوکی برداره و در قالب یک هدر مشخص برای سرور ارسال کنه. به نظرتون این کار چه مزیتی داره؟ چون به طور قطع در بررسی، مقدار هدر و کوکی برابر هستند! 🤔
{{< /notice >}}

{{< notice question >}}
به نظرتون تفاوت توکن CSRF با Masked Token چیه و چجوری از حمله BREACH جلوگیری می‌کنه؟
{{< /notice >}}

آدرس پست در لینکدین:

{{< direction ltr >}}
[linkedin.com/in/mobin-ghoveoud](https://linkedin.com/in/mobin-ghoveoud)
{{< /direction >}}

آدرس گیتهاب پروژه:

{{< direction ltr >}}
[https://github.com/mobinghoveoud/drf-jwt-httponly-cookie](https://github.com/mobinghoveoud/drf-jwt-httponly-cookie)
{{< /direction >}}

ممنون از توجه شما!
