---
slug: "securing-django-rest-jwt-httponly-cookie-part-1"
title: "افزایش امنیت API با استفاده از JWT و کوکی‌ HttpOnly در Django Rest - بخش اول"
tags: ["django", "drf", "jwt", "auth", "httponly-cookie"]
categories: ["django"]
date: "2024-12-27"
thumbnail: "/images/securing-django-rest-jwt-httponly-cookie-part-1/drf-jwt-httponly-part-1.jpg"
---

## مقدمه

احراز هویت همیشه یکی از مهم‌ترین بخش‌های توسعه API‌ بوده که از دسترسی غیرمجاز به منابع حساس جلوگیری می‌کنه. روش‌های مختلفی برای این کار وجود داره، ولی استفاده از توکن‌های`JSON Web Token (JWT)`، به خاطر سبک بودن، انعطاف‌پذیری و مخصوصاً `stateless` بودن بسیار پرطرفداره. یک نکته مهم در استفاده از JWT، نحوه ذخیره‌سازی توکن هاست. اگر توکن‌ها رو در یک جای ناامن مثل `localStorage` ذخیره کنیم، احتمال سرقت یا سوءاستفاده از اطلاعات بالا میره.

در این مقاله قصد داریم در مورد نحوه پیاده‌سازی سیستم احراز هویت با `JWT` و کوکی `HttpOnly` صحبت کنیم تا بتونیم امنیت API‌هامون رو افزایش بدیم.


{{< figure src="/images/securing-django-rest-jwt-httponly-cookie-part-1/drf-jwt-httponly-part-1.jpg" alt="Django JWT Token in HttpOnly Cookie" >}}

### JWT دقیقا چیه؟

JWT یا همون `JSON Web Token` یک استاندارد برای انتقال امن اطلاعات بین سیستم‌های مختلف است. این اطلاعات به صورت توکن رمزنگاری‌شده ردوبدل میشن که می‌تونن شامل اطلاعات مختلفی مثل شناسه کاربر، زمان انقضا و ... باشن. توکن‌های JWT از سه بخش اصلی تشکیل شدن:

1. **Header**: شامل اطلاعاتی درباره نوع توکن و الگوریتم رمزنگاریه.
2. **Payload**: داده‌های اصلی مثل شناسه کاربر یا نقش رو نگه می‌داره. 
3. **Signature**: با استفاده از یک کلید خصوصی تولید میشه و مطمئن میشه که محتوا دستکاری نشده.

{{< figure src="/images/securing-django-rest-jwt-httponly-cookie-part-1/jwt.png" alt="Django JWT Token in HttpOnly Cookie" >}}

اما چرا باید از JWT استفاده کنیم؟ مهم‌ترین مزیتش اینه که stateless هست، یعنی نیازی نیست سرور برای احراز هویت، اطلاعات توکن رو در دیتابیس ذخیره کنه. این باعث میشه سیستم مقیاس‌پذیرتر بشه و از کوئری‌های اضافی به دیتابیس جلوگیری بشه.
سیستم JWT از دو نوع توکن استفاده می‌کنه:

- **Access Token**: برای احراز هویت در API‌ها استفاده میشه و عمر کوتاهی داره تا در صورت لو رفتن، خطر کمتری داشته باشه.
- **Refresh Token**: طول عمر بیشتری داره و به کاربر اجازه میده بدون لاگین مجدد، Access Token جدید بگیره.

برای اطلاعات بیشتر در این مورد میتونین به سایت [jwt.io](https://jwt.io) سر بزنین.


### توکن‌های JWT رو کجا ذخیره کنیم؟

زمانی که از JWT برای احراز هویت استفاده می‌کنیم، باید توکن‌های کاربر رو ذخیره کنیم تا در هر درخواست به سرور ارسال بشه. حالا سوال اینه که:

{{< notice question >}}
**بهترین مکان برای ذخیره توکن‌های JWT کجاست؟**
{{< /notice >}}

اکثراً به دلیل راحتی، توکن‌ها رو در `localStorage` ذخیره می‌کنن. اما این روش مشکلاتی داره. یکی از بزرگ‌ترین خطرات این کار حملات `XSS` هست که به طور کلی در این حمله، اگر مهاجم بتونه یه کد مخرب رو در مرورگر قربانی اجرا کنه، به راحتی به `localStorage` دسترسی پیدا می‌کنه و توکن‌های امنیتی رو به سرقت می‌بره!

در نتیجه، بهترین کار استفاده از `HttpOnly Cookie` هست. این نوع کوکی توسط سرور تنظیم میشه و مرورگر به طور خودکار توکن‎‌ها رو در درخواست‌های بعدی ارسال می‌کنه. مهم‌تر از همه، چون این کوکی‌ها خارج از دسترس جاوااسکریپت هستن، خطر سرقت توکن از طریق `XSS` وجود نداره.

البته ذخیره توکن‌های `JWT` در کوکی به تنهایی کافی نیست و ممکنه سیستم رو در برابر حملات `CSRF` آسیب‌پذیر کنه. در بخش‎ بعدی مقاله درباره جلوگیری از حملات `CSRF` هم صحبت خواهیم کرد.

{{< notice note >}}
در این مقدمه سعی کردیم مفاهیم رو به صورت کلی توضیح بدیم تا بتونیم در ادامه وارد بخش اصلی یعنی پیاده‌سازی پروژه بشیم. با این حال پیشنهاد می‌کنیم حتماً درباره این مفاهیم بیشتر تحقیق کنید و مقاله‌های بیشتری بخونید.
{{< /notice >}}

## پیاده‌سازی پروژه

در این بخش قصد داریم از صفر یک پروژه جنگو بسازیم و با استفاده از کتابخانه‌های `DRF` و `SimpleJWT` سیستم احراز هویت رو پیاده‌سازی کنیم.

### 1. ایجاد پروژه جدید

در ابتدا یک پروژه جدید ایجاد کرده و کتابخانه‌های مورد نیاز رو نصب می‌کنیم. برای این کار می‎تونین از دستورات زیر استفاده کنین:

```shell
mkdir drf-jwt-httponly-cookie
cd drf-jwt-httponly-cookie
uv init
uv add django djangorestframework djangorestframework-simplejwt
source .venv/bin/activate  # Activate virtual environment
django-admin startproject backend
```

{{< notice tip >}}
اینجا از `uv` برای مدیریت پکیج‌ها استفاده می‌کنیم. `uv` یک جایگزین برای ابزارهایی مثل `pip` و `poetry` هست که با زبان `Rust` نوشته شده و قابلیت‌ها و سرعت خیلی بیشتری نسبت به ابزارهای مشابه داره. پیشنهاد می‌کنم حتما امتحانش کنید. ([داکیومنت uv](https://docs.astral.sh/uv/))
{{< /notice >}}

تا اینجا ساختار پروژه ما به این شکل هست:

```copy
├── backend
│   ├── backend
│   │   ├── asgi.py
│   │   ├── __init__.py
│   │   ├── settings.py
│   │   ├── urls.py
│   │   └── wsgi.py
│   └── manage.py
├── pyproject.toml
└── uv.lock
```

برای استفاده از کتابخانه‌ها، فایل `settings.py` را به شکل زیر تغییر می‌دیم:

```python
# backend/settings.py
from datetime import timedelta

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party apps
    "rest_framework",
    "rest_framework_simplejwt",
]

# Simple JWT
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    # Auth
    "AUTH_HEADER_TYPES": ("Bearer",),
}
```

### 2. پیاده‌سازی Login API

برای پیاده‌سازی سیستم لاگین، ابتدا یک app جدید ایجاد می‌کنیم:

```shell
python manage.py startapp accounts
```

{{< notice note >}}
فراموش نکنید که app جدید رو به `INSTALLED_APP` در `settings.py` اضافه کنید.
{{< /notice >}}

قبل از نوشتن API ما نیاز داریم تا تنظیمات جدیدی رو برای کوکی‌های مربوط به `Access Token` و `Refresh Token` اضافه کنیم.

```python
# backend/settings.py
from datetime import timedelta

# Simple JWT
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    # Auth
    "AUTH_HEADER_TYPES": ("Bearer",),
    # Auth Cookie
    "AUTH_COOKIE_ACCESS": "access_token",
    "AUTH_COOKIE_REFRESH": "refresh_token",
    "AUTH_COOKIE_DOMAIN": None,  # ".example.com" or None for standard domain cookie
    "AUTH_COOKIE_SECURE": False,  # Whether the auth cookies should be secure (https:// only).
    "AUTH_COOKIE_HTTP_ONLY": True,
    "AUTH_COOKIE_SAMESITE": "Lax",  # The flag restricting cookie leaks on cross-site requests. 'Lax', 'Strict' or None to disable the flag.
    "AUTH_COOKIE_REFRESH_PATH": "/accounts/auth/",
}
```

برای امنیت بیشتر کوکی‌ها، پارامترهای زیر رو باید تنظیم کنیم:

+ **Secure**: اگر مقدار این پارامتر True باشه، کوکی فقط از طریق `HTTPS` ارسال میشه. این گزینه رو در محیط `production` حتما فعال کنید.
+ **Domain**: این پارامتر مشخص می‌کنه کوکی روی چه دامنه‌ای معتبر باشه. اگر API و کلاینت روی دامنه‌های مختلفی هستن، می‌تونید به شکل `Domain=.example.com` تنظیم کنید.
+ **Path**: به صورت پیش‌فرض مقدار این پارامتر `/` هست، که باعث میشه کوکی در تمام درخواست‌ها ارسال بشه. اما چون Refresh Token فقط برای مسیرهای خاصی لازمه، این مقدار رو برای کوکی مربوط به Refresh Token طوری تنظیم می‌کنیم که فقط در درخواست‌های مورد نیاز ارسال بشه.


برای اضافه کردن توکن‌های احراز هویت در کوکی‌، تابع زیر رو به پروژه اضافه می‌کنیم تا بعداً برای لاگین کاربر ازش استفاده کنیم:

```python
# accounts/jwt.py
from django.conf import settings
from rest_framework.response import Response


def set_token_cookies(
    response: Response,
    access_token: str | None = None,
    refresh_token: str | None = None,
) -> None:
    if access_token:
        response.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE_ACCESS"],
            value=access_token,
            max_age=settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            domain=settings.SIMPLE_JWT["AUTH_COOKIE_DOMAIN"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

    if refresh_token:
        response.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
            value=refresh_token,
            max_age=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
            path=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH_PATH"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            domain=settings.SIMPLE_JWT["AUTH_COOKIE_DOMAIN"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )
```

حالا باید API لاگین کاربر رو ایجاد کنیم که نام کاربری و رمز عبور رو دریافت کنه و اگر اطلاعات درست بود، توکن‌های احراز هویت رو در کوکی ذخیره و ارسال کنه.

```python
# accounts/serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.serializers import PasswordField


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = PasswordField()
```

```python
# accounts/views.py
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.jwt import set_token_cookies
from accounts.serializers import LoginSerializer


class LoginAPIView(APIView):
    serializer_class = LoginSerializer
    authentication_classes = ()
    permission_classes = ()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]
        user = authenticate(request, username=username, password=password)

        if not user:
            raise AuthenticationFailed

        response = Response({}, status=status.HTTP_200_OK)

        # Set auth cookies
        refresh = RefreshToken.for_user(user)
        set_token_cookies(response, str(refresh.access_token), str(refresh))

        return response
```

```python
# accounts/urls.py
from django.urls import path

from accounts import views

app_name = "accounts"
urlpatterns = [
    path("auth/login/", views.LoginAPIView.as_view(), name="login"),
]
```

برای اضافه کردن URL جدید به پروژه، حتما فایل `urls.py` اصلی رو هم به این شکل تغییر بدین:

```python
# backend/urls.py
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

### 3. پیاده‌سازی Refresh Token API

در این مرحله باید یک API ایجاد کنیم تا وقتی Access Token کاربر منقضی شد، بدون نیاز به لاگین مجدد، توکن جدید دریافت کنه. برای این کار از View پیش‌فرض کتابخونه SimpleJWT استفاده می‌کنیم، با این تفاوت که:

- توکن‌های جدید در کوکی `HttpOnly` ذخیره میشن.
- `Refresh Token` از کوکی خونده میشه و برای Serializer ارسال میشه.

```python
# accounts/views.py
from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import Token
from rest_framework_simplejwt.views import TokenRefreshView

from accounts.jwt import set_token_cookies


class RefreshTokenAPIView(TokenRefreshView):
    def post(self, request: Request, *args, **kwargs) -> Response:
        try:
            serializer = self.get_serializer(data={"refresh": self.get_refresh_token_from_cookie()})
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0]) from e

        response = Response({}, status=status.HTTP_200_OK)

        # Set auth cookies
        access_token = serializer.validated_data.get("access")
        refresh_token = serializer.validated_data.get("refresh")
        set_token_cookies(response, access_token, refresh_token)

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
    # Auth
    path("auth/refresh_token/", views.RefreshTokenAPIView.as_view(), name="refresh-token"),
    path("auth/login/", views.LoginAPIView.as_view(), name="login"),
]
```

### 4. پیاده‌سازی سیستم احراز هویت JWT با کوکی

تا اینجا تونستیم کاربر رو لاگین کنیم و توکن‌های لازم رو در کوکی‌های کاربر ذخیره کنیم. حالا برای احراز هویت کاربر بر اساس کوکی باید یک `Authentication Class` جدید بنویسیم تا `Access Token` رو از کوکی بخونه و بر اساس اون احراز هویت کاربر انجام بشه.

```python
# accounts/authentication.py
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication

class JWTCookieAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)

        if header is None:
            raw_token = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE_ACCESS"]) or None
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)

        return self.get_user(validated_token), validated_token
```

در نهایت باید این کلاس رو به `DRF` هم معرفی کنیم تا برای احراز هویت کاربر در APIها از این کلاس استفاده کنه. برای این کار تنظیمات `REST_FRAMEWORK` رو در فایل `settings.py` به شکل زیر تغییر می‌دیم:

```python
# backend/settings.py

# DRF
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("accounts.authentication.JWTCookieAuthentication",),
}
```

برای تست سیستم احراز هویت، یک API ساده ایجاد می‌کنیم که اطلاعات کاربر رو فقط در صورتی نمایش بده که کاربر لاگین کرده باشه.

```python
# accounts/serializers.py
from django.contrib.auth.models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "first_name",
            "last_name",
        )
```

```python
# accounts/views.py
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from accounts.serializers import UserSerializer


class UserRetrieveAPIView(GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return self.request.user

    def get(self, request):
        serializer = self.get_serializer(instance=self.get_queryset())
        return Response(serializer.data, status=status.HTTP_200_OK)
```

```python
# accounts/urls.py
from django.urls import path

from accounts import views

app_name = "accounts"
urlpatterns = [
    # Auth
    path("auth/refresh_token/", views.RefreshTokenAPIView.as_view(), name="refresh-token"),
    path("auth/login/", views.LoginAPIView.as_view(), name="login"),
    # User
    path("user/", views.UserRetrieveAPIView.as_view(), name="user"),
]
```

## در بخش دوم چه مواردی بررسی خواهد شد؟

خب تا اینجا در بخش اول مقاله با مفاهیم اصلی JWT و چالش‌هایی که ممکنه در استفاده از اون پیش بیاد آشنا شدیم و سعی کردیم یک سیستم احراز هویت امن با استفاده از JWT و کوکی‌های HttpOnly پیاده‌سازی کنیم. اما این پایان کار نیست! در بخش دوم مقاله قراره به موضوعات دیگه‌ای مثل پیاده‌سازی `Logout API` و راهکارهای جلوگیری از حملات `CSRF` بپردازیم.

همچنین می‌تونید کدهای کامل پروژه رو از گیت‌هاب دریافت کنید. اگر این پروژه براتون مفید بود، خوشحال میشم به پروژه استار بدید.

[https://github.com/mobinghoveoud/drf-jwt-httponly-cookie](https://github.com/mobinghoveoud/drf-jwt-httponly-cookie)

اگر نظری، سوالی یا پیشنهادی دارید، لطفا در لینکدین باهام به اشتراک بذارید! 🙌

آدرس لینکدین: [linkedin.com/in/mobin-ghoveoud](https://linkedin.com/in/mobin-ghoveoud)

