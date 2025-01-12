---
slug: "securing-django-rest-jwt-httponly-cookie-part-2"
title: "Securing Django Rest Framework with JWT Authentication in HttpOnly Cookie - Part 2"
tags: ["django", "drf", "jwt", "auth", "httponly-cookie", "csrf"]
categories: ["django"]
date: "2025-01-10"
thumbnail: "/images/posts/securing-django-rest-jwt-httponly-cookie-part-2/drf-jwt-httponly-part-2.jpeg"
---

## Recap of Part One
In [Part One]({{< relref "posts/securing-django-rest-jwt-httponly-cookie-part-1.md" >}}), we covered the basics of JWT, implemented the login and refresh token APIs, and learned how to securely store JWTs in HttpOnly cookies for better security.

In this part, we will implement the `Logout API` and explore `CSRF` attacks along with methods to prevent them.

{{< figure src="/images/posts/securing-django-rest-jwt-httponly-cookie-part-2/drf-jwt-httponly-part-2.jpeg" alt="Django JWT CSRF" >}}

## Implementing the Logout API

Here, we will create a new API for logging out users, but first, we need to add some prerequisites to the project.

### 1. Removing JWT Tokens from Cookies

Just like the function we used for storing tokens in cookies, we also need a function to remove cookies.

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
You might find it interesting that the `delete_cookie` method doesn’t actually delete the cookie. Instead, it sets a new cookie with the same properties but an expired timestamp (timestamp=0), causing the browser to ignore it.
{{< /notice >}}

### 2. Managing JWT Tokens

Proper management of the Refresh Token is a crucial aspect of using JWTs. When a user logs out, we remove the tokens from their cookies. However, the user might have saved the Refresh Token beforehand and could use it to obtain a new Access Token.

To prevent this, the SimpleJWT library offers a `Blacklist` solution. This method allows us to blacklist the Refresh Token (store it in the database) whenever necessary. If the user tries to use an old Refresh Token to get a new Access Token, we can check the database and prevent this action.

To implement this approach, simply modify the `settings.py` file as follows:

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
After applying these changes, make sure to run `python manage.py migrate` to update the database accordingly.
{{< /notice >}}

{{< notice tip >}}
Another method for managing Refresh Tokens is called `Whitelist`. It's worth exploring to determine which approach best suits your project's needs.
{{< /notice >}}

### 3. Logout API

Finally, we need to create a new API for handling user logout. If the user is logged in, we will remove the JWTs from the cookies and ensure the Refresh Token is added to the blacklist.

To achieve this, we first extract the Refresh Token from the cookie and pass it to the `TokenBlacklistSerializer` (provided by the SimpleJWT library) to validate and blacklist the token.

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
## Preventing CSRF Attacks

As mentioned earlier, using cookies can increase the chance of encountering `CSRF` attacks. Therefore, it is crucial to implement appropriate measures to prevent such attacks. Let’s first understand the concept of CSRF and explore ways to prevent it.

### 1. Understanding CSRF and Prevention Methods

**CSRF (Cross-Site Request Forgery)** is a common web attack where an attacker tricks a user into performing unwanted actions on a trusted website. This attack exploits the user's authenticated session without their knowledge.

To prevent CSRF, several methods can be employed:

- **CSRF Token:** A unique and unpredictable token generated by the server and provided to the client. When the client sends sensitive requests, such as form submissions, it includes this token. This makes it difficult for an attacker to forge a valid request on behalf of the victim.
- **SameSite Cookies:** This cookie attribute is a browser security mechanism that restricts cookies from being sent with cross-site requests. This helps prevent CSRF by ensuring that authentication cookies are not sent with malicious requests. However, this method alone is not guaranteed to work, as some browsers may not fully support this feature.
- **Referer Header Validation:** Another method is to check the `Referer` header in HTTP requests to verify the request's origin. However, this approach is less reliable than CSRF tokens, as attackers can easily spoof the `Referer` header.

### 2. CSRF Implementation in Django

Django includes a built-in middleware for handling CSRF protection. This middleware not only checks the `CSRF token` in requests but also validates the `Referer` header. Note that these checks are not performed for safe HTTP methods (`GET`, `HEAD`, `OPTION`, and `TRACE`).

Django automatically generates a CSRF token for each user and stores it in a cookie. When a request is made, the token must be included in the form data. The Django middleware then compares the submitted token with the one stored in the cookie. If they do not match, the request is denied.

{{< notice tip >}}
The token placed in the user's form is a `Masked Token`, which is generated using the original CSRF token through specific algorithms and is twice the length of the original token. This technique helps prevent [BREACH Attack](https://www.breachattack.com). You can learn more about it if you're interested.
{{< /notice >}}

To manage CSRF, you need to add the following settings to your project:

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

### 3. CSRF Validation in APIs

In Django Rest Framework (DRF), CSRF validation is not enabled by default, and handling CSRF tokens in APIs is slightly different. To implement this, we need to add CSRF validation to the `Authentication` class we created earlier. Note that this validation is not necessary for APIs that do not require authentication or when the user is not logged in.

Here's how we can update the `JWTCookieAuthentication` class:

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

If the `AUTH_COOKIE_USE_CSRF` setting in SimpleJWT is set to `False`, CSRF validation will be skipped, but this is **strongly not recommended!**

### 4. When Does the CSRF Token Expire?

A CSRF token technically doesn’t expire as long as the corresponding cookie remains in the user’s browser. (Refer to the `CSRF_COOKIE_AGE` setting for more details.)

Additionally, Django’s documentation recommends regenerating the CSRF token after each user login for security reasons. Therefore, we can update the Login API we implemented earlier as follows:

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

### 5. Implementing the CSRF Token API

As mentioned earlier, DRF does not automatically handle CSRF validation, and consequently, the CSRF token cookie is not automatically set for the user (except during login). In certain situations, we may need to generate a new CSRF token for the user. To achieve this, we can define a new API as follows:

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

In this setup, the CSRF token is stored in a cookie, and the masked token is returned in the API response.

### 6. How to Work with API

For requests that do not include a HTML form, Django cannot automatically include the CSRF token in the request. To address this, Django suggests using a specific header. The Frontend should read the CSRF token from the cookie and send it in the `X-CSRFToken` header. This allows Django to validate the token by comparing the header's value with the token stored in the cookie.

## The End!

In these two parts of the article, we covered the key aspects of implementing an authentication system using JWT and HTTPOnly cookies. Remember, there are always more details to explore and learn. _Never stop learning and enhancing your skills!_

To wrap up, here are some questions to ponder. If you find the answers, feel free to share them in the comments on [LinkedIn](https://www.linkedin.com/posts/mobin-ghoveoud_%DA%86%DA%AF%D9%88%D9%86%D9%87-%DB%8C%DA%A9-%D8%B3%DB%8C%D8%B3%D8%AA%D9%85-%D8%A7%D8%AD%D8%B1%D8%A7%D8%B2-%D9%87%D9%88%DB%8C%D8%AA-%D8%A7%D9%85%D9%86-%D8%A8%D8%A7-jwt-%D9%88-activity-7284147108201328640-4BaK).

{{< notice question >}}
We mentioned that the SimpleJWT library uses a Blacklist strategy for token management. However, upon closer examination, this might not be entirely accurate. How do you think this library actually implements this feature?
{{< /notice >}}

{{< notice question >}}
We explained that the Frontend can extract the CSRF token from the cookie and send it via a specific header. What do you think is the advantage of this approach, given that the values in the header and the cookie will always match? 🤔
{{< /notice >}}

{{< notice question >}}
What do you think is the difference between the main CSRF token and the masked token, and how does it help prevent BREACH attacks?
{{< /notice >}}

LinkedIn Post:

[linkedin.com/in/mobin-ghoveoud](https://www.linkedin.com/posts/mobin-ghoveoud_%DA%86%DA%AF%D9%88%D9%86%D9%87-%DB%8C%DA%A9-%D8%B3%DB%8C%D8%B3%D8%AA%D9%85-%D8%A7%D8%AD%D8%B1%D8%A7%D8%B2-%D9%87%D9%88%DB%8C%D8%AA-%D8%A7%D9%85%D9%86-%D8%A8%D8%A7-jwt-%D9%88-activity-7284147108201328640-4BaK)

GitHub Project:

[https://github.com/mobinghoveoud/drf-jwt-httponly-cookie](https://github.com/mobinghoveoud/drf-jwt-httponly-cookie)

Thank you for your attention!
