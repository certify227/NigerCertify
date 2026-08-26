from django.shortcuts import redirect


class TOTPVerificationMiddleware:
  EXEMPT_PREFIXES = (
      "/accounts/login",
      "/accounts/logout",
      "/accounts/register",
      "/accounts/totp",
      "/accounts/password-reset",
      "/static/",
      "/api/",
  )

  def __init__(self, get_response):
      self.get_response = get_response

  def __call__(self, request):
      if request.user.is_authenticated and request.user.totp_enabled:
          if not request.session.get("totp_verified"):
              path = request.path
              if not any(path.startswith(p) for p in self.EXEMPT_PREFIXES):
                  return redirect("accounts:totp_verify")
      return self.get_response(request)
