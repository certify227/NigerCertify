"""Rendu des templates login hotspot MikroTik."""

import re

DEFAULT_LOGIN_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{wifi_name}} — Connexion WiFi</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, sans-serif;
      background: {{background_color}};
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }
    .card {
      background: #fff;
      border-radius: 16px;
      padding: 2rem;
      max-width: 400px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,.3);
    }
    h1 { color: {{primary_color}}; font-size: 1.5rem; margin-bottom: .5rem; }
    p.sub { color: #666; font-size: .9rem; margin-bottom: 1.5rem; }
    label { display: block; font-size: .85rem; margin-bottom: .25rem; color: #444; }
    input {
      width: 100%;
      padding: .75rem;
      border: 1px solid #ddd;
      border-radius: 8px;
      margin-bottom: 1rem;
      font-size: 1rem;
    }
    button {
      width: 100%;
      padding: .85rem;
      background: {{primary_color}};
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      cursor: pointer;
    }
    .logo { max-height: 48px; margin-bottom: 1rem; }
  </style>
</head>
<body>
    <div class="card">
    <img src="{{logo_url}}" alt="Logo" class="logo" id="wz-logo">
    <h1>{{wifi_name}}</h1>
    <p class="sub">{{company_name}}</p>
  $(if trial == 'yes')
  <p class="sub">Essai gratuit — connectez-vous</p>
  $(endif)
    <form name="login" action="$(link-login-only)" method="post">
      <input type="hidden" name="dst" value="$(link-orig)">
      <input type="hidden" name="popup" value="true">
      <label>Utilisateur / Voucher</label>
      <input name="username" type="text" value="$(username)" placeholder="Code voucher">
      <label>Mot de passe</label>
      <input name="password" type="password" placeholder="Mot de passe">
      <button type="submit">Se connecter</button>
    </form>
  </div>
</body>
</html>"""


def render_login_template(template, operator=None, router=None):
    """Remplace variables WiFiZone + conserve variables MikroTik $(...)."""
    html = template.html_body or DEFAULT_LOGIN_HTML
    wifi_name = template.wifi_name or "WiFiZone"
    company = ""
    if operator:
        company = operator.company_name or operator.display_name
    if router and router.login_template_id == template.id:
        wifi_name = template.wifi_name or router.name

    replacements = {
        "{{wifi_name}}": wifi_name,
        "{{company_name}}": company,
        "{{primary_color}}": template.primary_color,
        "{{background_color}}": template.background_color,
        "{{logo_url}}": template.logo_url or "",
    }
    for key, val in replacements.items():
        html = html.replace(key, val)

    if not template.logo_url:
        html = re.sub(r"<img[^>]*id=\"wz-logo\"[^>]*>", "", html)

    return html


def build_mikrotik_login_html(template, operator=None, router=None) -> str:
    """HTML final pour upload MikroTik (login.html)."""
    html = render_login_template(template, operator=operator, router=router)
    delay = template.login_delay_seconds or 0
    if delay > 0:
        cyber_block = f"""
<div id="wz-cyber-timer" style="text-align:center;padding:1rem;background:#fff3cd;border-radius:8px;margin-bottom:1rem;">
  Mode cyber café — accès dans <strong id="wz-count">{delay}</strong> s
</div>
<script>
(function() {{
  var s = {delay};
  var el = document.getElementById('wz-count');
  var btn = document.querySelector('button[type=submit], form button');
  if (btn) btn.disabled = true;
  var timer = setInterval(function() {{
    s--;
    if (el) el.textContent = s;
    if (s <= 0) {{
      clearInterval(timer);
      if (btn) btn.disabled = false;
      var box = document.getElementById('wz-cyber-timer');
      if (box) box.style.display = 'none';
    }}
  }}, 1000);
}})();
</script>"""
        html = html.replace("</body>", cyber_block + "</body>")
    return html
