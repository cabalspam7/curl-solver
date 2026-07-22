#!/usr/bin/env python3
"""
curl_cffi Turnstile Solver — HTTP-level fingerprint bypass
Deploys to Railway as a lightweight alternative to Camoufox browsers.
"""
import os, re, json, time, uuid, hashlib
from aiohttp import web
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('curl-solver')

# ===== Solver Engine =====

async def solve_turnstile(sitekey, siteurl, action="login", timeout=60):
    """Solve Turnstile using curl_cffi with browser impersonation."""
    from curl_cffi import requests as curl_req
    
    session = curl_req.Session()
    session.impersonate = "chrome124"
    session.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    })
    
    # Visit page with the target sitekey embedded
    resp = session.get(siteurl, timeout=timeout)
    html = resp.text
    cookies = dict(session.cookies) if hasattr(session.cookies, 'items') else {}
    
    log.info(f"curl_cffi → {siteurl[:60]}: status={resp.status_code}, len={len(html)}")
    
    # Check for cf_clearance
    if "cf_clearance" in cookies:
        log.info("Got cf_clearance cookie!")
        return {"token": cookies["cf_clearance"], "method": "cf_clearance", "cookies": cookies}
    
    # Pattern 1: input[name=cf-turnstile-response]
    m = re.search(r'<input[^>]*name=["\']cf-turnstile-response["\'][^>]*value=["\']([^"\']+)["\']', html)
    if m and m.group(1) and len(m.group(1)) > 10:
        return {"token": m.group(1), "method": "input_field"}
    
    # Pattern 2: window.cfTurnstileCallback data
    m = re.search(r'cf-turnstile-callback[^;]*["\']([^"\']+)["\']', html)
    if m:
        return {"token": m.group(1), "method": "callback"}
    
    # Pattern 3: Turnstile token in script tags
    for sm in re.finditer(r'<script[^>]*>([^<]+)</script>', html):
        tok_m = re.search(r'["\']([A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,})["\']', sm.group(1))
        if tok_m:
            cand = tok_m.group(1)
            if cand.startswith(("1.", "0.", "3.")):
                return {"token": cand, "method": "script_extract"}
    
    return {"error": "No token found", "html_len": len(html), "cookies": cookies}


# ===== HTTP API =====

async def handle_solve(request):
    """POST /solve — curl_cffi Turnstile solver"""
    try:
        data = await request.json()
    except:
        return web.json_response({"error": "invalid JSON"}, status=400)
    
    sitekey = data.get("sitekey", "")
    siteurl = data.get("siteurl", "")
    action = data.get("action", "login")
    timeout = min(int(data.get("timeout", 30)), 90)
    
    if not siteurl:
        return web.json_response({"error": "siteurl required"}, status=400)
    
    result = await solve_turnstile(sitekey, siteurl, action, timeout)
    
    if "token" in result:
        return web.json_response({
            "token": result["token"],
            "method": result.get("method", "unknown"),
            "elapsed": 0,
        })
    else:
        return web.json_response(result, status=408)


async def handle_health(request):
    return web.json_response({
        "status": "ok",
        "engine": "curl_cffi",
        "fingerprint": "chrome124",
    })


app = web.Application()
app.router.add_post("/solve", handle_solve)
app.router.add_get("/health", handle_health)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    web.run_app(app, host="0.0.0.0", port=port)
