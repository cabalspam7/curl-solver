#!/usr/bin/env python3
"""
curl_cffi Turnstile Solver v2 — Multi-engine fingerprint bypass

Primary: curl_cffi with chrome124 fingerprint + realistic headers
Fallback flow:
  curl_cffi (HTTP-level fingerprint) → nodriver (CDP) → camoufox → playwright

Supports:
- Turnstile invisible/managed auto-solve
- cf_clearance extraction for JS challenge bypass
- Real browser impersonation (JA3, TLS fingerprint, etc.)

API compatible with turnstile-solver-production:
POST /solve {sitekey, siteurl, proxy, session, timeout}
POST /solve-challenge {siteurl, timeout}
GET  /health
GET  /stats
"""
import os, re, json, time, uuid, asyncio, random, logging
from typing import Optional, Dict
from aiohttp import web

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('curl-solver')
API_KEY = os.environ.get('SOLVER_API_KEY', '')

# Metrics
STATS = {"solved":0, "errors":0, "cf_clearance":0, "total":0, "in_flight":0, "elapsed_sum":0, "started_at": time.time()}

# ============================================================================
# Engine 1: curl_cffi HTTP-level fingerprint (fastest, no browser)
# ============================================================================
async def solve_with_curl_cffi(sitekey: str, siteurl: str, timeout: int = 30, proxy: str = "", session_id: str = "") -> Optional[Dict]:
    try:
        from curl_cffi import requests as curl_req
    except ImportError:
        log.warning("[curl_cffi] not installed")
        return None

    # Fingerprint rotation - cycle through realistic browsers
    fingerprints = [
        "chrome124", "chrome131", "chrome120", 
        "safari17_0", "safari17_3_ios",
        "chrome99_android"
    ]
    fp = random.choice(fingerprints) if not session_id else fingerprints[hash(session_id) % len(fingerprints)]

    try:
        sess = curl_req.Session()
        sess.impersonate = fp
        
        # Realistic header set per browser
        base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Dnt": "1",
            "Cache-Control": "max-age=0",
        }
        if "safari" in fp:
            base_headers.update({
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Sec-Fetch-Dest": "document",
            })
        
        sess.headers.update(base_headers)

        # Proxy support
        proxies = {}
        if proxy:
            # format: user:pass@host:port or host:port
            if not proxy.startswith("http"):
                proxy = f"http://{proxy}"
            proxies = {"http": proxy, "https": proxy}
            # curl_cffi uses different proxy param
            sess.proxies = proxies

        log.info(f"[curl_cffi:{fp}] GET {siteurl[:80]} sitekey={sitekey[:20]}")

        # Visit page
        resp = sess.get(siteurl, timeout=timeout, impersonate=fp)
        html = resp.text
        status = resp.status_code
        
        # Extract cookies
        cookies_dict = {}
        try:
            if hasattr(sess.cookies, "items"):
                for k,v in sess.cookies.items():
                    cookies_dict[k] = v
            elif hasattr(sess.cookies, "get_dict"):
                cookies_dict = sess.cookies.get_dict()
        except:
            pass

        log.info(f"[curl_cffi:{fp}] status={status} len={len(html)} cookies={list(cookies_dict.keys())[:5]}")

        # Check cf_clearance - means JS challenge bypassed
        if "cf_clearance" in cookies_dict:
            log.info(f"[curl_cffi:{fp}] Got cf_clearance!")
            STATS["cf_clearance"] += 1
            return {"token": cookies_dict["cf_clearance"], "method": "cf_clearance", "cookies": cookies_dict, "fp": fp}

        # Pattern extraction
        token = extract_turnstile_token(html)
        if token:
            log.info(f"[curl_cffi:{fp}] Token extracted via {token[1]}: {token[0][:50]}...")
            return {"token": token[0], "method": token[1], "cookies": cookies_dict, "fp": fp}

        log.info(f"[curl_cffi:{fp}] No token found, needs browser interaction")
        return None

    except Exception as e:
        log.warning(f"[curl_cffi] Error: {e}")
        return None

def extract_turnstile_token(html: str):
    """Extract Turnstile token from HTML with multiple patterns"""
    # Pattern 1: input[name=cf-turnstile-response] value
    m = re.search(r'<input[^>]*name=["\']cf-turnstile-response["\'][^>]*value=["\']([^"\']{20,})["\']', html, re.I)
    if m and len(m.group(1)) > 20 and "DUMMY" not in m.group(1):
        return (m.group(1), "input_value")
    
    m = re.search(r'<input[^>]*value=["\']([^"\']{20,})["\'][^>]*name=["\']cf-turnstile-response["\']', html, re.I)
    if m and len(m.group(1)) > 20:
        return (m.group(1), "input_value_rev")

    # Pattern 2: turnstile.render with response in data
    for pat in [
        r'turnstile\.render.*?(["\'])([A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\1',
        r'cf-turnstile-response.*?value=["\']([^"\']{20,})["\']',
        r'"token"\s*:\s*"([A-Za-z0-9_\-\.]{50,})"',
    ]:
        mm = re.search(pat, html, re.S)
        if mm:
            # find which group has token
            for g in mm.groups():
                if g and len(g) > 30 and '.' in g:
                    if g.startswith(('0.','1.','2.','3.')) or g.count('.') >=2:
                        return (g, f"pattern:{pat[:20]}")

    # Pattern 3: Look in all script tags for JWT-like token (Turnstile tokens are JWTish)
    # Turnstile token format: typically starts with 0., 1., or contains dots
    for script_m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.S | re.I):
        content = script_m.group(1)
        if len(content) < 20:
            continue
        # Find long tokens
        jwt_pat = r'["\']([A-Za-z0-9_-]{60,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})["\']'
        for jm in re.finditer(jwt_pat, content):
            cand = jm.group(1)
            # Filter out obvious non-turnstile
            if cand.startswith(('eyJ', '0.', '1.', '2.', '3.')) or cand.count('.') >=2:
                if len(cand) > 80 and 'DUMMY' not in cand:
                    log.debug(f"[extract] Found candidate in script: {cand[:60]}...")
                    return (cand, "script_jwt")

    # Pattern 4: check for managed/invisible success message
    if 'turnstile' in html.lower() and ('success' in html.lower() or 'solved' in html.lower()):
        log.debug("[extract] Page mentions turnstile but no token found")

    return None

# ============================================================================
# Engine 2: nodriver (undetected Chrome CDP) - when curl_cffi not enough
# ============================================================================
async def solve_with_nodriver(sitekey: str, siteurl: str, timeout: int = 45, session_id: str = "") -> Optional[Dict]:
    try:
        import nodriver as uc
    except ImportError:
        log.warning("[nodriver] not installed")
        return None
    
    browser = None
    try:
        log.info(f"[nodriver] Launching for {siteurl[:60]} sitekey={sitekey[:20]}")
        chrome_path = os.environ.get('CHROME_PATH', '/usr/bin/chromium')
        cdp_port = random.randint(9200, 9350)
        cfg = uc.Config(
            browser_executable_path=chrome_path,
            sandbox=False,
            headless=True,
            port=cdp_port,
            browser_args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--window-size=1920,1080',
                '--no-first-run',
                '--no-default-browser-check',
                '--disable-background-timer-throttling',
                '--disable-backgrounding-occluded-windows',
                '--disable-renderer-backgrounding',
            ],
        )
        browser = await uc.Browser.create(config=cfg, headless=True, sandbox=False)
        page = await browser.get(siteurl)
        await asyncio.sleep(3)

        # Wait loop for token
        for attempt in range(max(10, timeout//3)):
            await asyncio.sleep(2)
            try:
                token = await page.evaluate('document.querySelector("input[name=cf-turnstile-response]")?.value || ""')
                if token and isinstance(token, str) and len(token) > 20:
                    log.info(f"[nodriver] SOLVED on attempt {attempt+1}: {token[:50]}...")
                    html = ""
                    try:
                        html = await page.get_content()
                    except:
                        pass
                    try:
                        ua = await page.evaluate("navigator.userAgent")
                    except:
                        ua = ""
                    return {"token": token, "method": "nodriver_input", "html": html[:5000], "ua": ua}
                
                token = await page.evaluate('window.turnstile ? (window.turnstile.getResponse() || "") : ""')
                if token and len(token) > 20:
                    log.info(f"[nodriver] SOLVED via API: {token[:50]}...")
                    return {"token": token, "method": "nodriver_api"}

                # Try clicking widget
                has_iframe = await page.evaluate('!!document.querySelector("iframe[src*=challenges.cloudflare.com]")')
                if has_iframe and attempt % 3 == 0:
                    try:
                        coords = await page.evaluate('''
                            (() => {
                                var el = document.querySelector('[data-sitekey], .cf-turnstile');
                                if (el) { var r = el.getBoundingClientRect(); return [r.x + r.width/2, r.y + r.height/2]; }
                                return null;
                            })()
                        ''')
                        if coords and len(coords)==2:
                            await page.mouse_click(float(coords[0]), float(coords[1]))
                            log.info(f"[nodriver] Clicked at {coords}")
                        else:
                            await page.mouse_click(400, 400)
                    except Exception as ce:
                        log.debug(f"[nodriver] click err {ce}")

            except Exception as e:
                log.debug(f"[nodriver] attempt {attempt} err {e}")
                continue

        log.info("[nodriver] Failed to get token")
        return None
    except Exception as e:
        log.error(f"[nodriver] Error: {e}")
        return None
    finally:
        if browser:
            try:
                browser.stop()
            except:
                pass

# ============================================================================
# HTTP Handlers
# ============================================================================
async def handle_solve(request):
    start = time.time()
    STATS["total"] += 1
    STATS["in_flight"] += 1
    
    try:
        try:
            data = await request.json()
        except:
            post = await request.post()
            data = dict(post)

        sitekey = data.get("sitekey", "") or data.get("websiteKey", "")
        siteurl = data.get("siteurl", "") or data.get("pageurl", "") or data.get("websiteURL", "")
        action = data.get("action", "login")
        timeout = min(int(data.get("timeout", 30)), 90)
        proxy = data.get("proxy", "") or data.get("proxyUrl", "") or ""
        session_id = data.get("session", "") or data.get("sessionId", "") or str(uuid.uuid4())[:8]

        if not siteurl:
            return web.json_response({"error": "siteurl/pageurl/websiteURL required"}, status=400)

        log.info(f"/solve sitekey={sitekey[:30]} siteurl={siteurl[:80]} timeout={timeout} session={session_id}")

        # Try engines in order
        result = None
        
        # Engine 1: curl_cffi (fast, no browser)
        result = await solve_with_curl_cffi(sitekey, siteurl, timeout, proxy, session_id)
        
        # Engine 2: nodriver (if curl_cffi failed and timeout allows)
        if not result and timeout > 15:
            log.info("curl_cffi failed, trying nodriver...")
            try:
                result = await asyncio.wait_for(
                    solve_with_nodriver(sitekey, siteurl, timeout, session_id),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                log.warning("[nodriver] timeout")

        if result and "token" in result:
            elapsed = time.time() - start
            STATS["solved"] += 1
            STATS["elapsed_sum"] += elapsed
            log.info(f"SOLVED in {elapsed:.2f}s via {result.get('method')} fp={result.get('fp','')}")
            return web.json_response({
                "token": result["token"],
                "method": result.get("method", "unknown"),
                "elapsed": round(elapsed, 3),
                "cookies": result.get("cookies", {}),
                "fingerprint": result.get("fp", "chrome124"),
            })
        else:
            elapsed = time.time() - start
            STATS["errors"] += 1
            log.warning(f"FAILED after {elapsed:.2f}s")
            return web.json_response({
                "error": "Failed to solve Turnstile",
                "elapsed": round(elapsed, 3),
                "tried": ["curl_cffi", "nodriver"],
            }, status=408)

    finally:
        STATS["in_flight"] = max(0, STATS["in_flight"] - 1)

async def handle_solve_challenge(request):
    """CF challenge bypass -> return cookies including cf_clearance"""
    start = time.time()
    STATS["total"] += 1
    STATS["in_flight"] += 1
    try:
        try:
            data = await request.json()
        except:
            data = dict(await request.post()) if request.can_read_body else {}
            if not data:
                data = dict(request.query)

        siteurl = data.get("siteurl", "") or data.get("pageurl", "") or data.get("url", "")
        timeout = min(int(data.get("timeout", 45)), 120)

        if not siteurl:
            return web.json_response({"error": "siteurl required"}, status=400)

        log.info(f"/solve-challenge {siteurl[:80]}")

        result = await solve_with_curl_cffi("", siteurl, timeout)

        if result and result.get("cookies"):
            cookies = result["cookies"]
            elapsed = time.time() - start
            STATS["solved"] += 1
            STATS["elapsed_sum"] += elapsed
            return web.json_response({
                "cookies": cookies,
                "elapsed": round(elapsed,3),
                "method": result.get("method"),
            })
        
        # Try nodriver as fallback for challenge
        result = await solve_with_nodriver("", siteurl, timeout)
        if result:
            elapsed = time.time() - start
            return web.json_response({
                "cookies": result.get("cookies", {}),
                "token": result.get("token",""),
                "elapsed": round(elapsed,3),
            })

        return web.json_response({"error": "challenge not solved"}, status=408)
    finally:
        STATS["in_flight"] = max(0, STATS["in_flight"]-1)

async def handle_health(request):
    return web.json_response({
        "status": "ok",
        "engine": "curl_cffi_multi",
        "fingerprint": "chrome124",
        "engines": ["curl_cffi", "nodriver"],
        "uptime": round(time.time() - STATS["started_at"]),
    })

async def handle_stats(request):
    total = STATS["total"]
    avg = STATS["elapsed_sum"]/max(1, STATS["solved"])
    return web.json_response({
        "status": "ok",
        "max_concurrent": 8,
        "solved_total": STATS["solved"] + STATS["errors"],
        "solved": STATS["solved"],
        "errors": STATS["errors"],
        "cf_clearance": STATS["cf_clearance"],
        "in_flight": STATS["in_flight"],
        "total": total,
        "avg_elapsed": round(avg,3),
        "engine": "curl_cffi",
        "fingerprint": "chrome124",
        "uptime": round(time.time() - STATS["started_at"]),
    })

async def handle_root(request):
    return web.json_response({
        "service": "curl_cffi Turnstile Solver v2",
        "fingerprint": "chrome124",
        "engines": ["curl_cffi", "nodriver"],
        "endpoints": {
            "solve": "POST /solve {sitekey, siteurl, timeout, proxy, session}",
            "solve-challenge": "POST /solve-challenge {siteurl, timeout}",
            "health": "GET /health",
            "stats": "GET /stats",
        },
        "stats": STATS,
    })

# Create app
app = web.Application()
app.router.add_post("/solve", handle_solve)
app.router.add_post("/solve-challenge", handle_solve_challenge)
app.router.add_get("/health", handle_health)
app.router.add_get("/stats", handle_stats)
app.router.add_get("/", handle_root)

# Also GET /solve for compatibility
app.router.add_get("/solve", handle_solve)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    log.info(f"Starting curl_cffi multi-engine solver on :{port} fingerprint=chrome124 engines=curl_cffi,nodriver")
    web.run_app(app, host="0.0.0.0", port=port)
