#!/usr/bin/env python3
"""vibecheck - heuristic detector for "vibe coded" websites.

Usage:
    python vibecheck.py https://example.com
    python vibecheck.py https://example.com --json
    python vibecheck.py --file page.html

It fetches the page, headers and a few JS bundles (stdlib only), looks for
AI-builder fingerprints, generic AI boilerplate, missing production basics and
security slips, then prints a score, reasons and a fix for each finding.

Heuristics only: a high score means "likely", never proof.
"""
import argparse, json, re, sys
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

UA = "Mozilla/5.0 (compatible; vibecheck/1.0)"


def fetch(url, limit=2_000_000):
    try:
        r = urlopen(Request(url, headers={"User-Agent": UA}), timeout=15)
        return r.read(limit).decode("utf-8", "replace"), dict(r.headers), r.status
    except Exception:
        return None, {}, None


# (id, category, weight, reason, fix, test) -- test(ctx) -> evidence string or None
def rx(pattern, flags=re.I):
    p = re.compile(pattern, flags)
    def f(text):
        m = p.search(text)
        return m.group(0)[:80] if m else None
    return f


BUILDERS = rx(r"lovable\.(app|dev)|gptengineer|v0\.dev|bolt\.new|stackblitz|base44|\.replit\.(app|dev)|created with (lovable|bolt|v0)|cursor\.sh|windsurf")
DEFAULT_TITLE = rx(r"<title>\s*(vite \+ react|create next app|react app|lovable generated project|vite app|my app|untitled)[^<]*</title>")
LOREM = rx(r"lorem ipsum|john doe|jane smith|acme (inc|corp)|your (company|name|brand) here|example\.com/?\"")
BUZZ = re.compile(r"\b(revolutioni[sz]e|seamless(ly)?|elevate your|unlock the (power|potential)|cutting-edge|game-?changer|supercharge|streamline your|next-gen|empower(s|ing)? (you|your)|transform your|effortless(ly)?|harness the power)\b", re.I)
GRADIENT = rx(r"from-(purple|violet|indigo|blue)-\d+[^\"']*(via-[a-z]+-\d+[^\"']*)?to-(pink|blue|purple|cyan|indigo)-\d+")
SHADCN = rx(r"data-radix|radix-:r|lucide|class=\"[^\"]*(text-muted-foreground|bg-background|border-border)")
SECRETS = rx(r"(sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9A-Za-z]{20,}|service_role[^a-z]{0,20}eyJ[A-Za-z0-9_\-\.]{20,}|AKIA[0-9A-Z]{16})", 0)
SUPABASE = rx(r"[a-z0-9]{15,}\.supabase\.co")
LOCALHOST = rx(r"https?://(localhost|127\.0\.0\.1)[:/]")
CONSOLE = rx(r"console\.(log|debug)\(\s*[\"'](test|here|debug|data|response|error)", 0)
EMPTY_LINK = rx(r"<a[^>]+href=[\"'](#|javascript:void\(0\);?)?[\"'][^>]*>")
EMOJI_H = rx(r"<h[1-3][^>]*>\s*[\U0001F300-\U0001FAFF\u2600-\u27BF]")
TODO = rx(r"(TODO|FIXME|placeholder text|coming soon)", 0)


def meta(text, name):
    return re.search(r"<meta[^>]+(name|property)=[\"']%s[\"']" % re.escape(name), text, re.I)


def tests(ctx):
    h, hdr, bundles, base = ctx["html"], ctx["headers"], ctx["bundles"], ctx["url"]
    low = {k.lower(): v for k, v in hdr.items()}
    allsrc = h + "\n" + "\n".join(bundles.values())
    body_text = re.sub(r"<(script|style)[\s\S]*?</\1>|<[^>]+>", " ", h, flags=re.I)
    F = []

    def add(id, cat, w, reason, fix, ev=None):
        if ev:
            F.append(dict(id=id, category=cat, weight=w, reason=reason, fix=fix,
                          evidence=ev if isinstance(ev, str) else ""))

    add("builder-fingerprint", "Fingerprint", 30, "References an AI app builder (Lovable, Bolt, v0, Replit, Base44...).",
        "Remove builder branding/badges and tags, set your own domain, and review the exported code before shipping.", BUILDERS(allsrc))
    add("default-title", "Fingerprint", 15, "Default template <title> left in place.",
        "Write a real, unique title (50-60 chars) for every page.", DEFAULT_TITLE(h))
    add("placeholder-content", "Content", 12, "Placeholder or fake-person text (lorem ipsum, John Doe, Acme).",
        "Replace all placeholder copy with real content; grep the repo for 'lorem', 'Acme', 'John'.", LOREM(h))
    n = len(BUZZ.findall(body_text))
    add("ai-buzzwords", "Content", 8 if n < 5 else 14, "Heavy use of generic marketing filler (%d hits: seamless, elevate, unlock the power...)." % n,
        "Rewrite copy with specifics: who it is for, what it does, proof (numbers, names, screenshots).", "%d buzzword hits" % n if n >= 3 else None)
    add("gradient-hero", "Design", 6, "Stock purple/blue gradient Tailwind styling, a common AI-generated look.",
        "Define a brand palette in your Tailwind config and use it instead of default gradients.", GRADIENT(h))
    add("shadcn-lucide", "Design", 4, "shadcn/Radix + Lucide default component look (common in AI scaffolds, also in many human projects).",
        "Customise tokens, radii and typography so it stops looking like the template.", SHADCN(h))
    add("emoji-headings", "Design", 5, "Emojis used as heading/feature icons.", "Use a consistent icon set or custom SVGs.", EMOJI_H(h))
    add("dead-links", "Quality", 7, "Links that go nowhere (href='#' / empty).",
        "Point every link to a real route or turn it into a <button>; add a link checker to CI.", EMPTY_LINK(h))
    add("todo-left", "Quality", 5, "TODO/placeholder/'coming soon' text left in shipped HTML.", "Remove or finish unfinished sections.", TODO(body_text))

    # SEO / basics
    add("no-meta-desc", "Basics", 6, "No meta description.", "Add <meta name=description> (140-160 chars).", None if meta(h, "description") else "missing")
    add("no-og", "Basics", 5, "No Open Graph / social preview tags.", "Add og:title, og:description, og:image, twitter:card.", None if meta(h, "og:title") else "missing")
    add("no-canonical", "Basics", 3, "No canonical link.", "Add <link rel=canonical href=...>.", None if re.search(r"rel=[\"']canonical", h, re.I) else "missing")
    add("no-lang", "Accessibility", 4, "<html> has no lang attribute.", "Use <html lang='en'>.", None if re.search(r"<html[^>]+lang=", h, re.I) else "missing")
    add("no-favicon", "Basics", 4, "No favicon link.", "Add a branded favicon + apple-touch-icon.", None if re.search(r"rel=[\"'](shortcut )?icon", h, re.I) else "missing")
    imgs = re.findall(r"<img\b[^>]*>", h, re.I)
    noalt = [i for i in imgs if not re.search(r"\balt=[\"'][^\"']+", i, re.I)]
    add("img-no-alt", "Accessibility", 6, "%d of %d images lack alt text." % (len(noalt), len(imgs)),
        "Add meaningful alt text (alt='' for purely decorative images).", "%d/%d" % (len(noalt), len(imgs)) if imgs and len(noalt) / len(imgs) > .3 else None)
    h1 = len(re.findall(r"<h1\b", h, re.I))
    add("h1-count", "Accessibility", 4, "Page has %d <h1> elements (should be exactly 1)." % h1, "Use one <h1>, then <h2>/<h3> in order.", "%d h1" % h1 if h1 != 1 and len(h) > 3000 else None)
    sem = len(re.findall(r"<(main|nav|header|footer|section|article)\b", h, re.I))
    divs = len(re.findall(r"<div\b", h, re.I))
    add("div-soup", "Quality", 5, "Mostly <div>s, few semantic landmarks.", "Use <header>, <nav>, <main>, <section>, <footer>.", "%d divs / %d semantic" % (divs, sem) if divs > 40 and sem < 3 else None)
    spa = re.search(r"<div id=[\"'](root|app|__next)[\"']\s*>\s*</div>", h, re.I)
    add("csr-only", "Quality", 6, "Empty client-rendered shell: crawlers and no-JS users see nothing.",
        "Add SSR/SSG (Next.js, Astro, Remix) or pre-render key pages, plus a <noscript> fallback.", "empty #root" if spa and "<noscript" not in h.lower() else None)
    add("inline-styles", "Quality", 3, "Heavy inline style attributes.", "Move styling into classes/design tokens.",
        "%d inline styles" % len(re.findall(r"style=\"", h)) if len(re.findall(r"style=\"", h)) > 40 else None)
    if ctx.get("robots") is False:
        add("no-robots", "Basics", 3, "No robots.txt.", "Add robots.txt and sitemap.xml.", "404")

    # Security
    sec = [("content-security-policy", "CSP"), ("strict-transport-security", "HSTS"),
           ("x-content-type-options", "X-Content-Type-Options"), ("x-frame-options", "X-Frame-Options / frame-ancestors")]
    if hdr:
        miss = [n for k, n in sec if k not in low]
        add("sec-headers", "Security", 8, "Missing security headers: %s." % ", ".join(miss),
            "Set them at your host/CDN (Vercel headers, Netlify _headers, nginx) or via Helmet.", ", ".join(miss) if len(miss) >= 3 else None)
    add("secret-leak", "Security", 40, "A secret-looking key is exposed in client code.",
        "Rotate the key NOW, move calls behind a server/edge function, and keep secrets in env vars that never ship to the browser.", SECRETS(allsrc))
    add("supabase-client", "Security", 10, "Supabase used directly from the browser (check Row Level Security!).",
        "Enable RLS on every table, write explicit policies, and never expose the service_role key.", SUPABASE(allsrc))
    add("localhost", "Quality", 10, "Hard-coded localhost URL in production code.", "Use environment variables for API base URLs.", LOCALHOST(allsrc))
    add("sourcemaps", "Security", 6, "Source maps are publicly exposed, leaking original source.", "Disable production sourcemaps or upload them privately to your error tracker.",
        next((u for u, t in bundles.items() if "sourceMappingURL=" in t[-300:]), None))
    add("console-noise", "Quality", 4, "Debug console.log calls left in the bundle/inline scripts.", "Strip with a lint rule (no-console) or build plugin.", CONSOLE(allsrc))
    if low.get("server", "").lower().startswith("x-powered") or "x-powered-by" in low:
        add("powered-by", "Security", 2, "X-Powered-By header discloses the stack.", "Disable it (app.disable('x-powered-by')).", low.get("x-powered-by", ""))
    return F


def analyse(url, html, headers):
    bundles, robots = {}, None
    if url:
        srcs = re.findall(r"<script[^>]+src=[\"']([^\"']+)", html, re.I)
        host = urlparse(url).netloc
        for s in srcs:
            u = urljoin(url, s)
            if urlparse(u).netloc == host and len(bundles) < 4:
                t, _, st = fetch(u, 3_000_000)
                if t:
                    bundles[u] = t
        _, _, st = fetch(urljoin(url, "/robots.txt"), 2000)
        robots = st == 200
    ctx = dict(url=url, html=html, headers=headers, bundles=bundles, robots=robots)
    F = tests(ctx)
    score = min(100, sum(f["weight"] for f in F))
    verdict = ("Very likely vibe coded" if score >= 60 else "Likely vibe coded" if score >= 40
               else "Possibly vibe coded / unpolished" if score >= 20 else "Probably human-reviewed")
    return dict(url=url, score=score, verdict=verdict, findings=sorted(F, key=lambda f: -f["weight"]))


def report(r):
    print("\n%s\nvibecheck: %s\nScore: %d/100  ->  %s\n%s" % ("=" * 64, r["url"] or "local file", r["score"], r["verdict"], "=" * 64))
    if not r["findings"]:
        print("No red flags found.")
    for f in r["findings"]:
        print("\n[%s | +%d] %s" % (f["category"], f["weight"], f["reason"]))
        if f["evidence"]:
            print("   evidence: %s" % f["evidence"])
        print("   fix:      %s" % f["fix"])
    print("\nNote: heuristic score. Plenty of good human-made sites trip a few of these.\n")


def main():
    ap = argparse.ArgumentParser(description="Detect vibe-coded websites and suggest fixes.")
    ap.add_argument("url", nargs="?")
    ap.add_argument("--file", help="analyse a local HTML file instead")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.file:
        html, hdr, url = open(a.file, encoding="utf-8", errors="replace").read(), {}, None
    elif a.url:
        url = a.url if a.url.startswith("http") else "https://" + a.url
        html, hdr, st = fetch(url)
        if html is None:
            sys.exit("Could not fetch %s" % url)
    else:
        ap.error("give a URL or --file")
    r = analyse(url, html, hdr)
    print(json.dumps(r, indent=2)) if a.json else report(r)


if __name__ == "__main__":
    main()
