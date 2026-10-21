"""Username OSINT: Sherlock-style existence check across public profile URLs.
Only public, unauthenticated pages are probed -> no ToS-violating scraping."""
from concurrent.futures import ThreadPoolExecutor
import requests

UA = {"User-Agent": "Mozilla/5.0 (compatible; mini-osint/0.1; +research)"}

# (site, url_template, not-found marker in body)
SITES = [
    ("GitHub",       "https://github.com/{u}",                []),
    ("GitLab",       "https://gitlab.com/{u}",                []),
    ("Reddit",       "https://www.reddit.com/user/{u}",       []),
    ("Instagram",    "https://www.instagram.com/{u}/",        ["page isn't available", "page not found"]),
    ("X/Twitter",    "https://x.com/{u}",                     ["this account doesn't exist"]),
    ("YouTube",      "https://www.youtube.com/@{u}",          ["page not found"]),
    ("TikTok",       "https://www.tiktok.com/@{u}",           []),
    ("Pinterest",    "https://www.pinterest.com/{u}/",        []),
    ("LinkedIn",     "https://www.linkedin.com/in/{u}",       []),
    ("Medium",       "https://medium.com/@{u}",               []),
    ("dev.to",       "https://dev.to/{u}",                    []),
    ("Twitch",       "https://www.twitch.tv/{u}",             []),
    ("Steam",        "https://steamcommunity.com/id/{u}",     []),
    ("Spotify",      "https://open.spotify.com/user/{u}",     []),
    ("SoundCloud",   "https://soundcloud.com/{u}",            []),
    ("Bandcamp",     "https://{u}.bandcamp.com",              []),
    ("Vimeo",        "https://vimeo.com/{u}",                 []),
    ("Behance",      "https://www.behance.net/{u}",           []),
    ("Dribbble",     "https://dribbble.com/{u}",              []),
    ("Flickr",       "https://www.flickr.com/people/{u}/",    []),
    ("Tumblr",       "https://{u}.tumblr.com",                []),
    ("WordPress",    "https://{u}.wordpress.com",             []),
    ("Blogspot",     "https://{u}.blogspot.com",              []),
    ("Substack",     "https://{u}.substack.com",              []),
    ("About.me",     "https://about.me/{u}",                  []),
    ("Keybase",      "https://keybase.io/{u}",                []),
    ("Gravatar",     "https://gravatar.com/{u}",              []),
    ("Mastodon",     "https://mastodon.social/@{u}",          []),
    ("Telegram",     "https://t.me/{u}",                      []),
    ("Roblox",       "https://www.roblox.com/user.aspx?username={u}", []),
    ("Chess.com",    "https://www.chess.com/member/{u}",      []),
    ("Lichess",      "https://lichess.org/@/{u}",             []),
    ("Hacker News",  "https://news.ycombinator.com/user?id={u}", []),
    ("Product Hunt", "https://www.producthunt.com/@{u}",      []),
    ("Patreon",      "https://www.patreon.com/{u}",           []),
    ("Bitbucket",    "https://bitbucket.org/{u}/",            []),
    ("Codeberg",     "https://codeberg.org/{u}",              []),
    ("Replit",       "https://replit.com/@{u}",               []),
    ("HuggingFace",  "https://huggingface.co/{u}",            []),
    ("Kaggle",       "https://www.kaggle.com/{u}",            []),
    ("PyPI",         "https://pypi.org/user/{u}/",            []),
    ("npm",          "https://www.npmjs.com/~{u}",            []),
    ("Docker Hub",   "https://hub.docker.com/u/{u}",          []),
    ("Pastebin",     "https://pastebin.com/u/{u}",            []),
    ("Imgur",        "https://imgur.com/user/{u}",            []),
    ("9GAG",         "https://9gag.com/u/{u}",                []),
    ("VK",           "https://vk.com/{u}",                    []),
    ("OK.ru",        "https://ok.ru/{u}",                     []),
    ("eBay",         "https://www.ebay.com/usr/{u}",          []),
    ("ask.fm",       "https://ask.fm/{u}",                    []),
]

def _check(username, site):
    name, tpl, markers = site
    url = tpl.format(u=username)
    try:
        r = requests.get(url, headers=UA, timeout=6, allow_redirects=True)
        if r.status_code == 404:
            return {"site": name, "url": url, "status": "not_found"}
        if r.status_code == 200:
            body = r.text.lower()
            if any(m.lower() in body for m in markers):
                return {"site": name, "url": url, "status": "not_found"}
            return {"site": name, "url": url, "status": "found"}
        return {"site": name, "url": url, "status": "unknown", "http": r.status_code}
    except requests.exceptions.Timeout:
        return {"site": name, "url": url, "status": "unknown", "error": "timeout"}
    except Exception as e:
        return {"site": name, "url": url, "status": "unknown", "error": str(e)[:120]}

def lookup(username, max_workers=10):
    username = username.strip().lstrip("@")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = list(ex.map(lambda s: _check(username, s), SITES))
    found  = [r for r in results if r["status"] == "found"]
    return {
        "username": username,
        "checked": len(results),
        "found_count": len(found),
        "results": sorted(results, key=lambda r: (r["status"] != "found", r["site"])),
    }
