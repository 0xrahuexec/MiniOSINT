"""Telegram OSINT: public channel/group statistics via Telethon (async API).
Setup: put TELEGRAM_API_ID / TELEGRAM_API_HASH in .env (my.telegram.org), then run
the ONE-TIME interactive login:  python telegram_login.py
(creates osint_session.session in the project root; the web app reuses it).
Only PUBLIC channels/groups are queried."""
import os

# project root = app/modules/../..  (must match telegram_login.py, which saves to project root)
SESSION_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                            "osint_session")

async def lookup(channel, limit=200, api_id=None, api_hash=None):
    if os.name == "nt":     # Telethon on Windows requires the selector loop policy
        import asyncio, sys
        if sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    api_id = api_id or os.getenv("TELEGRAM_API_ID")
    api_hash = api_hash or os.getenv("TELEGRAM_API_HASH")
    if not (api_id and api_hash):
        return {"error": "Set TELEGRAM_API_ID and TELEGRAM_API_HASH in .env "
                         "(get them at https://my.telegram.org -> API Development Tools), "
                         "then run: python telegram_login.py (one-time, interactive)"}

    from telethon import TelegramClient, errors

    channel = channel.strip().lstrip("@")
    for prefix in ("https://t.me/", "http://t.me/", "t.me/"):
        if channel.startswith(prefix):
            channel = channel[len(prefix):]
            break

    client = TelegramClient(SESSION_PATH, int(api_id), api_hash)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            return {"error": ("session not authorized — Telegram requires a one-time interactive "
                              "login. Stop the server, run: python telegram_login.py "
                              "(phone → code → 2FA), then restart. "
                              f"(expected session file: {SESSION_PATH}.session)")}

        try:
            ent = await client.get_entity(channel)
        except ValueError:
            return {"error": f"cannot find any public channel/group named '{channel}' — "
                             "check the exact username (t.me/<name>) and that it exists."}

        msgs = []
        async for m in client.iter_messages(ent, limit=limit):
            msgs.append(m)

        fwd = sum(1 for m in msgs if getattr(m, "fwd_from", None) or getattr(m, "forward", None))
        views = [m.views for m in msgs if getattr(m, "views", None)]
        return {
            "title": getattr(ent, "title", None) or getattr(ent, "first_name", None),
            "username": getattr(ent, "username", None),
            "participants": getattr(ent, "participants_count", None),
            "description": (getattr(ent, "about", None) or "")[:500],
            "created": str(getattr(ent, "date", None)),
            "sampled_messages": len(msgs),
            "forwarded_ratio": round(fwd / len(msgs), 2) if msgs else None,
            "avg_views": round(sum(views) / len(views)) if views else None,
            "last_activity": str(msgs[0].date) if msgs else None,
            "first_sampled": str(msgs[-1].date) if msgs else None,
            "recent_message_preview": (msgs[0].message or "")[:300] if msgs else None,
            "official_site": getattr(ent, "site", None),
        }
    except errors.ApiIdInvalidError:
        return {"error": "TELEGRAM_API_ID / TELEGRAM_API_HASH rejected by Telegram — "
                         "re-copy both from my.telegram.org -> API Development Tools (no spaces)."}
    except errors.FloodWaitError as e:
        return {"error": f"Telegram rate limit — retry in {e.seconds}s."}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
