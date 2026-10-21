#!/usr/bin/env python3
"""One-time interactive Telegram login (async — Telethon >= 1.34 returns coroutines
for sync-style calls, so we use the async API explicitly).
Run from the project root AFTER setting TELEGRAM_API_ID / TELEGRAM_API_HASH in .env:
    python telegram_login.py
Enter your phone (intl format, e.g. +15551234567), the code Telegram sends you,
and your 2FA password if enabled. Creates osint_session.session, which the web
app then reuses for all Telegram OSINT lookups."""
import asyncio
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

api_id = os.getenv("TELEGRAM_API_ID")
api_hash = os.getenv("TELEGRAM_API_HASH")
if not (api_id and api_hash):
    raise SystemExit("Set TELEGRAM_API_ID and TELEGRAM_API_HASH in .env first "
                     "(https://my.telegram.org -> API Development Tools).")

if os.name == "nt":
    import sys
    if sys.version_info >= (3, 8):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from telethon import TelegramClient

async def main():
    client = TelegramClient(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "osint_session"), int(api_id), api_hash)
    await client.connect()
    if not await client.is_user_authorized():
        await client.start()      # interactive: phone -> code -> (2FA password)
    me = await client.get_me()
    print(f"Logged in as {me.first_name} (@{me.username or 'no-username'}) - session saved. "
          "You can now start the web app.")
    await client.disconnect()

asyncio.run(main())
