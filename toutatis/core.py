#!/usr/bin/env python3
"""
Simplified Toutatis core:
– Grabs Instagram sessionid interactively (no CLI arg needed)
– Then performs the usual profile lookup logic
ty for reworking my code by using my edited version of https://github.com/starstrucked/Instagram-Session-ID-Grabber/blob/main/Session-ID-Grabber.py gpt o3 ilysm
oh and credits to starstrucked for making the session id grabber
"""

import argparse
import getpass
from json import dumps, decoder
from uuid import uuid4
from urllib.parse import quote_plus

import phonenumbers
import pycountry
import requests
from phonenumbers.phonenumberutil import region_code_for_country_code

# ───────────────────────── Session helper ──────────────────────────
def fetch_session_id() -> str | None:
    """Interactive login to obtain a valid Instagram sessionid cookie."""
    print("[*] Instagram Login (credentials are NOT stored)\n")
    user = input("[+] Username: ")
    pwd = getpass.getpass("[+] Password: ")

    s = requests.Session()
    s.headers.update({
        "Host": "i.instagram.com",
        "X-Ig-Connection-Type": "WIFI",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Ig-Capabilities": "36r/Fx8=",
        "User-Agent": ("Instagram 159.0.0.28.123 "
                       "(iPhone8,1; iOS 14_1; en_US; scale=2.00) "
                       "AppleWebKit/420+"),
        "Accept-Encoding": "gzip, deflate",
    })

    payload = {
        "username": user,
        "enc_password": f"#PWD_INSTAGRAM:0:&:{pwd}",
        "device_id": str(uuid4()),
        "phone_id": str(uuid4()),
        "login_attempt_count": "0",
        "reg_login": "0",
    }

    resp = s.post("https://i.instagram.com/api/v1/accounts/login/", data=payload)
    if "logged_in_user" not in resp.text:
        print("[!] Login failed – check credentials or 2FA.\n")
        return None

    print("[+] Login success.\n")
    return resp.cookies.get("sessionid")

# ────────────────────── Existing helper functions ───────────────────
def getUserId(username, sessionId):
    headers = {"User-Agent": "iphone_ua", "x-ig-app-id": "936619743392459"}
    api = requests.get(
        f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
        headers=headers,
        cookies={"sessionid": sessionId},
    )
    try:
        if api.status_code == 404:
            return {"id": None, "error": "User not found"}
        uid = api.json()["data"]["user"]["id"]
        return {"id": uid, "error": None}
    except decoder.JSONDecodeError:
        return {"id": None, "error": "Rate limit"}

def getInfo(search, sessionId, searchType="username"):
    if searchType == "username":
        data = getUserId(search, sessionId)
        if data["error"]:
            return data
        userId = data["id"]
    else:
        try:
            userId = str(int(search))
        except ValueError:
            return {"user": None, "error": "Invalid ID"}

    try:
        resp = requests.get(
            f"https://i.instagram.com/api/v1/users/{userId}/info/",
            headers={"User-Agent": "Instagram 64.0.0.14.96"},
            cookies={"sessionid": sessionId},
        )
        if resp.status_code == 429:
            return {"user": None, "error": "Rate limit"}
        resp.raise_for_status()
        user = resp.json().get("user")
        if not user:
            return {"user": None, "error": "Not found"}
        user["userID"] = userId
        return {"user": user, "error": None}
    except requests.exceptions.RequestException:
        return {"user": None, "error": "Not found"}

def advanced_lookup(username):
    data = "signed_body=SIGNATURE." + quote_plus(
        dumps({"q": username, "skip_recovery": "1"}, separators=(",", ":"))
    )
    api = requests.post(
        "https://i.instagram.com/api/v1/users/lookup/",
        headers={
            "Accept-Language": "en-US",
            "User-Agent": "Instagram 101.0.0.15.120",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-IG-App-ID": "124024574287414",
            "Accept-Encoding": "gzip, deflate",
            "Host": "i.instagram.com",
            "Connection": "keep-alive",
            "Content-Length": str(len(data)),
        },
        data=data,
    )
    try:
        return {"user": api.json(), "error": None}
    except decoder.JSONDecodeError:
        return {"user": None, "error": "Rate limit"}

# ────────────────────────────── main ────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Toutatis – Instagram OSINT utility (now auto-handles sessionid)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--username", help="Target username")
    group.add_argument("-i", "--id", help="Target numeric ID")
    args = parser.parse_args()

    # grab session cookie
    sessionId = fetch_session_id()
    if not sessionId:
        exit(1)

    search_type = "id" if args.id else "username"
    search_val = args.id or args.username
    infos = getInfo(search_val, sessionId, searchType=search_type)
    if not infos.get("user"):
        exit(infos["error"])

    user = infos["user"]

    print("─" * 50)
    print(f"Informations about     : {user['username']}")
    print(f"userID                 : {user['userID']}")
    print(f"Full Name              : {user['full_name']}")
    print(
        f"Verified               : {user['is_verified']} | "
        f"Business Account : {user['is_business']}"
    )
    print(f"Private Account        : {user['is_private']}")
    print(
        f"Followers              : {user['follower_count']} | "
        f"Following : {user['following_count']}"
    )
    print(f"Number of posts        : {user['media_count']}")
    if user["external_url"]:
        print(f"External url           : {user['external_url']}")
    print(
        "Biography              : "
        + ("\n" + " " * 25).join(user["biography"].split("\n"))
    )
    print(f"Linked WhatsApp        : {user['is_whatsapp_linked']}")
    print(f"Memorial Account       : {user['is_memorialized']}")
    print(f"New Instagram user     : {user['is_new_to_instagram']}")

    if user.get("public_email"):
        print(f"Public Email           : {user['public_email']}")

    if user.get("public_phone_number"):
        phonenr = f"+{user['public_phone_country_code']} {user['public_phone_number']}"
        try:
            pn = phonenumbers.parse(phonenr)
            country = pycountry.countries.get(
                alpha_2=region_code_for_country_code(pn.country_code)
            )
            phonenr += f" ({country.name})"
        except Exception:
            pass
        print(f"Public Phone number    : {phonenr}")

    other = advanced_lookup(user["username"])
    if other["error"] == "Rate limit":
        print("Rate limit – try again later.")
    elif other["user"].get("message") == "No users found":
        print("Lookup did not work on this account.")
    else:
        if other["user"].get("obfuscated_email"):
            print(f"Obfuscated email       : {other['user']['obfuscated_email']}")
        else:
            print("No obfuscated email found")

        if other["user"].get("obfuscated_phone"):
            print(f"Obfuscated phone       : {other['user']['obfuscated_phone']}")
        else:
            print("No obfuscated phone found")

    print("─" * 50)
    print(f"Profile Picture        : {user['hd_profile_pic_url_info']['url']}")

if __name__ == "__main__":
    main()
