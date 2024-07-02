import json
import logging
import os
from typing import Tuple

import requests

logging.basicConfig(level=logging.INFO)


# Global Variables
n = None  # To shorten line lengths
TL_URL = os.environ.get("TL_URL")


def getScans(token: str) -> Tuple[int, str]:
    scanURL = TL_URL + "/api/v1/scans" if TL_URL is not None else exit(1)
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    response = requests.get(scanURL, headers=headers, timeout=60, verify=False)
    return (response.status_code, response.text)


def generateCwpToken(accessKey: str, accessSecret: str) -> Tuple[int, str]:
    authURL = f"{TL_URL}/api/v1/authenticate" if TL_URL is not n else exit(1)

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": accessKey, "password": accessSecret}
    response = requests.post(
        authURL, headers=headers, json=body, timeout=60, verify=False
    )

    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data["token"]
    else:
        logging.error(
            "Unable to acquire token with error code: %s", response.status_code
        )

    return response.status_code, ""


def check_param(param_name: str) -> str:
    param_value = os.environ.get(param_name)
    if param_value is None:
        logging.error(f"Missing {param_name}")
        raise ValueError(f"Missing {param_name}")
    return param_value


def main():
    P: Tuple[str, str, str] = ("PC_IDENTITY", "PC_SECRET", "TL_URL")
    accessKey, accessSecret, _ = map(check_param, P)
    responseCode, cwpToken = (
        generateCwpToken(accessKey, accessSecret)
        if accessKey and accessSecret
        else (None, None)
    )

    responseCode, content = getScans(cwpToken) if cwpToken else (exit(1))
    logging.info(responseCode)
    logging.info(content)


if __name__ == "__main__":
    main()
