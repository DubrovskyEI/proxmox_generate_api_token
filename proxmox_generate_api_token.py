#!/usr/bin/env python3

import sys
import argparse
import urllib3

import requests

# Disable warnings InsecureRequestWarning to avoid spamming in stdout
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for Proxmox API token management."""

    parser = argparse.ArgumentParser(description="Proxmox API token management.")
    parser.add_argument("--host", required=True, help="Proxmox host address")
    parser.add_argument(
        "--port", required=False, default="8006", help="Proxmox port (default: 8006)"
    )
    parser.add_argument("--user", required=True, help="Proxmox user")
    parser.add_argument("--password", required=True, help="Proxmox password")
    parser.add_argument(
        "--tokenid",
        required=False,
        default="monitoring",
        help="Proxmox user-specific token identifier.",
    )
    return parser.parse_args()


def get_ticket_cookie(
    pm_host: "str", pm_port: "str", pm_user: "str", pm_pass: "str"
) -> tuple[str, str]:
    """Return authentication ticket and CSRF Prevention Token for pm_user.

    Method: POST
    Create and return a New Authentication Ticket and the CSRF Prevention Token for a specific user
    For authentication need to pass valid credentials

    :rtype: tuple[str, str]
    :return: (pve_auth_cookie, pve_csrf_token)

    References:
    https://pve.proxmox.com/pve-docs/api-viewer/#/access/ticket
    https://pve.proxmox.com/wiki/Proxmox_VE_API#Example:_Get_a_New_Ticket_and_the_CSRF_Prevention_Token

    """
    url = f"https://{pm_host}:{pm_port}/api2/json/access/ticket"

    data = {"username": pm_user, "password": pm_pass}

    try:
        response = requests.post(url, data, verify=False, timeout=5)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error occurred: {e}")
    else:
        pm_auth_cookie = response.json()["data"]["ticket"]
        pm_csrf_token = response.json()["data"]["CSRFPreventionToken"]

        return pm_auth_cookie, pm_csrf_token


def generate_api_token(
    pm_host: "str",
    pm_port: "str",
    pm_user: "str",
    pm_csrf_token: "str",
    pm_auth_cookie: "str",
    tokenid: "str",
) -> str:
    """Generate and return new API token for pm_user with tokenid.

    Method: POST
    Generate and return new API token value used for authentication without expiration date
    and with full privileges of corresponding user

    :rtype: str
    :return: pve_token_value

    References:
    https://pve.proxmox.com/pve-docs/api-viewer/#/access/users/{userid}/token/{tokenid}

    """
    url = (
        f"https://{pm_host}:{pm_port}/api2/json/access/users/{pm_user}/token/{tokenid}"
    )
    headers = create_auth_headers(pm_csrf_token, pm_auth_cookie)

    data = {"expire": 0, "privsep": 0}

    try:
        response = requests.post(
            url, headers=headers, data=data, verify=False, timeout=5
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error occurred: {e}")
        # Try to get 'errors' field from proxmox JSON response
        errors = response.json().get(
            "errors", "В ответе от proxmox поле 'errors' отсутствует."
        )
        print(f"ERROR: {errors}")
        raise
    else:
        pm_token_value = response.json()["data"]["value"]
        print(
            f"INFO: Сгенерирован новый токен для пользователя '{pm_user}' с "
            f"tokenid '{tokenid}': '{pm_token_value}'"
        )
        # Print token_value for ansible parsing in task 'Set token_value as variable'
        print(f"PVE_TOKEN_VALUE={pm_token_value}")

        return pm_token_value


def is_token_exists(
    pm_host: "str",
    pm_port: "str",
    pm_user: "str",
    pm_csrf_token: "str",
    pm_auth_cookie: "str",
    tokenid: "str",
) -> bool:
    """Check that token with certain tokenid exists for pm_user.

    Method: GET
    Get list of pm_user's API tokens and check that token with certain tokenid exists

    :rtype: bool
    :return: pve_token_exist_flag

    References:
    https://pve.proxmox.com/pve-docs/api-viewer/#/access/users/{userid}/token

    """
    url = f"https://{pm_host}:{pm_port}/api2/json/access/users/{pm_user}/token"
    headers = create_auth_headers(pm_csrf_token, pm_auth_cookie)

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=5)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error occurred: {e}")
        # Try to get 'errors' field from proxmox JSON response
        errors = response.json().get(
            "errors", "В ответе от proxmox поле 'errors' отсутствует."
        )
        print(f"ERROR: {errors}")
        raise
    else:
        print(
            f"INFO: Проверяем наличие токена c tokenid '{tokenid}' "
            f"для пользователя '{pm_user}'."
        )
        # Define list of tokens for pm_user
        pm_tokens_list = response.json()["data"]
        # Check if there is a token with tokenid in pm_tokens_list
        pm_token_is_exists = any(
            pm_token["tokenid"] == f"{tokenid}" for pm_token in pm_tokens_list
        )

        if pm_token_is_exists:
            print(f"WARNING: Токен c tokenid '{tokenid}' уже существует!")
            return True
        else:
            print(f"INFO: Токен c tokenid '{tokenid}' не найден.")
            return False


def remove_api_token(
    pm_host: "str",
    pm_port: "str",
    pm_user: "str",
    pm_csrf_token: "str",
    pm_auth_cookie: "str",
    tokenid: "str",
) -> None:
    """Remove API token for pm_user with certain tokenid.

    Method: DELETE

    :return: None

    References:
    https://pve.proxmox.com/pve-docs/api-viewer/#/access/users/{userid}/token/{tokenid}

    """
    url = (
        f"https://{pm_host}:{pm_port}/api2/json/access/users/{pm_user}/token/{tokenid}"
    )
    headers = create_auth_headers(pm_csrf_token, pm_auth_cookie)

    try:
        response = requests.delete(url, headers=headers, verify=False, timeout=5)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error occurred: {e}")
        # Try to get 'errors' field from proxmox JSON response
        errors = response.json().get(
            "errors", "В ответе от proxmox поле 'errors' отсутствует."
        )
        print(f"ERROR: {errors}")
        raise
    else:
        print(f"INFO: Токен с tokenid '{tokenid}' успешно удален.")


def create_auth_headers(csrf_token: "str", auth_cookie: "str") -> dict[str, str]:
    """Return dict with Cookie HTTP request header for proxmox authentication.

    :rtype: dict[str, str]
    :return: headers for requests

    """
    return {"CSRFPreventionToken": csrf_token, "Cookie": f"PVEAuthCookie={auth_cookie}"}


if __name__ == "__main__":
    # Set variables from command line arguments
    args = parse_arguments()
    pve_host = args.host
    pve_port = args.port
    pve_user = args.user
    pve_pass = args.password
    token_name = args.tokenid

    # Get HTTP authentication cookies
    pve_auth_cookie, pve_csrf_token = get_ticket_cookie(
        pve_host, pve_port, pve_user, pve_pass
    )

    # Verify whether the API token already exists
    # If the token exists, print a warning in function and exit with code 0
    # Code 0 signals success, so Ansible will continue executing the playbook
    # If the token does not exist, create a new API token
    if is_token_exists(
        pve_host, pve_port, pve_user, pve_csrf_token, pve_auth_cookie, token_name
    ):
        sys.exit(0)
    else:
        pve_token_value = generate_api_token(
            pve_host, pve_port, pve_user, pve_csrf_token, pve_auth_cookie, token_name
        )
