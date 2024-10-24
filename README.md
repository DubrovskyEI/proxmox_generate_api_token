## Proxmox API Token Management Script

This script is designed to connect to a Proxmox Virtual Environment (PVE) server and manage API tokens. It provides functionalities to authenticate, check whether an API token exists, and generate or remove tokens for users. This script is useful for automating tasks that require API authentication in Proxmox, such as in infrastructure automation with Ansible, GitLab CI etc.

## Requirements

- Python 3.x
- `requests` module (can be installed with `pip install requests`)

## Usage

### Command-line arguments

- `--host`: (required) The address of the Proxmox host.
- `--port`: (optional) The Proxmox port, default is `8006`.
- `--user`: (required) The Proxmox user to authenticate as.
- `--password`: (required) The password for the Proxmox user.
- `--tokenid`: (optional) A specific token ID for the user (default is `monitoring`).

### Example Usage

#### Generate new token

```Bash
python.exe proxmox_generate_api_token.py --host dev-proxmox.lan --user pve-exporter@pve --password mypassword --port 8006 --tokenid mytoken
```

This will connect to `dev-proxmox.lan` on port `8006`, authenticate as `pve-exporter@pve`, and generate an API token with the identifier `mytoken`.

Script output:

```
INFO: Проверяем наличие токена c tokenid 'monitoring' для пользователя 'pve-exporter@pve'.
INFO: Токен c tokenid 'monitoring' не найден.
INFO: Сгенерирован новый токен для пользователя 'pve-exporter@pve' с tokenid 'monitoring': '0ccd579a-6573-4105-a30a-59d52a89880b'
PVE_TOKEN_VALUE=0ccd579a-6573-4105-a30a-59d52a89880b
```

If a token with this identifier already exists, the script will exit without generating a new token and exit with code 0.

Script output:

```
INFO: Проверяем наличие токена c tokenid 'mytoken' для пользователя 'pve-exporter@pve'.
WARNING: Токен c tokenid 'mytoken' уже существует!
```

Feel free to use functions for your certain case.

### References

Proxmox Documentation:

- [Proxmox API Documentation](https://pve.proxmox.com/pve-docs/api-viewer/)
- [Proxmox User Management](https://pve.proxmox.com/wiki/User_Management#pveum_tokens)
- [Proxmox Ticket Cookie](https://pve.proxmox.com/wiki/Proxmox_VE_API#Example:_Get_a_New_Ticket_and_the_CSRF_Prevention_Token)

Inspired by:

- [Github proxmox_get_token](https://github.com/luftegrof/proxmox_get_token)
