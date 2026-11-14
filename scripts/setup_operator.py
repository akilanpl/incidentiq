"""Run locally: .venv/bin/python -m scripts.setup_operator. No echoed passwords."""
from getpass import getpass
from pathlib import Path
import os
import secrets
from recurrence.auth import password_hash, LocalAuth


def main(root=None):
    root=Path(root) if root else Path(__file__).resolve().parent.parent
    path=root/'.env.auth'
    if path.exists() and input('Replace existing local operator configuration? [y/N] ').strip().lower()!='y':
        return
    username=input('Operator username: ').strip()
    password=getpass('Password (at least 12 characters): ')
    confirm=getpass('Confirm password: ')
    if not username or any(c in username for c in '\n\r\"\'') or len(password)<12 or password!=confirm:
        raise SystemExit('Invalid username, short password or confirmation mismatch. Nothing changed.')
    salt=secrets.token_hex(16)
    digest=password_hash(password,salt)
    users=LocalAuth(users_path=root/'data/users.json')
    users.accounts[username]={'salt':salt,'hash':digest,'role':'admin'}
    content='\n'.join(['INCIDENTIQ_AUTH_ENABLED=1','INCIDENTIQ_USERNAME='+username,
        'INCIDENTIQ_PASSWORD_SALT='+salt,'INCIDENTIQ_PASSWORD_HASH='+digest,
        'INCIDENTIQ_SESSION_SECRET='+secrets.token_hex(32),''])
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f:f.write(content)
    path.chmod(0o600)
    users._save_users()
    print('Local operator configured in .env.auth. API credentials in .env were not changed. Restart IncidentIQ.')


if __name__=='__main__':main()
