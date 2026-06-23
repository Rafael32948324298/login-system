"""login.py - Simple terminal-based user management with strict password policy.

Features:
- Stores users in users.txt (one JSON object per line).
- Accepts manual additions in users.txt using the format shown in the header comment.
- Validates usernames against a blacklist (example racist/profane words).
- Checks for duplicates when registering.
- Strong password policy: min 12 chars, upper, lower, digit, special, no sequences, not in common list, not containing username.
- Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes.
- On first run the script creates a pre-registered admin/admin account (role: admin).
- Only admin can list all users or import/upgrade manual entries from users.txt.

This script is cross-platform and runs in a terminal (no GUI).
"""

import json
import os
import re
import sys
import getpass
import hashlib
import secrets
from typing import Dict, List

USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.txt')
PBKDF2_ITERATIONS = 100_000
MIN_PASSWORD_LENGTH = 12
COMMON_PASSWORDS = {
    'password', '123456', '12345678', 'qwerty', 'abc123', 'admin', 'letmein', 'welcome'
}
# Example blacklist - extend this list as needed.
USERNAME_BLACKLIST = {
    'slur1', 'slur2', 'racistword'
}


def hash_password(password: str, salt: str = None) -> Dict[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return {'salt': salt, 'hash': pwd_hash.hex(), 'algo': 'pbkdf2_sha256'}


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return computed.hex() == expected_hash


def load_users() -> List[Dict]:
    users = []
    if not os.path.exists(USERS_FILE):
        return users
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    # Try to parse JSON-per-line first
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # If line looks like JSON
        if line.startswith('{') and line.endswith('}'):
            try:
                users.append(json.loads(line))
                continue
            except json.JSONDecodeError:
                pass
        # Otherwise try to parse a manual block format: we support 3-line blocks separated by blank lines
    # Manual blocks parsing
    manual_blocks = []
    block = []
    for line in content.splitlines():
        if not line.strip():
            if block:
                manual_blocks.append(block)
                block = []
            continue
        if line.strip().startswith('#'):
            continue
        block.append(line.rstrip('\n'))
    if block:
        manual_blocks.append(block)
    for b in manual_blocks:
        # Accept blocks that contain at least username and senha lines
        username = None
        senha = None
        role = 'user'
        for l in b:
            if l.lower().startswith('username:'):
                username = l.split(':', 1)[1].strip()
            elif l.lower().startswith('senha:') or l.lower().startswith('password:'):
                senha = l.split(':', 1)[1].strip()
            elif 'admin' in l.lower():
                role = 'admin'
            elif 'user' in l.lower() or 'normal' in l.lower():
                role = 'user'
        if username and senha:
            # If manual password provided in plain text, we store hashed version for safety when saving back
            entry = {
                'username': username,
                'role': role,
                'raw_pass': senha  # marker that this was plaintext and needs hashing on save
            }
            users.append(entry)
    # Also keep previously saved JSON lines parsed earlier
    # Re-parse JSON-per-line and append (we did above) -> currently users contains only manual parsed entries; append JSON lines.
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('{') and line.endswith('}'):
            try:
                obj = json.loads(line)
                # ensure minimal keys
                if 'username' in obj and 'role' in obj and 'password_hash' in obj and 'salt' in obj:
                    users.append(obj)
            except json.JSONDecodeError:
                continue
    # Deduplicate by username keeping the first (manual blocks will be processed later by admin import)
    seen = set()
    deduped = []
    for u in users:
        uname = u.get('username')
        if uname and uname.lower() not in seen:
            seen.add(uname.lower())
            deduped.append(u)
    return deduped


def save_users(users: List[Dict]):
    # Save as JSON-per-line. If an entry has 'raw_pass', hash it during save.
    lines = []
    for u in users:
        entry = u.copy()
        if 'raw_pass' in entry:
            hashed = hash_password(entry.pop('raw_pass'))
            entry['password_hash'] = hashed['hash']
            entry['salt'] = hashed['salt']
            entry['algo'] = hashed['algo']
        # Remove any runtime-only fields
        for k in list(entry.keys()):
            if k.startswith('_'):
                entry.pop(k, None)
        lines.append(json.dumps(entry, ensure_ascii=False))
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        f.write('# users.txt - do not edit unless you know the manual format described in the project README\n')
        f.write('# Supported manual format example (blocks separated by a blank line):\n')
        f.write('# username: Rafael\n# senha: Senha@123!@#\n# {normal user}\n\n')
        for line in lines:
            f.write(line + '\n')


def find_user(users: List[Dict], username: str):
    for u in users:
        if u.get('username', '').lower() == username.lower():
            return u
    return None


def username_allowed(username: str) -> (bool, str):
    uname = username.strip()
    if len(uname) < 2:
        return False, 'Username must be at least 2 characters long.'
    if any(b in uname.lower() for b in USERNAME_BLACKLIST):
        return False, 'Username contains disallowed words.'
    if not re.match(r'^[A-Za-z0-9_\-\.]+$', uname):
        return False, 'Username contains invalid characters. Allowed: letters, numbers, underscore, hyphen, dot.'
    return True, ''


def password_policy(password: str, username: str) -> (bool, List[str]):
    errors = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f'Password must be at least {MIN_PASSWORD_LENGTH} characters long.')
    if username.lower() in password.lower():
        errors.append('Password must not contain the username.')
    if password.lower() in COMMON_PASSWORDS:
        errors.append('Password is too common.')
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter.')
    if not re.search(r'[0-9]', password):
        errors.append('Password must contain at least one digit.')
    if not re.search(r'[^A-Za-z0-9]', password):
        errors.append('Password must contain at least one special character.')
    # Reject simple sequences like 1234 or abcd
    sequences = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwerty']
    low = password.lower()
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i+4] in low:
                errors.append('Password contains a sequential substring (e.g. 1234 or abcd).')
                break
    return (len(errors) == 0), errors


def register_user(users: List[Dict]):
    print('\n=== Create account ===')
    username = input('Username: ').strip()
    ok, msg = username_allowed(username)
    if not ok:
        print('Username not allowed:', msg)
        return
    if find_user(users, username):
        print('A user with that username already exists.')
        return
    while True:
        password = getpass.getpass('Password: ')
        confirm = getpass.getpass('Confirm password: ')
        if password != confirm:
            print('Passwords do not match. Try again.')
            continue
        ok, errors = password_policy(password, username)
        if not ok:
            print('Password does not meet policy:')
            for e in errors:
                print(' -', e)
            continue
        break
    hashed = hash_password(password)
    users.append({
        'username': username,
        'password_hash': hashed['hash'],
        'salt': hashed['salt'],
        'algo': hashed['algo'],
        'role': 'user'
    })
    save_users(users)
    print('Account created successfully.')


def login(users: List[Dict]):
    print('\n=== Login ===')
    username = input('Username: ').strip()
    user = find_user(users, username)
    if not user:
        print('User not found.')
        return None
    # If user entry has raw_pass (manual plaintext), verify against it directly but then hash it
    password = getpass.getpass('Password: ')
    if 'raw_pass' in user:
        if password == user['raw_pass']:
            # convert to hashed form
            hashed = hash_password(password)
            user['password_hash'] = hashed['hash']
            user['salt'] = hashed['salt']
            user.pop('raw_pass', None)
            save_users(users)
            print('Password migrated to hashed storage.')
            return user
        else:
            print('Incorrect password.')
            return None
    if 'password_hash' not in user or 'salt' not in user:
        print('User record is malformed. Contact admin.')
        return None
    if verify_password(password, user['salt'], user['password_hash']):
        print(f'Login successful. Welcome, {user["username"]}!')
        return user
    print('Incorrect password.')
    return None


def admin_import_manual(users: List[Dict]):
    # Admin-only: scan users.txt manual blocks and import any entries that are not yet in JSON format.
    print('\nImporting manual users from users.txt (admin only)...')
    content = []
    if not os.path.exists(USERS_FILE):
        print('users.txt not found.')
        return
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    manual_blocks = []
    block = []
    for line in content.splitlines():
        if not line.strip():
            if block:
                manual_blocks.append(block)
                block = []
            continue
        if line.strip().startswith('#'):
            continue
        if line.strip().startswith('{') and line.strip().endswith('}'):
            continue
        block.append(line.rstrip('\n'))
    if block:
        manual_blocks.append(block)
    added = 0
    for b in manual_blocks:
        username = None
        senha = None
        role = 'user'
        for l in b:
            if l.lower().startswith('username:'):
                username = l.split(':', 1)[1].strip()
            elif l.lower().startswith('senha:') or l.lower().startswith('password:'):
                senha = l.split(':', 1)[1].strip()
            elif 'admin' in l.lower():
                role = 'admin'
            elif 'user' in l.lower() or 'normal' in l.lower():
                role = 'user'
        if username and senha and not find_user(users, username):
            users.append({
                'username': username,
                'raw_pass': senha,
                'role': role
            })
            added += 1
    if added:
        save_users(users)
        print(f'Imported {added} users and saved as hashed records.')
    else:
        print('No new manual users found to import.')


def ensure_admin_present(users: List[Dict]):
    admin = find_user(users, 'admin')
    if admin:
        return users
    # Create default admin/admin
    print('No admin account found. Creating default admin account with username "admin" and password "admin".')
    hashed = hash_password('admin')
    users.append({
        'username': 'admin',
        'password_hash': hashed['hash'],
        'salt': hashed['salt'],
        'algo': hashed['algo'],
        'role': 'admin'
    })
    save_users(users)
    return users


def list_users(users: List[Dict]):
    print('\n=== Registered users ===')
    for u in users:
        print(f" - {u.get('username')} (role: {u.get('role', 'user')})")


def change_password(users: List[Dict], current_user: Dict):
    print('\n=== Change password ===')
    old = getpass.getpass('Old password: ')
    if 'raw_pass' in current_user:
        if old != current_user['raw_pass']:
            print('Incorrect old password.')
            return
    else:
        if not verify_password(old, current_user['salt'], current_user['password_hash']):
            print('Incorrect old password.')
            return
    while True:
        new = getpass.getpass('New password: ')
        conf = getpass.getpass('Confirm new password: ')
        if new != conf:
            print('Passwords do not match. Try again.')
            continue
        ok, errs = password_policy(new, current_user['username'])
        if not ok:
            print('Password policy violations:')
            for e in errs:
                print(' -', e)
            continue
        break
    hashed = hash_password(new)
    current_user['password_hash'] = hashed['hash']
    current_user['salt'] = hashed['salt']
    current_user.pop('raw_pass', None)
    save_users(users)
    print('Password changed successfully.')


def main_menu():
    users = load_users()
    users = ensure_admin_present(users)
    while True:
        print('\n=== Main menu ===')
        print('1) Create account')
        print('2) Login')
        print('3) Exit')
        choice = input('Select: ').strip()
        if choice == '1':
            register_user(users)
        elif choice == '2':
            user = login(users)
            if user:
                if user.get('role') == 'admin':
                    admin_menu(users, user)
                else:
                    user_menu(users, user)
        elif choice == '3':
            print('Goodbye')
            sys.exit(0)
        else:
            print('Invalid option.')


def admin_menu(users: List[Dict], current_user: Dict):
    while True:
        print('\n=== Admin menu ===')
        print('1) List users')
        print('2) Import manual users from users.txt (and hash their passwords)')
        print('3) Change my password')
        print('4) Logout')
        choice = input('Select: ').strip()
        if choice == '1':
            list_users(users)
        elif choice == '2':
            admin_import_manual(users)
        elif choice == '3':
            change_password(users, current_user)
        elif choice == '4':
            print('Logging out...')
            break
        else:
            print('Invalid option.')


def user_menu(users: List[Dict], current_user: Dict):
    while True:
        print('\n=== User menu ===')
        print('1) Change password')
        print('2) Logout')
        choice = input('Select: ').strip()
        if choice == '1':
            change_password(users, current_user)
        elif choice == '2':
            print('Logging out...')
            break
        else:
            print('Invalid option.')


if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        print('\nInterrupted. Bye.')
        sys.exit(0)
