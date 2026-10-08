"""Create independent persistent deployment secrets; never print their values."""
import argparse
import os
import secrets
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', default='secrets')
    parser.add_argument('--no-dashboard-password', action='store_true',
                        help='Tạo dashboard không yêu cầu đăng nhập; giữ nguyên file đã tồn tại.')
    args = parser.parse_args()
    directory = Path(args.directory).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == 'posix': directory.chmod(0o700)
    for name in ('admin_password', 'secret_key', 'service_token'):
        path = directory / name
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        except FileExistsError:
            print(f'Kept existing {path}')
            continue
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(('' if name == 'admin_password' and args.no_dashboard_password
                          else secrets.token_urlsafe(48)) + '\n')
        # Compose file-backed secrets retain host mode; non-root dashboard needs read.
        # The parent directory remains owner-only on the host.
        if os.name == 'posix': path.chmod(0o444)
        print(f'Created {path}')


if __name__ == '__main__': main()
