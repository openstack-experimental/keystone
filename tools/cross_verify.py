"""Verify a Rust-produced hash against the real (non-Passlib) Keystone hasher
classes.

Usage:
    cross_verify.py <algo> <password> <hash>

Exit codes:
    0 — verified
    1 — rejected (hash is structurally valid but password does not match)
    2 — error (unknown algorithm, malformed hash, import failure, etc.)

Run from a real Keystone Python checkout so the imports resolve:
    cd ~/Projects/openstack/keystone
    python tools/cross_verify.py bcrypt "openstack123" "<rust-hash>"

Algorithms: bcrypt, bcrypt_sha256, scrypt, pbkdf2_sha512
"""

import os
import sys

# When invoked as `python /abs/path/cross_verify.py`, Python sets sys.path[0]
# to the script's directory, not the working directory. Insert cwd explicitly
# so that `import keystone` finds the checkout the caller placed us in via
# current_dir (or by cd-ing before running the script directly).
sys.path.insert(0, os.getcwd())


def main() -> int:
    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.argv[0]} <algo> <password> <hash>",
            file=sys.stderr,
        )
        return 2

    algo, password, hashed = sys.argv[1], sys.argv[2].encode("utf-8"), sys.argv[3]

    # Import after arg-check so usage errors surface before slow Keystone imports.
    try:
        from keystone.common.password_hashers import bcrypt, pbkdf2, scrypt
    except ImportError as exc:
        print(
            f"Import failed — run from a real Keystone checkout: {exc}",
            file=sys.stderr,
        )
        return 2

    hashers = {
        "bcrypt": bcrypt.Bcrypt,
        "bcrypt_sha256": bcrypt.Bcrypt_sha256,
        "scrypt": scrypt.Scrypt,
        "pbkdf2_sha512": pbkdf2.Sha512,
    }

    hasher = hashers.get(algo)
    if hasher is None:
        print(f"Unknown algorithm: {algo!r}. Known: {list(hashers)}", file=sys.stderr)
        return 2

    try:
        return 0 if hasher.verify(password, hashed) else 1
    except Exception as exc:
        # Surfaces real Keystone's own error behaviour for malformed hashes.
        print(f"verify raised: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
