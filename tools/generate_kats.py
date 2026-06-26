"""Known-Answer Test (KAT) vector generator for password_hashing.rs.

Produces JSON-encoded hash strings by calling the real (non-Passlib) Keystone
Python hasher classes, applying the same pre-dispatch truncation policy that
Rust's verify_length_and_trunc_password() implements. Output is hand-copied
into Rust #[tokio::test] KAT cases in crates/core/src/common/password_hashing.rs.

Must be run from a real Keystone Python checkout so the imports resolve:
    cd ~/Projects/openstack/keystone
    python tools/generate_kats.py

Do NOT use Passlib for generation — Keystone has not used Passlib for over a
year and the wire formats differ.
"""

import json
import sys

# 1. Initialize Oslo Config BEFORE importing Keystone modules
from oslo_config import cfg
CONF = cfg.CONF

# Register the exact options Keystone's password hashers look for
identity_opts = [
    cfg.StrOpt('password_hashing_algorithm', default='bcrypt'),
    cfg.IntOpt('password_hash_rounds', default=12),
]
CONF.register_opts(identity_opts, group='identity')

# 2. Now import the native Keystone hashers safely
from keystone.common.password_hashers import bcrypt as bcrypt_mod
from keystone.common.password_hashers import pbkdf2 as pbkdf2_mod
from keystone.common.password_hashers import scrypt as scrypt_mod

# Mirrors Rust's verify_length_and_trunc_password() in password_hashing.rs.
# Must be applied to every password before hashing so the vectors match what
# real hash_password() persists. The 72-byte and 73-byte boundary cases are
# the critical ones: Bcrypt truncates there, all other algorithms do not.
BCRYPT_MAX_LENGTH = 72

def truncate(pwd: bytes, alg_name: str, max_password_length: int = 4096) -> bytes:
    max_length = (
        BCRYPT_MAX_LENGTH
        if alg_name == "Bcrypt" and max_password_length > BCRYPT_MAX_LENGTH
        else max_password_length
    )
    return pwd[:max_length] if len(pwd) > max_length else pwd


def generate():
    pwd = b"openstack123"

    # Map algorithm names to the exact hasher classes the maintainer provided.
    hashers = {
        "Bcrypt": bcrypt_mod.Bcrypt,
        "BcryptSha256": bcrypt_mod.Bcrypt_sha256,
        "Pbkdf2Sha512": pbkdf2_mod.Sha512,
        "Scrypt": scrypt_mod.Scrypt,
    }

    results = {}
    for name, hasher_cls in hashers.items():
        try:
            # Apply the same truncation Rust applies before dispatch.
            truncated = truncate(pwd, name)
            results[name] = hasher_cls.hash(truncated)
        except Exception as e:
            print(f"Error executing {name}: {e}", file=sys.stderr)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    generate()
