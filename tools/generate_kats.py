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

def generate():
    pwd = b"openstack123"
    
    # Map the exact classes the maintainer provided
    hashers = {
        "Bcrypt": bcrypt_mod.Bcrypt,
        "BcryptSha256": bcrypt_mod.Bcrypt_sha256,
        "Pbkdf2Sha512": pbkdf2_mod.Sha512,
        "Scrypt": scrypt_mod.Scrypt,
    }
    
    results = {}
    for name, hasher_cls in hashers.items():
        try:
            # Generate the hash using native Keystone logic
            results[name] = hasher_cls.hash(pwd)
        except Exception as e:
            print(f"Error executing {name}: {e}", file=sys.stderr)
            
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    generate()