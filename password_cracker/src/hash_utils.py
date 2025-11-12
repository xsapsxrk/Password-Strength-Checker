import hashlib
from typing import Literal

try:
    import bcrypt
    _bcrypt_available = True
except Exception:
    bcrypt = None
    _bcrypt_available = False

HashAlgo = Literal['md5', 'sha1', 'sha256', 'bcrypt']

def hash_password(password: str, algo: HashAlgo = 'sha256') -> str:
    """Return the hashed password as a hex (or bcrypt encoded) string."""
    if algo == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    if algo == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    if algo == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    if algo == 'bcrypt':
        if not _bcrypt_available:
            raise RuntimeError('bcrypt library is not installed')
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    raise ValueError(f'Unsupported algorithm: {algo}')

def verify_password(password: str, hashed: str, algo: HashAlgo = 'sha256') -> bool:
    """Verify a password against a stored hash."""
    if algo == 'bcrypt':
        if not _bcrypt_available:
            raise RuntimeError('bcrypt library is not installed')
        return bcrypt.checkpw(password.encode(), hashed.encode())
    return hash_password(password, algo) == hashed
