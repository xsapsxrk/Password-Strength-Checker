import itertools
import string
from typing import Optional
from tqdm import tqdm

def brute_force(target_hash: str, algo: str = 'sha256', max_len: int = 4, charset: str = None) -> Optional[str]:
    """
    Brute force generator that tries all combinations up to max_len.
    WARNING: combinatorics explode quickly. Keep max_len small for Python-based brute force.
    """
    import hashlib
    if charset is None:
        # default to lowercase + digits
        charset = string.ascii_lowercase + string.digits

    for length in range(1, max_len + 1):
        total = len(charset) ** length
        # tqdm over the product by grouping into an iterator
        it = itertools.product(charset, repeat=length)
        for combo in tqdm(it, total=total, desc=f'Brute force (len={length})'):
            candidate = ''.join(combo)
            h = getattr(hashlib, algo)(candidate.encode()).hexdigest()
            if h == target_hash:
                return candidate
    return None
