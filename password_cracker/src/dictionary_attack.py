import os
from typing import Optional, List, Tuple
from hashlib import md5, sha1, sha256
from tqdm import tqdm
from .hash_utils import hash_password

HASH_ALGOS = {
    'md5': md5,
    'sha1': sha1,
    'sha256': sha256,
}

def _hash_with_algo(word: str, algo: str) -> str:
    if algo == 'bcrypt':
        # bcrypt handled in hash_utils when verifying
        raise ValueError('bcrypt hashing not supported here for pre-computed comparison')
    h = HASH_ALGOS[algo]()
    h.update(word.encode())
    return h.hexdigest()

def dictionary_attack(target_hash: str, wordlist_path: str, algo: str = 'sha256', max_attempts: Optional[int] = None) -> Optional[str]:
    """
    Try to find the password that matches target_hash by hashing words from wordlist_path.
    Returns the plaintext if found, else None.
    """
    if algo not in HASH_ALGOS and algo != 'bcrypt':
        raise ValueError('Unsupported algorithm')

    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f'Wordlist not found: {wordlist_path}')

    attempts = 0
    with open(wordlist_path, 'r', errors='ignore') as f:
        for line in tqdm(f, desc='Dictionary attack'):
            word = line.strip()
            if not word:
                continue
            attempts += 1
            if max_attempts and attempts > max_attempts:
                break
            if algo == 'bcrypt':
                # bcrypt we must use bcrypt.compare directly
                try:
                    import bcrypt
                    if bcrypt.checkpw(word.encode(), target_hash.encode()):
                        return word
                except Exception:
                    continue
            else:
                if _hash_with_algo(word, algo) == target_hash:
                    return word
    return None
