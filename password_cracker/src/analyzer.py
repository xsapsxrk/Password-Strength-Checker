import string
from math import pow, log10
from typing import Tuple

CHARSET_SIZES = {
    'lower': len(string.ascii_lowercase),
    'upper': len(string.ascii_uppercase),
    'digits': len(string.digits),
    'symbols': len(string.punctuation),
}

def detect_charset(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += CHARSET_SIZES['lower']
    if any(c.isupper() for c in password):
        size += CHARSET_SIZES['upper']
    if any(c.isdigit() for c in password):
        size += CHARSET_SIZES['digits']
    if any(c in string.punctuation for c in password):
        size += CHARSET_SIZES['symbols']
    return size or CHARSET_SIZES['lower']

def estimate_crack_time(password: str, guesses_per_second: float = 1e9) -> Tuple[float, str]:
    """
    Estimate time (in seconds) required to brute force the password given guesses_per_second.
    Returns (seconds, human_readable).
    guesses_per_second default: 1e9 (1 billion attempts/sec) - adjust for attacker capability.
    """
    charset_size = detect_charset(password)
    combinations = pow(charset_size, len(password))
    seconds = combinations / guesses_per_second

    return seconds, human_readable_time(seconds)

def human_readable_time(seconds: float) -> str:
    # produce a friendly string
    units = [
        ('years', 60 * 60 * 24 * 365),
        ('days', 60 * 60 * 24),
        ('hours', 60 * 60),
        ('minutes', 60),
        ('seconds', 1),
    ]
    if seconds <= 0:
        return '0 seconds'
    parts = []
    remainder = seconds
    for name, sec_per in units:
        if remainder >= sec_per:
            value = int(remainder // sec_per)
            parts.append(f'{value} {name}')
            remainder = remainder % sec_per
    return ', '.join(parts[:2])
