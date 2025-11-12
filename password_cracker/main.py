"""Main CLI. Copy this file to the project root and run: python main.py"""

import argparse
import os
from src.hash_utils import hash_password, verify_password
from src.dictionary_attack import dictionary_attack
from src.brute_force import brute_force
from src.analyzer import estimate_crack_time
from src.visualize import plot_password_strength, plot_cracked_distribution

def run_hash(args):
    h = hash_password(args.password, algo=args.algo)
    print(f'Hashed ({args.algo}): {h}')

def run_verify(args):
    ok = verify_password(args.password, args.hash, algo=args.algo)
    print('MATCH' if ok else 'NO MATCH')

def run_dict(args):
    result = dictionary_attack(args.hash, args.wordlist, algo=args.algo, max_attempts=args.max_attempts)
    if result:
        print(f'Found password: {result}')
    else:
        print('Not found')

def run_bruteforce(args):
    result = brute_force(args.hash, algo=args.algo, max_len=args.max_len, charset=args.charset)
    if result:
        print(f'Found password: {result}')
    else:
        print('Not found')

def run_analyze(args):
    seconds, human = estimate_crack_time(args.password, guesses_per_second=args.gps)
    print(f'Estimated crack time: {human} ({seconds:.2e} seconds)')

def main():
    parser = argparse.ArgumentParser(description='Password Cracking & Analysis Suite')
    subparsers = parser.add_subparsers(dest='cmd')

    p_hash = subparsers.add_parser('hash')
    p_hash.add_argument('--password', required=True)
    p_hash.add_argument('--algo', default='sha256')
    p_hash.set_defaults(func=run_hash)

    p_verify = subparsers.add_parser('verify')
    p_verify.add_argument('--password', required=True)
    p_verify.add_argument('--hash', required=True)
    p_verify.add_argument('--algo', default='sha256')
    p_verify.set_defaults(func=run_verify)

    p_dict = subparsers.add_parser('dict')
    p_dict.add_argument('--hash', required=True)
    p_dict.add_argument('--wordlist', required=True)
    p_dict.add_argument('--algo', default='sha256')
    p_dict.add_argument('--max-attempts', type=int, default=None)
    p_dict.set_defaults(func=run_dict)

    p_bf = subparsers.add_parser('brute')
    p_bf.add_argument('--hash', required=True)
    p_bf.add_argument('--algo', default='sha256')
    p_bf.add_argument('--max-len', type=int, default=4)
    p_bf.add_argument('--charset', default=None)
    p_bf.set_defaults(func=run_bruteforce)

    p_an = subparsers.add_parser('analyze')
    p_an.add_argument('--password', required=True)
    p_an.add_argument('--gps', type=float, default=1e9, help='guesses per second (attacker)')
    p_an.set_defaults(func=run_analyze)

    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
        return
    args.func(args)


if __name__ == '__main__':
    main()
