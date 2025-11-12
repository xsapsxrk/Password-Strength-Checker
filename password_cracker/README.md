Password Cracking & Analysis Suite

Project structure (copy files into a directory called `password_cracker/`):

password_cracker/
│── data/
│   └── rockyou.txt         # (not included) wordlist - download separately
│── hashes/
│   └── hashes.txt          # sample hashed passwords
│── src/
│   ├── hash_utils.py       # Hashing and verification
│   ├── dictionary_attack.py# Dictionary-based attack
│   ├── brute_force.py      # Brute force engine (bounded lengths)
│   ├── analyzer.py         # Strength & time-to-crack estimation
│   ├── visualize.py        # Graphs & reporting
│── main.py                 # Main CLI entry

Notes:
- Install dependencies: pip install bcrypt tqdm matplotlib.
