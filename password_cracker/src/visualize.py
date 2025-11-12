import matplotlib.pyplot as plt
from typing import List, Tuple
from .analyzer import estimate_crack_time

def plot_password_strength(passwords: List[str], guesses_per_second: float = 1e9) -> None:
    """Plot password length vs estimated crack time (log scale)."""
    lengths = [len(p) for p in passwords]
    times = [estimate_crack_time(p, guesses_per_second)[0] for p in passwords]

    plt.figure()
    plt.scatter(lengths, times)
    plt.yscale('log')
    plt.xlabel('Password length')
    plt.ylabel('Estimated crack time (seconds, log scale)')
    plt.title('Password length vs estimated crack time')
    plt.grid(True)
    plt.show()

def plot_cracked_distribution(cracked: List[str], uncracked_count: int) -> None:
    labels = ['Cracked', 'Uncracked']
    sizes = [len(cracked), uncracked_count]
    plt.figure()
    plt.pie(sizes, labels=labels, autopct='%1.1f%%')
    plt.title('Cracked vs Uncracked')
    plt.show()
