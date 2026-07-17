# secret_sharing.py

import random
from sympy import symbols, Poly
from sympy import GF

# Function to generate the shares
def generate_shares(secret, n, k):
    """
    Generate n shares with a threshold of k to reconstruct the secret.
    
    :param secret: The secret to share
    :param n: Total number of shares
    :param k: Minimum number of shares required to reconstruct the secret
    :return: List of shares
    """
    # Generate random coefficients for the polynomial
    coefficients = [secret] + [random.randint(0, 100) for _ in range(k-1)]
    
    # Define the polynomial
    x = symbols('x')
    polynomial = sum(c * x**i for i, c in enumerate(coefficients))
    
    # Calculate n shares
    shares = []
    for i in range(1, n+1):
        y = polynomial.subs(x, i)
        shares.append((i, y))  # Store share as (x, y)    
    return shares

