from sympy import symbols, Poly
from sympy import GF

# Function to reconstruct the secret from k shares
def reconstruct_secret(shares):
    """
    Reconstruct the secret using Lagrange interpolation.
    
    :param shares: List of shares (x, y)
    :return: Reconstructed secret
    """
    x = symbols('x')
    secret = 0
    k = len(shares)
    
    # Lagrange Interpolation formula
    for i in range(k):
        xi, yi = shares[i]
        print('x and y', xi, yi)
        numerator = 1
        denominator = 1
        for j in range(k):
            if i != j:
                xj, _ = shares[j]
                numerator *= (x - xj)
                denominator *= (xi - xj)
        
        # Add contribution of current share to secret
        secret += yi * numerator / denominator
    
    # Now, evaluate the secret at x = 0 and convert to an integer
    secret_at_zero = secret.subs(x, 0)  # Substitute x = 0 in the expression
    return int(secret_at_zero)  # Return the integer value
