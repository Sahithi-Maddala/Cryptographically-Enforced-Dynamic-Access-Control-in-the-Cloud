# utils.py

def display_shares(shares):
    """
    Function to display the shares in a user-friendly format.
    
    :param shares: List of shares (x, y)
    """
    print("Shares:")
    for share in shares:
        print(f"Share: {share[0]} -> {share[1]}")

