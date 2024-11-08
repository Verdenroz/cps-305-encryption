import hashlib
import random

# Diffie-Hellman parameters (in practice, use larger secure primes)
P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
        '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
        '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
        '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
        '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
        '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
G = 2


def generate_keypair():
    """Generate private and public keys for Diffie-Hellman."""
    private_key = random.randint(2, P - 2)
    public_key = pow(G, private_key, P)
    return private_key, public_key


def generate_shared_secret(private_key: int, other_public_key: int) -> bytes:
    """Generate shared secret and convert to 32-byte key."""
    shared_secret = pow(other_public_key, private_key, P)
    # Convert to fixed-length bytes using SHA-256
    print(f"Generated shared secret: {shared_secret}")
    return hashlib.sha256(str(shared_secret).encode()).digest()
