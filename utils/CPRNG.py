import secrets
import hashlib

class Shake256PRNG:
    """
    A class implementing a cryptographically secure pseudo-random number generator (PRNG)
    using the SHAKE-256 hash function from the hashlib library. This PRNG allows for
    generating random bytes and random integers within a specified range. The internal
    state of the PRNG can be saved and restored.
    """
    def __init__(self, seed:bytes=None,debug:bool=False):
        if seed is None:
            seed = secrets.token_bytes(32)  # Generate a random seed if none is provided
        self.state = seed
        self.debug = debug
    
    def iterate(self,n:int=1):
        """iterate to update the state"""
        for i in range(n):self.state = hashlib.shake_256(self.state).digest(32)

    def randbytes(self, n=32):
        """
        Generate n random bytes (default is 32 bytes).
        """
        if n <= 0:
            raise ValueError("n must be a positive integer")
        randbytes = b""
        while len(randbytes) < n:
            randbytes += hashlib.shake_256(self.state).digest(32)
            self.iterate()
        return randbytes[:n]

    def randint(self, a:int, b:int) -> int:
        """
        Generate a random integer n such that a <= n <= b.
        """
        if a > b:
            raise ValueError("a must be less than or equal to b")
        range_size = b - a
        if range_size == 0:
            return a
        randbytes = self.randbytes(32)
        rand_int = int.from_bytes(randbytes, "big")
        return a + rand_int % (range_size + 1)
    
    def get_state(self):
        """Return the current state of the PRNG."""
        return self.state
    
    def set_state(self, state:bytes):
        """Reset the state of the PRNG to a specific state."""
        self.state = state
        # self.shaker = hashlib.shake_256()  # Reset the shaker
        # self.shaker.update(self.state)  # Update with the new state
        # if self.debug:print(f"changed state {self.state.hex()}")

    def shuffle(self, lst:list):
        """Shuffle a list randomly"""
        for i in range(len(lst)-1, 0, -1):
            j = self.randint(0, i)
            lst[i], lst[j] = lst[j], lst[i]

    def ascii(self, n:int) -> str:
        """Generate a random ASCII string of length n"""
        return self.randbytes(n).decode("ascii")

if __name__ == "__main__":
    # Example usage
    seed = secrets.token_hex(10000).encode("utf-8")
    cprng1 = Shake256PRNG(seed,debug=True)
    cprng2 = Shake256PRNG(seed,debug=True)
    for i in range(10**6):
        if i%10**5==0:print(i)
        assert cprng1.randbytes(32) == cprng2.randbytes(32)