import re
from enum import Enum
from typing import Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import bcrypt


class HashAlgorithm(Enum):
    BCRYPT = "$2b$"
    ARGON2 = "$argon2id$"


# This is an abstract class of hasher, applying the strategy pattern.
class Hasher:
    def hash(self, pwd: bytes) -> bytes:
        raise NotImplementedError()

    def needs_rehash(self, pwd: bytes) -> bool:
        raise NotImplementedError()

    def check_hash(self, pwd: bytes, hashed_pwd: bytes) -> bool:
        raise NotImplementedError()


class BcryptHasher(Hasher):
    """
    Hasher implementation for bcrypt.
    Defaults are from the library.
    """

    def __init__(self, rounds: int = 12):
        self.rounds = rounds

    def hash(self, pwd: bytes) -> bytes:
        return bcrypt.hashpw(pwd, bcrypt.gensalt(self.rounds))

    def needs_rehash(self, pwd_hash: bytes) -> bool:
        matches = re.compile(r"\$(\d+)\$").findall(pwd_hash.decode())
        return len(matches) != 0 and self.rounds != int(matches[0])

    def check_hash(self, pwd: bytes, hashed_pwd: bytes) -> bool:
        return bcrypt.checkpw(pwd, hashed_pwd)


class Argon2Hasher(Hasher):
    """
    Hasher implementation for Argon2.
    Defaults are from the library.
    """
    def __init__(self, time_cost: int = 2, memory_cost: int = 102400, parallelism: int = 8, hash_len: int = 16, salt_len: int = 16):
        self.hasher = PasswordHasher(time_cost, memory_cost, parallelism, hash_len, salt_len)

    def hash(self, pwd: bytes) -> bytes:
        return self.hasher.hash(pwd).encode()

    def needs_rehash(self, pwd_hash: bytes) -> bool:
        return self.hasher.check_needs_rehash(pwd_hash.decode())

    def check_hash(self, pwd: bytes, hashed_pwd: bytes) -> bool:
        try:
            self.hasher.verify(hashed_pwd.decode(), pwd.decode())
        except VerifyMismatchError:
            return False
        return True


class MultiplexHasher(Hasher):
    """
    This implementation of the hasher enables to handle multiple hashing algorithms,
    for example if the algorithm should be changeable.
    """
    def __init__(self, main_algo: HashAlgorithm, *args: Tuple[HashAlgorithm, Hasher]):
        self.algo: HashAlgorithm = None
        self.hasher = None
        self.set_algo(main_algo)
        self.hashers = {}
        for arg in args:
            self.hashers[arg[0]] = arg[1]

    def hash(self, pwd: bytes) -> bytes:
        # Hashing with the current algorithm
        return self.hasher.hash(pwd)

    def needs_rehash(self, pwd: bytes) -> bool:
        # If for the password a different algorithm was used, returning true
        if not pwd.decode().startswith(self.algo.value):
            return True
        # Checking if different parameters were used
        return self.hasher.needs_rehash(pwd)

    def check_hash(self, pwd: bytes, hashed_pwd: bytes) -> bool:
        # Searching matching algorithm
        for algo, hasher in self.hashers.items():
            if pwd.decode().startswith(algo.value):
                # Checking hash
                return hasher.check_hash(pwd, hashed_pwd)
        # If not implementation was found, raising an Error
        raise NotImplementedError(f"No implemented hasher for this hash: {hashed_pwd.decode()}")

    def set_algo(self, algo: HashAlgorithm):
        self.algo = algo
        # Searching the right hasher, and setting it
        for arg in self.hashers:
            if arg[0] == self.algo:
                self.hasher = arg[1]
                return
