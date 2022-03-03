import requests
import hashlib


def pwd_pwned(pwd: str):
    r"""Requests the amount of breaches of the provided password.
        :param pwd: password to request
        :return: amount of breaches
        :rtype: int
        """
    # First, we encode the string in utf-8, to receive all bytes for hash
    # Then, we hash, get the digest, and then make the digest in uppercase.
    pwd_hashed = hashlib.sha1(pwd.encode()).hexdigest().upper()
    # Requesting (GET) from HIBP the list of pwned passwords with the 5 first characters of
    # the digest. The response is a text, so we need to parse it later.
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{pwd_hashed[:5]}")
    # Here we go through every line of the response, mapping the line to a tuple
    # of the second part of the digest and the amount of breaches.
    entries = [(entry.split(":")[0], int(entry.split(":")[1])) for entry in resp.text.split()]
    # Trimming the hash
    pwd_hashed = pwd_hashed[5:]
    # Searching for the right digest.
    for entry in entries:
        if entry[0] == pwd_hashed:
            return entry[1]
    # If none was found, return 0.
    return 0


def is_pwd_pwned(pwd: str):
    r"""Requests if the provided password was pwned.
        Basically testing pwd_pwned on greater than 0.
        :param pwd: password to request
        :return: if provided password was pwned
        :rtype: bool
        """
    return pwd_pwned(pwd) > 0
