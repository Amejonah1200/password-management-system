import random

import hibprequester
import policy
import secrets


def generate(p: policy.Policy, check_on_hibp=False) -> str:
    r"""
    Generating password randomly using secure randomness from the os
    :param p: policy to reference
    :return: generated password
    """
    # raw_pwd is a pool of chars which are then put together into a string
    # Adding needed minimum of numbers into the pool
    raw_pwd = generate_n_chars_from_charset("0123456789", p.min_numbers)
    # Adding needed minimum of capitals into the pool
    raw_pwd += generate_n_chars_from_charset("ABCDEFGHIJKLMNOPQRSTUVWXYZ", p.min_capital)
    # Adding needed minimum of lower characters into the pool
    raw_pwd += generate_n_chars_from_charset("abcdefghijklmnopqrstuvwxyz", p.min_lower)
    # Adding needed minimum of special characters into the pool
    raw_pwd += generate_n_chars_from_charset(p.special_set, p.min_special)
    # Adding random chars within the charset to match the minimum length
    if len(raw_pwd) < p.min_length:
        raw_pwd += generate_n_chars_from_charset(p.get_charset(), p.min_length - len(raw_pwd))
    # Shuffling the pool
    random.shuffle(raw_pwd, random=lambda: secrets.SystemRandom().random())
    # Joining together into a string
    pwd = "".join(raw_pwd)
    if check_on_hibp:
        while hibprequester.is_pwd_pwned(pwd):
            pwd = generate(p)
    return pwd


def generate_n_chars_from_charset(charset: str, nb: int) -> list:
    # Mapping a number for the range from 0 to nb to a random char in the charset
    # Basically generating randomly nb chars from the charset
    return [secrets.choice(charset) for _ in range(nb)]
