import json

from hasher import Argon2Hasher, HashAlgorithm, BcryptHasher
from policy import Policy


class HashingConfig:
    def __init__(self, algo: HashAlgorithm, argon2, bcrypt):
        self.algo = algo
        self.hasher = bcrypt if algo == HashAlgorithm.BCRYPT else argon2
        self.argon2 = argon2
        self.bcrypt = bcrypt


def load_hashing_from_config(jsonobj) -> HashingConfig:
    algo = HashAlgorithm.ARGON2 if jsonobj["algorithm"] == "argon2" else HashAlgorithm.BCRYPT
    bcrypt = BcryptHasher(jsonobj["bcrypt"]["rounds"])
    jsonobj = jsonobj["argon2"]
    return HashingConfig(algo, Argon2Hasher(jsonobj["time_cost"],
                                            jsonobj["memory_cost"],
                                            jsonobj["parallelism"],
                                            jsonobj["hash_len"],
                                            jsonobj["salt_len"]),
                         bcrypt)


def create_default_hashing(algo: HashAlgorithm) -> HashingConfig:
    return HashingConfig(algo, Argon2Hasher(), BcryptHasher())


class Configuration:
    def __init__(self, dev: bool, policy: Policy, hashing: HashingConfig, auth: bool):
        self.dev = dev
        self.policy = policy
        self.hashing = hashing
        self.auth = auth


def policy_load_from_json(jsonobj) -> Policy:
    return Policy(jsonobj["min_length"],
                  jsonobj["min_capital"],
                  jsonobj["min_lower"],
                  jsonobj["min_numbers"],
                  jsonobj["min_special"],
                  jsonobj["special_set"])


def config_load_from_file(file) -> Configuration:
    with open(file) as f:
        jsonobj = json.load(f)
        return Configuration(bool(jsonobj["dev"]), policy_load_from_json(jsonobj["policy"]), load_hashing_from_config(jsonobj["hashing"]),
                             jsonobj["auth"])
