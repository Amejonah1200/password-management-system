import secrets
from typing import Tuple, Mapping, List, Dict


class Policy:
    def __init__(self, min_length: int, min_capital: int, min_lower: int, min_numbers: int, min_special: int, special_set: str):
        self.min_capital = min_capital
        self.min_lower = min_lower
        self.min_numbers = min_numbers
        self.min_special = min_special
        self.special_set = special_set
        if min_length < sum((min_capital, min_special, min_lower, min_numbers)):
            min_length = sum((min_capital, min_special, min_lower, min_numbers))
        self.min_length = min_length
        self.min_charset = {
            "min_capital": ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_capital),
            "min_lower": ("abcdefghijklmnopqrstuvwxyz", min_lower),
            "min_numbers": ("0123456789", min_numbers),
            "min_special": (self.special_set, min_special),
            "other": ("", 0)
        }

    def get_charset(self) -> str:
        r"""
        :return: the whole charset
        """
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" + self.special_set

    def validate(self, pwd: str) -> (bool, Mapping[str, Tuple[int, int]]):
        # Counting how much capitals there are
        count_capital = count_charset(pwd, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        # Counting how much lower case characters there are
        count_lower = count_charset(pwd, "abcdefghijklmnopqrstuvwxyz")
        # Counting how much numbers there are
        count_numbers = count_charset(pwd, "0123456789")
        # Counting how much special characters there are
        count_special = count_charset(pwd, self.special_set)
        # Creating response
        problems = {}
        # Adding problems, all criteria which are not met by the password
        if len(pwd) < self.min_length:
            problems["min_length"] = (len(pwd), self.min_length)
        if count_capital < self.min_capital:
            problems["min_capital"] = (count_capital, self.min_capital)
        if count_lower < self.min_capital:
            problems["min_lower"] = (count_lower, self.min_lower)
        if count_numbers < self.min_capital:
            problems["min_numbers"] = (count_numbers, self.min_numbers)
        if count_special < self.min_capital:
            problems["min_special"] = (count_special, self.min_special)
        return len(problems) == 0, problems

    def polish(self, pwd: str, trim_to_min=False) -> str:
        r"""
        Polishing a password to met the policy. Passing an empty password, results the generation of one.
        It's highly recommended to use pwdgen to generate passwords,
        because this algorithm should be only used to fix passwords, the reason is the efficiency.

        :param pwd: password to poilish
        :param trim_to_min: if it should trim the password to minimum length if needed. default is false.
        :return: polished password
        """

        if len(pwd) < self.min_length:
            # Adding random characters to the password if not matching the minimum length
            pwd += "".join([secrets.choice(self.get_charset()) for _ in range(self.min_length - len(pwd))])
        elif trim_to_min and len(pwd) > self.min_length:
            # Trimming to minimum length if set so
            pwd = pwd[:self.min_length]
        # Converting password into a list, to be able to modify it
        pwd = list(pwd)
        # Validate the password to analyse the problems, if any
        valid, broken_rules = self.validate("".join(pwd))
        if valid:
            # Password is already valid, returning
            return "".join(pwd)
        # Finding all indices which can be replaced
        indices = self.find_sacrificable_indexes(pwd, broken_rules)
        for rule in broken_rules:
            count, min = broken_rules[rule]
            # Looping that much times, which is needed to match the criterion
            for _ in range(min - count):
                # (secure) randomly choosing a position
                name, inds = secrets.choice(list(indices.items()))
                i = secrets.choice(inds)
                if len(inds) - 1 == self.min_charset[name][1]:
                    # Removing from indices if you cannot replace them anymore,
                    # because otherwise it would replace characters which are needed by the policy
                    del indices[name]
                else:
                    # Removing used index to not replace it anymore
                    inds.remove(i)
                # Replacing the character with a random selected character from the charset
                pwd[i] = secrets.choice(self.min_charset[rule][0])
        # Joining the password into a string
        return "".join(pwd)

    def find_sacrificable_indexes(self, pwd, broken_rules: Mapping[str, Tuple[int, int]]) -> Dict[str, List[int]]:
        r"""
        Finds characters in the provided password, which can be replaced.
        :param pwd: password in which to search to
        :param broken_rules: criteria which were broken by the password
        :return: replaceable indices
        """
        indices = {}
        # Iterating over min charsets which are not been broken.
        for charset in filter(lambda cs: cs not in broken_rules, self.min_charset):
            indices[charset] = []
            # Iterating over password using indices
            for i in range(len(pwd)):
                if pwd[i] in self.min_charset[charset][0]:
                    # Add index of found character which can be replaced
                    indices[charset].append(i)
        indices["other"] = []
        # Add other characters which are not in the charset
        for i in range(len(pwd)):
            if pwd[i] not in self.get_charset():
                indices["other"].append(i)
        # Remove indices which are already matching the policy or empty lists
        for rule in indices.copy().items():
            if self.min_charset[rule[0]][1] == len(rule[1]) or len(rule[1]) == 0:
                del indices[rule[0]]
        return indices


def count_charset(txt: str, charset: str) -> int:
    r"""
    Counts the amount of characters in txt which are in the charset.
    :param txt: text to analyse
    :param charset: charset for referencing
    :return: amount of charset's characters present in txt
    """
    return sum(txt.count(c) for c in charset)
