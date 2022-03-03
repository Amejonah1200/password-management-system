import secrets
import unittest
from unittest import TestCase

import auth
import configuration
import database
import hasher
import pwdgen
import usermanager
from auth import Authenticator
from configuration import create_default_hashing, HashAlgorithm
from policy import Policy


def make_user_manager_test(config: configuration.Configuration):
    class UserManagerTest(TestCase):

        def setUp(self) -> None:
            self.user_manager = usermanager.UserManager(database.InMemoryDatabase(), config)
            self.test_pwd = pwdgen.generate(self.user_manager.config.policy)

        def test_insert(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))

        def test_insert_different_appid(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "other"), (usermanager.InsertionResult.SUCCESS, None))

        def test_insert_duplicate(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"),
                             (usermanager.InsertionResult.USER_ALREADY_REGISTERED, None))

        def test_validation(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertEqual(self.user_manager.user_validate("tester", self.test_pwd, "default")[0], usermanager.ValidationResult.VALID)

        def test_validation_false_pwd(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertEqual(self.user_manager.user_validate("tester", pwdgen.generate(self.user_manager.config.policy), "default")[0],
                             usermanager.ValidationResult.NOT_VALID)

        def test_validation_non_existent(self):
            self.assertTrue(self.user_manager.user_validate("tester", self.test_pwd, "default")[0], usermanager.ValidationResult.USER_NOT_FOUND)

        def test_password_change(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertEqual(self.user_manager.user_validate("tester", self.test_pwd, "default")[0], usermanager.ValidationResult.VALID)
            old_pwd = self.test_pwd
            self.test_pwd = pwdgen.generate(self.user_manager.config.policy)
            self.assertEqual(self.user_manager.user_change_password("tester", self.test_pwd, "default", old_pwd),
                             (usermanager.ChangePasswordResult.SUCCESS, None))
            self.assertEqual(self.user_manager.user_validate("tester", self.test_pwd, "default")[0], usermanager.ValidationResult.VALID)

        def test_password_change_non_existent(self):
            self.assertEqual(self.user_manager.user_change_password("tester", self.test_pwd, "nobody"),
                             (usermanager.ChangePasswordResult.USER_NOT_FOUND, None))

        def test_password_change_invalid_policy(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertEqual(self.user_manager.user_validate("tester", self.test_pwd, "default")[0], usermanager.ValidationResult.VALID)
            old_pwd = self.test_pwd
            self.test_pwd = "invalid"
            result, broken_rules = self.user_manager.user_change_password("tester", self.test_pwd, "default", old_pwd)
            self.assertEqual(result, usermanager.ChangePasswordResult.PASSWORD_INVALID)

        def test_delete_user(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertTrue(self.user_manager.user_delete("tester", "default"))
            self.assertEqual(self.user_manager.user_validate("tester", self.test_pwd, "default")[0],
                             usermanager.ValidationResult.USER_NOT_FOUND)

        def test_delete_user_many(self):
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "default"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertEqual(self.user_manager.user_insert("tester", self.test_pwd, "other"), (usermanager.InsertionResult.SUCCESS, None))
            self.assertTrue(self.user_manager.user_delete_all("tester"))
            self.assertEqual(self.user_manager.user_validate("tester", self.test_pwd, "default")[0],
                             usermanager.ValidationResult.USER_NOT_FOUND)
            self.assertEqual(self.user_manager.user_validate("tester", self.test_pwd, "other")[0],
                             usermanager.ValidationResult.USER_NOT_FOUND)

        def test_delete_user_non_existent(self):
            self.assertFalse(self.user_manager.user_delete("nobody", "default"))

    return UserManagerTest


def create_test_config(algo: HashAlgorithm) -> configuration.Configuration:
    return configuration.Configuration(True, Policy(16, 4, 4, 4, 4, "/*-+"), create_default_hashing(algo), True)


class BCryptUserManagerTest(make_user_manager_test(create_test_config(HashAlgorithm.BCRYPT))):
    pass


class Argon2UserManagerTest(make_user_manager_test(create_test_config(HashAlgorithm.ARGON2))):
    pass


class HasherTest:

    def test_hash(self):
        self.assertTrue(self.hasher.check_hash("it's me a hash".encode(), self.hasher.hash("it's me a hash".encode())))

    def test_needs_rehash(self):
        raise NotImplementedError()


class Argon2HasherTest(HasherTest, TestCase):

    def setUp(self) -> None:
        self.hasher = hasher.Argon2Hasher()

    def test_needs_rehash(self):
        hash = self.hasher.hash("it's me a hash".encode())
        self.hasher = hasher.Argon2Hasher(parallelism=2)
        self.assertTrue(self.hasher.needs_rehash(hash))


class BcryptHasherTest(HasherTest, TestCase):

    def setUp(self) -> None:
        self.hasher = hasher.BcryptHasher()

    def test_needs_rehash(self):
        hash = self.hasher.hash("it's me a hash".encode())
        self.hasher = hasher.BcryptHasher(rounds=2)
        self.assertTrue(self.hasher.needs_rehash(hash))


class TokenAuthTest(TestCase):

    def setUp(self) -> None:
        self.auth = Authenticator(database.InMemoryDatabase(), configuration.Configuration(True, None, None, True))
        self.default_token = self.auth.token_get("adminadm-inad-mina-dminadminadminad")
        self.assertIsNotNone(self.default_token)

    def test_default_token_perms(self):
        for perm in auth.all_perms:
            with self.subTest(perm=perm):
                self.auth.token_auth("adminadm-inad-mina-dminadminadminad", perm)

    def test_token_generation_all(self):
        result, token = self.auth.token_generate("adminadm-inad-mina-dminadminadminad", auth.all_perms)
        self.assertEqual(result, auth.GenerationResult.SUCCESS)
        self.assertIsInstance(token, database.Token)
        for perm in auth.all_perms:
            with self.subTest(perm=perm):
                self.auth.token_auth(token.token, perm)

    def test_default_token_regeneration(self):
        token = self.auth.token_get("adminadm-inad-mina-dminadminadminad")
        self.assertIsNotNone(token)
        self.assertListEqual(token.perms, auth.all_perms)
        result, token = self.auth.token_regenerate("adminadm-inad-mina-dminadminadminad")
        self.assertEqual(result, auth.GenerationResult.SUCCESS)
        self.assertIsNotNone(token)
        token = self.auth.token_get(token)
        self.assertIsNotNone(token)
        self.assertListEqual(token.perms, auth.all_perms)
        self.assertIsNone(self.auth.token_get("adminadm-inad-mina-dminadminadminad"))

    def test_unknown_perm(self):
        self.assertFalse(self.auth.token_auth(self.default_token.token, ""))
        result, perms = self.auth.token_generate(self.default_token.token, ["a"])
        self.assertEqual(result, auth.GenerationResult.UNKNOWN_PERMS)
        self.assertListEqual(perms, ["a"])

    def test_token_deletion(self):
        result, token = self.auth.token_generate("adminadm-inad-mina-dminadminadminad", auth.all_perms)
        self.assertEqual(result, auth.GenerationResult.SUCCESS)
        self.assertIsInstance(token, database.Token)
        token = self.auth.token_get(token.token)
        self.assertIsNotNone(token)
        self.assertTrue(self.auth.database.token_delete(token.token))
        self.assertIsNone(self.auth.token_get(token.token))


class PasswordTest(TestCase):

    def setUp(self) -> None:
        self.policy = Policy(17, 4, 4, 4, 4, "!#*-+")

    def test_pwdgen_and_validate(self):
        self.assertTrue(self.policy.validate(pwdgen.generate(self.policy))[0])

    def test_min_length(self):
        valid, broken_rules = self.policy.validate(pwdgen.generate(self.policy)[:self.policy.min_length - 1])
        self.assertFalse(valid)
        self.assertTrue("min_length" in broken_rules)
        self.assertTupleEqual(broken_rules["min_length"], (self.policy.min_length - 1, self.policy.min_length))
        for length in range(self.policy.min_length, self.policy.min_length + 2):
            with self.subTest(length=length):
                self.assertTrue(self.policy.validate(pwdgen.generate(self.policy)[:length])[0])

    def test_min_charsets(self):
        for charset_name, charset_attributes in self.policy.min_charset.items():
            charset, charset_min = charset_attributes
            if charset_name == "other":
                continue
            with self.subTest(charset_name=charset_name, charset_min=charset_min, nb=charset_min - 1):
                pwd = "".join([secrets.choice(charset) for _ in range(charset_min - 1)])
                valid, broken_rules = self.policy.validate(pwd)
                self.assertFalse(valid)
                self.assertTrue(charset_name in broken_rules)
            for nb in range(charset_min, charset_min + 2):
                with self.subTest(charset_name=charset_name, charset_min=charset_min, nb=nb):
                    pwd = "".join([secrets.choice(charset) for _ in range(nb)])
                    valid, broken_rules = self.policy.validate(pwd)
                    self.assertFalse(valid)
                    self.assertTrue(charset_name not in broken_rules)

    def test_polish(self):
        pwd = self.policy.polish("§")
        validation = self.policy.validate(pwd)
        self.assertTrue(validation[0])


if __name__ == '__main__':
    unittest.main()
