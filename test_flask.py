import json
import unittest
from typing import Union
from unittest import TestCase

import werkzeug
from flask.testing import FlaskClient

import app
import configuration
import policy
import pwdgen
from auth import Authenticator
from database import InMemoryDatabase
from hasher import HashAlgorithm
from usermanager import UserManager


class TestApp(app.App):

    def setup(self):
        self.setuped = True
        self.config = configuration.Configuration(True, policy.Policy(16, 4, 4, 4, 4, "!"),
                                                  configuration.create_default_hashing(HashAlgorithm.ARGON2),
                                                  False)
        self.database = InMemoryDatabase()
        self.user_manager = UserManager(self.database, self.config)
        self.auth = Authenticator(self.database, self.config)


app.app.testing = True
app.the_app = TestApp()


class FlaskTest(TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        app.the_app.setup()

    def setUp(self) -> None:
        app.the_app.db_set(InMemoryDatabase())
        self.client = app.app.test_client()

    def test_passwords_generate(self):
        for check_hibp in ["?check_hibp=true", "?check_hibp=false", ""]:
            with self.subTest(url="/passwords/generate" + check_hibp):
                response = self.client.get("/passwords/generate" + check_hibp)
                self.assertTrue(response.is_json)
                self.assertTrue("pwd" in response.json)
                self.assertTrue(app.the_app.config.policy.validate(response.json["pwd"]))

    def test_passwords_generate_batch(self):
        response = self.client.get("/passwords/generate?batch=2")
        self.assertTrue(response.is_json)
        self.assertTrue("pwds" in response.json)
        pwds = response.json["pwds"]
        for pwd in pwds:
            with self.subTest(pwd=pwd):
                self.assertTrue(app.the_app.config.policy.validate(pwd))

    def test_passwords_validate(self):
        for pwd in ["not-valid", pwdgen.generate(app.the_app.config.policy, False)]:
            with self.subTest(pwd=pwd):
                response = self.client.get(f"/passwords/validate?password={pwd}")
                self.assertTrue(response.is_json)
                self.assertTrue("valid" in response.json)
                self.assertEqual(response.json["valid"], app.the_app.config.policy.validate(pwd)[0])

    def test_users_insert(self):
        pwd = pwdgen.generate(app.the_app.config.policy)
        response = post_json(self.client, "/users", {"username": "tester", "appId": "default", "password": pwd})
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 201)

    def test_users_insert_different_appid(self):
        for appId in ["a", "b", "c"]:
            with self.subTest(appId=appId):
                pwd = pwdgen.generate(app.the_app.config.policy)
                response = post_json(self.client, "/users", {"username": "tester", "appId": appId, "password": pwd})
                self.assertTrue(response.is_json)
                self.assertEqual(response.status_code, 201)

    def test_users_insert_duplicate(self):
        pwd = pwdgen.generate(app.the_app.config.policy)
        self.assertEqual(post_json(self.client, "/users", {"username": "tester", "appId": "default", "password": pwd}).status_code, 201)
        response = post_json(self.client, "/users", {"username": "tester", "appId": "default", "password": pwd})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["success"])
        self.assertTrue(response.is_json)
        self.assertTrue("message" in response.json)
        self.assertEqual(response.json["message"], "user_already_registered")

    def test_users_validation(self, pwd=None):
        if pwd is None:
            pwd = pwdgen.generate(app.the_app.config.policy)
        response = post_json(self.client, "/users", {"username": "tester", "appId": "default", "password": pwd})
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 201)
        response = self.client.get(f"/users/tester/validate?appId=default&password={pwd}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        self.assertTrue("success" in response.json)
        self.assertTrue(response.json["success"])

    def test_users_validation_false_pwd(self):
        pwd = pwdgen.generate(app.the_app.config.policy)
        response = post_json(self.client, "/users", {"username": "tester", "appId": "default", "password": pwd})
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 201)
        response = self.client.get(f"/users/tester/validate?appId=default&password=yes-but-no")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        self.assertTrue("success" in response.json and "message" in response.json)
        self.assertFalse(response.json["success"])
        self.assertEqual(response.json["message"], "not_valid")

    def test_users_validation_non_existent(self):
        response = self.client.get(f"/users/nobody/validate?appId=default&password=yes-but-no")
        self.assertEqual(response.status_code, 404)
        self.assertTrue(response.is_json)
        self.assertTrue("success" in response.json and "message" in response.json)
        self.assertFalse(response.json["success"])
        self.assertEqual(response.json["message"], "user_not_found")

    def test_users_password_change(self):
        pwd = pwdgen.generate(app.the_app.config.policy)
        response = post_json(self.client, "/users", {"username": "tester", "appId": "default", "password": pwd})
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 201)
        old_pwd = pwd
        pwd = pwdgen.generate(app.the_app.config.policy)
        response = patch_json(self.client, "/users/tester/change_pwd", {
            "password": pwd,
            "appId": "default",
            "old_password": old_pwd
        })
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 200)
        self.assertTrue("success" in response.json)
        self.assertTrue(response.json["success"])

    def test_users_password_change_non_existent(self):
        response = patch_json(self.client, "/users/nobody/change_pwd", {
            "password": "yes-but-no",
            "appId": "default"
        })
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 404)
        self.assertTrue("success" in response.json and "message" in response.json)
        self.assertFalse(response.json["success"])
        self.assertEqual(response.json["message"], "user_not_found")

    def test_users_password_change_invalid_policy(self):
        old_pwd = pwdgen.generate(app.the_app.config.policy)
        response = post_json(self.client, "/users", {"username": "tester", "appId": "default", "password": old_pwd})
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 201)
        response = patch_json(self.client, "/users/tester/change_pwd", {
            "password": "invalid",
            "appId": "default",
            "old_password": old_pwd
        })
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 200)
        self.assertTrue("success" in response.json and "message" in response.json and "broken_rules" in response.json)
        self.assertFalse(response.json["success"])
        self.assertEqual(response.json["message"], "password_invalid")
        _, broken_rules = app.the_app.config.policy.validate("invalid")
        for rule_name, count_and_min in broken_rules.items():
            with self.subTest(rule_name=rule_name, count_and_min=count_and_min):
                self.assertTrue(rule_name in response.json["broken_rules"])
                self.assertTrue("count" in response.json["broken_rules"][rule_name])
                self.assertTrue("expected" in response.json["broken_rules"][rule_name])
                self.assertEqual(response.json["broken_rules"][rule_name]["count"], count_and_min[0])
                self.assertEqual(response.json["broken_rules"][rule_name]["expected"], count_and_min[1])

    def test_users_delete(self):
        self.test_users_validation()
        response = self.client.delete("/users/tester?appid=default")
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 200)
        self.assertTrue("success" in response.json)
        self.assertTrue(response.json["success"])

    def test_users_delete_many(self):
        self.test_users_insert_different_appid()
        for id in ["a", "b", "c"]:
            response = self.client.get(f"/users/tester/validate?appId={id}&password=i-don't-know")
            self.assertNotEqual(response.status_code, 404)
            self.assertTrue(response.is_json)
            self.assertTrue("success" in response.json)
        response = self.client.delete("/users/tester")
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 200)
        self.assertTrue("success" in response.json)
        self.assertTrue(response.json["success"])
        for id in ["a", "b", "c"]:
            response = self.client.get(f"/users/tester/validate?appId={id}&password=i-don't-know")
            self.assertEqual(response.status_code, 404)
            self.assertTrue(response.is_json)
            self.assertTrue("success" in response.json)
            self.assertFalse(response.json["success"])

    def test_users_delete_non_existent(self):
        response = self.client.delete("/users/nobody")
        self.assertTrue(response.is_json)
        self.assertEqual(response.status_code, 404)
        self.assertTrue("success" in response.json)
        self.assertFalse(response.json["success"])


if __name__ == '__main__':
    unittest.main()


def post_json(client: FlaskClient, path: str, body: Union[dict, list]) -> werkzeug.test.TestResponse:
    return client.post(path, headers={'Content-Type': 'application/json'}, data=json.dumps(body))


def put_json(client: FlaskClient, path: str, body: Union[dict, list]) -> werkzeug.test.TestResponse:
    return client.put(path, headers={'Content-Type': 'application/json'}, data=json.dumps(body))


def patch_json(client: FlaskClient, path: str, body: Union[dict, list]) -> werkzeug.test.TestResponse:
    return client.patch(path, headers={'Content-Type': 'application/json'}, data=json.dumps(body))
