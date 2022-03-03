from flask import Flask, jsonify, request

import hibprequester
from database import InMemoryDatabase, JsonDatabase, Database
from usermanager import UserManager, ValidationResult, ChangePasswordResult, InsertionResult
from auth import Authenticator, GenerationResult
import configuration
import pwdgen

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False


class App:
    """
    This class if for holding all data about the app. The setup() method is called before the first request,
    make sure to not raising any errors on loading resources.
    """

    def __init__(self):
        self.config = None
        self.database = None
        self.user_manager = None
        self.auth = None
        self.setuped: bool = False

    def setup(self):
        raise NotImplementedError

    def db_set(self, db: Database):
        self.database = db
        self.user_manager.database = db
        self.auth.database = db


class ProductionApp(App):
    """
    The production ready implementation of the class.
    """

    def setup(self):
        self.setuped = True
        try:
            self.config = configuration.config_load_from_file("config.json")
        except KeyError as error:
            print("config.json is broken! Please fix it!")
            print(error)
            exit(-1)
        if self.config.dev:
            self.database = InMemoryDatabase()
        else:
            self.database = JsonDatabase("db.json")
        self.user_manager = UserManager(self.database, self.config)
        self.auth = Authenticator(self.database, self.config)


the_app = ProductionApp()


@app.before_first_request
def _start():
    # Loading resource only when actually a request was made, this enables to change the_app before
    if not the_app.setuped:
        the_app.setup()
    if the_app.auth.token_get("adminadm-inad-mina-dminadminadminad") is not None:
        print("CAUTION! The default token is working and not regenerated! Please regenerate it!")


def auth_token(args, permission) -> (bool, int):
    if not the_app.config.auth:
        return True, 200
    if "token" not in args:
        return False, 401
    if the_app.auth.token_auth(args["token"], permission):
        return True, 200
    else:
        return False, 403


@app.route('/passwords/generate')
def passwords_generate():
    # Getting amount of batches
    amount = request.args.get("batch", 1, int)
    # Setting >=1
    amount = max(1, amount)
    # Getting if checking these passwords on hibp
    check_hibp = request.args.get("check_hibp", False, bool)
    if amount == 1:
        return {"pwd": pwdgen.generate(the_app.config.policy, check_hibp)}, 200
    else:
        return {"pwds": [pwdgen.generate(the_app.config.policy, check_hibp) for _ in range(amount)]}, 200


@app.route('/passwords/check_hibp')
def passwords_check_hibp():
    # Getting password
    pwd = request.args["password"]
    # Checking it
    amount = hibprequester.pwd_pwned(pwd)
    # Returning result
    if amount == 0:
        return {"pwned": False}, 200
    else:
        return {"pwned": True, "amount": amount}, 200


@app.route('/passwords/validate')
def passwords_validate():
    # Get password
    password = request.args["password"]
    # Validating
    valid, broken_rules = the_app.config.policy.validate(password)
    if valid:
        # If valid
        return {"valid": True}, 200
    else:
        # Not valid, returning broken rules
        broken_rules_result = {}
        for rule_name, count_and_min in broken_rules.items():
            broken_rules_result[rule_name] = {
                "count": count_and_min[0],
                "expected": count_and_min[1]
            }
        return {"valid": False, "broken_rules": broken_rules_result}, 200


@app.route('/users', methods=["POST"])
def users():
    # Authenticating
    is_auth, error_code = auth_token(request.args, "users.create")
    if not is_auth:
        return {}, error_code
    # Getting body as json
    json_req = request.get_json(force=True, silent=True)
    # If the content is not a json
    if json_req is None:
        return {"message": "not-json"}, 400
    try:
        # Inserting user
        result, broken_rules = the_app.user_manager.user_insert(json_req["username"], json_req["password"], json_req["appId"])
        if result == InsertionResult.SUCCESS:
            return {"success": True}, 201
        elif result == InsertionResult.USER_ALREADY_REGISTERED:
            return {"success": False, "message": "user_already_registered"}, 200
        else:
            # Not valid password, returning broken rules
            broken_rules_result = {}
            for rule_name, count_and_min in broken_rules.items():
                broken_rules_result[rule_name] = {
                    "count": count_and_min[0],
                    "expected": count_and_min[1]
                }
            return {"success": False, "message": "password_invalid", "broken_rules": broken_rules_result}, 200
    except KeyError:
        # If username, password or appId was not provided
        return {"message": "false-json-scheme"}, 400


@app.route('/users/<user>/validate')
def users_validate(user):
    # Authenticating
    is_auth, error_code = auth_token(request.args, "users.validate")
    if not is_auth:
        return {}, error_code
    # Getting parameters
    pwd = request.args["password"]
    appId = request.args["appId"]
    # Validating password
    result, broken_rules = the_app.user_manager.user_validate(user, pwd, appId)
    # Returning result
    return {
        ValidationResult.VALID: ({"success": True}, 200),
        ValidationResult.USER_NOT_FOUND: ({"success": False, "message": "user_not_found"}, 404),
        ValidationResult.NOT_VALID: ({"success": False, "message": "not_valid"}, 200),
        ValidationResult.VALID_BUT_NOT_POLICY: ({"success": True, "message": "policy_not_valid", "broken_policies": broken_rules}, 200)
    }[result]


@app.route('/users/<user>/change_pwd', methods=["PATCH"])
def users_change_pwd(user):
    # Authenticating
    is_auth, error_code = auth_token(request.args, "users.change_pw")
    if not is_auth:
        return {}, error_code
    # Getting body as json
    json_req = request.get_json(force=True, silent=True)
    # If the content is not a json
    if json_req is None:
        return {"message": "not-json"}, 400
    # Trying to change password
    try:
        result, broken_rules = the_app.user_manager.user_change_password(user, json_req["password"], json_req["appId"],
                                                                         json_req["old_password"] if "old_password" in json_req else None)
    except KeyError:
        return {"message": "false-json-scheme"}, 400
    if result == ChangePasswordResult.PASSWORD_INVALID:
        # Password not matches criteria, returning broken rules
        broken_rules_result = {}
        for rule_name, count_and_min in broken_rules.items():
            broken_rules_result[rule_name] = {
                "count": count_and_min[0],
                "expected": count_and_min[1]
            }
        return {"success": False, "message": "password_invalid", "broken_rules": broken_rules_result}, 200
    else:
        # Other responses
        return {
            ChangePasswordResult.SUCCESS: ({"success": True}, 200),
            ChangePasswordResult.USER_NOT_FOUND: ({"success": False, "message": "user_not_found"}, 404),
            ChangePasswordResult.WRONG_PASSWORD: ({"success": False, "message": "wrong_password"}, 200)
        }[result]


@app.route('/users/<user>', methods=["DELETE"])
def users_delete(user):
    # Authenticating
    is_auth, error_code = auth_token(request.args, "users.delete")
    if not is_auth:
        return {}, error_code
    # Deleting user, all if no appId provided
    result = the_app.user_manager.user_delete(user, request.args["appId"]) if "appId" in request.args else the_app.user_manager.user_delete_all(user)
    # Sending if succeed
    if result:
        return {"success": True}, 200
    else:
        return {"success": False}, 404


@app.route('/tokens', methods=["POST"])
def tokens_create():
    # Authenticating
    if "token" not in request.args:
        return {}, 401
    # Getting body as json
    json_req = request.get_json(force=True, silent=True)
    if json_req is None or not isinstance(json_req, list):
        return {}, 400
    # Checking if every entry is a string
    for perm in json_req:
        if not isinstance(perm, str):
            return {}, 400
    # Generate token
    result = the_app.auth.token_generate(request.args["token"], json_req)
    # Returning response, lambda was used to not call result[1].token if it's not a Token object
    return {
        GenerationResult.SUCCESS: lambda: ({"success": True, "token": {
            "token": result[1].token,
            "perms": result[1].perms
        }}, 200),
        GenerationResult.UNAUTHORIZED: lambda: ({"success": False}, 403),
        GenerationResult.UNAUTHENTICATED: lambda: ({"success": False}, 401),
        GenerationResult.NO_PERMS: lambda: ({"success": False, "message": GenerationResult.NO_PERMS.value}, 200),
    }.get(result[0], lambda: {"success": False, "message": result[0].value, "problem_perms": result[1]})()


@app.route('/tokens/permissions')
def tokens_permissions_get():
    # Authenticating
    if "token" not in request.args:
        return {}, 401
    # Getting token
    token = the_app.auth.token_get(request.args["token"])
    if token is None:
        return {}, 401
    else:
        # Returning an array of strings (permissions)
        return jsonify(token.perms), 200


@app.route('/tokens/permissions', methods=['PUT'])
def tokens_permissions_set():
    # Getting body as json
    json_req = request.get_json(force=True, silent=True)
    if json_req is None or not isinstance(json_req, list):
        return {}, 400
    # Checking if every entry is a string
    for perm in json_req:
        if not isinstance(perm, str):
            return {}, 400
    # Trying to set permissions
    result = the_app.auth.token_set_perms(request.args["token"], request.args["token_other"], json_req)
    # Returning result
    return {
        GenerationResult.SUCCESS: ({"success": True}, 200),
        GenerationResult.UNAUTHORIZED: ({"success": False}, 403),
        GenerationResult.UNAUTHENTICATED: ({"success": False}, 401),
        GenerationResult.NO_PERMS: ({"success": False, "message": GenerationResult.NO_PERMS.value}, 200),
        GenerationResult.FAILURE: ({"success": False, "message": "token_not_found"}, 404),
    }.get(result[0], {"success": False, "message": result[0].value, "problem_perms": result[1]})


@app.route('/tokens/regenerate')
def tokens_regenerate():
    if "token" not in request.args:
        return {}, 401
    result, new_token = the_app.auth.token_regenerate(request.args["token"])
    # If token valid, it is regenerated
    if result == GenerationResult.SUCCESS:
        return {"success": True, "new_token": new_token}, 200
    # No valid token provided, failure
    else:
        return {"success": False}, 403


@app.route('/tokens', methods=["DELETE"])
def tokens_delete():
    # Authenticating
    is_auth = auth_token(request.args, "tokens.delete")
    if not is_auth:
        return {}, 401
    # Deleting, returning if token found
    if the_app.database.token_delete(request.args["token_other"]):
        return {}, 200
    else:
        return {}, 404
