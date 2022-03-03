import sys

import configuration
import pwdgen
from database import JsonDatabase
from hibprequester import pwd_pwned
from usermanager import UserManager, ValidationResult, ChangePasswordResult, InsertionResult


def _user_register(app_name: str, args=()):
    # Loading users
    user_manager = UserManager(JsonDatabase("db.json"), configuration.config_load_from_file("config.json"))
    # Checking amount of arguments
    if len(args) != 3:
        # Printing syntax
        print(f"Syntax: {app_name} user register <user> <appId> <pwd>")
        return
    result, broken_rules = user_manager.user_insert(args[0], args[1], args[2])
    if result == InsertionResult.SUCCESS:
        print("User inserted!")
    elif result == InsertionResult.USER_ALREADY_REGISTERED:
        print("User already in Database!")
    else:
        print("User found, password is not matching criteria.\nrule | count | expected"
              + "".join(f"\n{rule[0]} : {rule[1][0]} : {rule[1][1]}" for rule in broken_rules.items()))


def _user_validate(app_name: str, args=()):
    # Loading users
    user_manager = UserManager(JsonDatabase("db.json"), configuration.config_load_from_file("config.json"))
    # Checking amount of arguments
    if len(args) != 3:
        # Printing syntax
        print(f"Syntax: {app_name} user validate <user> <appId> <pwd>")
        return
    result, broken_rules = user_manager.user_validate(args[0], args[1], args[2])
    if result == ValidationResult.VALID_BUT_NOT_POLICY:
        # Password not matching criteria
        print("User found, credentials correct, but password is not matching criteria.\nrule | count | expected"
              + "".join(f"\n{rule[0]} : {rule[1][0]} : {rule[1][1]}" for rule in broken_rules.items()))
    else:
        print({
                  ValidationResult.VALID: "User found, and credentials are correct.",
                  ValidationResult.USER_NOT_FOUND: "User not found.",
                  ValidationResult.NOT_VALID: "User found, but false credentials."
              }[result])


def _user_changepwd(app_name: str, args=()):
    # Loading users
    user_manager = UserManager(JsonDatabase("db.json"), configuration.config_load_from_file("config.json"))
    # Checking amount of arguments
    if len(args) < 3:
        # Printing syntax
        print(f"Syntax: {app_name} user changepwd <user> <appId> <pwd> [old_pwd]")
        return
    # Try to change password
    result, broken_rules = user_manager.user_change_password(args[0], args[1], args[2], None if len(args) < 4 else args[3])
    if result == ChangePasswordResult.PASSWORD_INVALID:
        # Password not matching criteria
        print("User found, password is not matching criteria.\nrule | count | expected"
              + "".join(f"\n{rule[0]} : {rule[1][0]} : {rule[1][1]}" for rule in broken_rules.items()))
    else:
        print({
                  ChangePasswordResult.SUCCESS: "Password changed.",
                  ChangePasswordResult.USER_NOT_FOUND: "User not found.",
                  ChangePasswordResult.WRONG_PASSWORD: "User found, but wrong old password.",
              }[result])


def _user_delete(app_name: str, args=()):
    # Loading users
    user_manager = UserManager(JsonDatabase("db.json"), configuration.config_load_from_file("config.json"))
    # Checking amount of arguments
    if len(args) == 0:
        # Printing syntax
        print(f"Syntax: {app_name} user delete <user> [appId]")
    # Deleting user, returning success
    result = user_manager.user_delete(args[0], None if len(args) < 2 else args[1])
    if not result:
        print("User not found.")
    else:
        print("User deleted." if len(args) > 1 else "All users with given username were deleted.")


def _generate_pwd(app_name: str, args=()):
    batch = 1
    file = None
    check_hibp = False
    i = 0
    # Loop equivalent of for(i = 0; i < len(args); i++)
    while i < len(args):
        # If -o was found
        if args[i] == "-o":
            # trying to check if filename was specified
            if len(args) > i + 1:
                # Specified
                i += 1
                file = args[i]
            else:
                # Not specified, printing syntax
                print("Please provide a path for the file (option \"-o\" detected).")
                print(f"Syntax: {app_name} password generate [--batch N] [-o file.txt]")
                exit(0)
        # If --batch was found
        elif args[i] == "--batch":
            # trying to check if batch amount was specified
            if len(args) > i + 1:
                # Specified
                i += 1
                batch = int(args[i])
            else:
                # Not specified, printing syntax
                print("Please provide a number for the batch parameter (option \"--batch\" detected).")
                print(f"Syntax: {app_name} password generate [--batch N] [-o file.txt]")
                exit(0)
        # If --check-hibp was found
        elif args[i] == "--check-hipb":
            check_hibp = True
        else:
            # Option not identified, printing syntax
            print(f"Option \"{args[i]}\" not recognized!")
            print(f"Syntax: {app_name} password generate [--batch N] [-o file.txt]")
            exit(0)
        i += 1
    # Loading policy
    policy = configuration.config_load_from_file("config.json").policy
    # Generating a list of passwords, batch is >=1
    pwds = [pwdgen.generate(policy, check_hibp) for _ in range(max(1, batch))]
    if file is None:
        # If no file was specified
        for pwd in pwds:
            print(pwd)
    else:
        # If a filename was given, writing in it
        with open(file, "w", encoding="utf-8") as f:
            for pwd in pwds:
                f.write(pwd + '\n')


def _validate_pwd(app_name: str, args=()):
    # Loading config
    config = configuration.config_load_from_file("config.json")
    # Checking amount of arguments
    if len(args) == 0:
        # Printing syntax
        print("Please provide a password to test on.")
        print(f"Syntax: {app_name} password validate <password>")
    else:
        # Validating password
        valid, broken_rules = config.policy.validate(args[0])
        if valid:
            print("Password valid!")
        else:
            print("Password not valid! Broken rules:")
            print("rule | count | expected")
            # Printing broken rules
            for rule in broken_rules.items():
                print(f"{rule[0]} : {rule[1][0]} : {rule[1][1]}")


def _pwned(app_name: str, args=()):
    # Checking amount of arguments
    if len(args) == 0:
        # Printing syntax
        print(f"Please provide a password to test.\nSyntax: {app_name} pwned <pwd>")
    else:
        # Checking on hibp then returning amount
        amount = pwd_pwned(args[0])
        if amount == 0:
            print("Provided password was not found on HIBP.")
        else:
            print(f"Password was pwned! Found in {amount} breach(es)!")


def _send_help(app_name: str, args=()):
    print(f"""Syntax:
{app_name} user register  <user> <appId> <pwd>
{app_name} user validate  <user> <appId> <pwd>
{app_name} user changepwd <user> <appId> <pwd>
{app_name} user delete    <user> [appId]

{app_name} password generate [--batch N] [-o file.txt] [--check-hipb]
{app_name} password validate <password>
{app_name} pwned <pwd>""")


if __name__ == '__main__':
    # If no arguments were given
    if len(sys.argv) == 1:
        _send_help(sys.argv[0])
    else:
        # Setting up command tree
        funcs = {
            "user": {
                "register": _user_register,
                "validate": _user_validate,
                "changepwd": _user_changepwd,
                "delete": _user_delete
            },
            "password": {
                "generate": _generate_pwd,
                "validate": _validate_pwd
            },
            "pwned": _pwned
        }
        # Get route or default
        route = funcs.get(sys.argv[1], _send_help)
        # If it's a dict, so searching subcommands
        if isinstance(route, dict):
            # The amount of args is min. 3 (script name + args)
            if len(sys.argv) < 3:
                # Send help when less
                _send_help(sys.argv[0])
            else:
                # Execute command
                route.get(sys.argv[2], _send_help)(sys.argv[0], sys.argv[3:])
        else:
            route(sys.argv[0], sys.argv[2:])
