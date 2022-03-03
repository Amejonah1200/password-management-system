import enum
from typing import Optional, Tuple, Dict

from database import User, Database
from configuration import Configuration


class ValidationResult(enum.Enum):
    VALID = "valid"
    NOT_VALID = "not_valid"
    VALID_BUT_NOT_POLICY = "policy_not_valid"
    USER_NOT_FOUND = "user_not_found"


class ChangePasswordResult(enum.Enum):
    SUCCESS = "success"
    WRONG_PASSWORD = "wrong_password"
    PASSWORD_INVALID = "password_invalid"
    USER_NOT_FOUND = "user_not_found"


class InsertionResult(enum.Enum):
    SUCCESS = "success"
    PASSWORD_INVALID = "password_invalid"
    USER_ALREADY_REGISTERED = "user_already_registered"


class UserManager:
    def __init__(self, database: Database, config: Configuration):
        self.database = database
        self.config = config

    def user_insert(self, username, pwd: str, appId: str, validate: bool = True) -> Tuple[InsertionResult, Optional[Dict[str, Tuple[int, int]]]]:
        # If validation should be performed, perform.
        if validate:
            valid, broken_rules = self.config.policy.validate(pwd)
            # On not valid password, return broken rules
            if not valid:
                return InsertionResult.PASSWORD_INVALID, broken_rules
        # Hashing and adding to Database, return if this operation succeeded
        if self.database.user_create(username, self.config.hashing.hasher.hash(pwd.encode()), appId):
            return InsertionResult.SUCCESS, None
        else:
            return InsertionResult.USER_ALREADY_REGISTERED, None

    def user_delete(self, username, appId=None) -> bool:
        if appId is None:
            # Executing alias
            return self.database.user_delete_all(username)
        # Deleting user account
        return self.database.user_delete(username, appId)

    def user_delete_all(self, username):
        # Deleting all user with given usernames and returning success
        return self.database.user_delete_all(username)

    def user_validate(self, username, password: str, appId, rehash: bool = True) -> (ValidationResult, Optional[list]):
        # Getting user
        user = self.database.user_get(username, appId)
        # If no user was found
        if user is None:
            return ValidationResult.USER_NOT_FOUND, None
        # Checking password
        if not self.config.hashing.hasher.check_hash(password.encode(), user.pwd):
            return ValidationResult.NOT_VALID, None
        # Rehashing if needed
        if rehash and self.config.hashing.hasher.needs_rehash(user.pwd):
            # Just setting same password
            self.user_change_password(username, password, appId)
        # Validating password for criteria
        validation = self.config.policy.validate(password)
        # If not valid for policy
        if not validation[0]:
            return ValidationResult.VALID_BUT_NOT_POLICY, validation[1]
        return ValidationResult.VALID, None

    def user_change_password(self, username, pwd: str, appId, old_pwd: str = None, validate: bool = True) \
            -> Tuple[ChangePasswordResult, Optional[Dict[str, Tuple[int, int]]]]:
        # Getting user
        user = self.database.user_get(username, appId)
        # If no user was found
        if user is None:
            return ChangePasswordResult.USER_NOT_FOUND, None
        # If old_password was provided, check it and on failure return
        if old_pwd is not None and not self.config.hashing.hasher.check_hash(old_pwd.encode(), user.pwd):
            return ChangePasswordResult.WRONG_PASSWORD, None
            # If validation should be performed, perform.
        if validate:
            valid, broken_rules = self.config.policy.validate(pwd)
            # On not valid password, return broken rules
            if not valid:
                return ChangePasswordResult.PASSWORD_INVALID, broken_rules
        # Changing password in database
        self.database.user_change_password(username, self.config.hashing.hasher.hash(pwd.encode()), appId)
        return ChangePasswordResult.SUCCESS, None

    def user_get(self, username, appId) -> Optional[User]:
        return self.database.user_get(username, appId)

    def user_get_all(self, username: str) -> list:
        """
        Getting all users which matches given username
        :param username: username to search with
        :return: User when found, or else None
        """
        return self.database.user_get_all(username)
