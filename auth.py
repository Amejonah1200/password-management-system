import uuid
from enum import Enum
from typing import List, Optional, Union

import configuration
from database import Database, Token

all_perms = [
    "users.create",
    "users.validate",
    "users.change_pw",
    "users.delete",
    "tokens.create",
    "tokens.permissions.set",
    "tokens.delete",
    "settings.get",
    "settings.set"
]


class GenerationResult(Enum):
    SUCCESS = "success"
    UNAUTHORIZED = "unauthorized"
    UNAUTHENTICATED = "unauthenticated"
    NO_PERMS = "other_token_has_no_perms"
    UNAUTHORIZED_PERMS = "other_token_has_foreign_perms"
    UNKNOWN_PERMS = "other_token_has_unknown_perms"
    FAILURE = "failure"


class Authenticator:
    def __init__(self, database: Database, config: configuration.Configuration):
        self.config = config
        self.database = database

    def token_auth(self, token, permission) -> bool:
        # If auth is deactivated, everyone is authenticated
        if not self.config.auth:
            return True
        # Getting token
        token = self.token_get(token)
        # If no token was found, not authenticated
        if token is None:
            return False
        # If token was found, verifying permissions
        else:
            return permission in token.perms

    def token_generate(self, auth_token: str, perms: List[str]) -> (GenerationResult, Optional[Union[Token, List[str]]]):
        # Getting token
        auth_token = self.token_get(auth_token)
        # Checking permissions
        check_result = check_perms(auth_token, "tokens.create", perms) if self.config.auth else (GenerationResult.SUCCESS, None)
        # Not authenticated, not authorized...
        if check_result[0] != GenerationResult.SUCCESS:
            return check_result
        # Generating token
        token = Token(uuid.uuid4(), perms)
        # Inserting
        self.database.token_insert(token.token, token.perms)
        # Returning success
        return GenerationResult.SUCCESS, token

    def token_regenerate(self, token: str) -> (GenerationResult, Optional[str]):
        # Getting token
        token = self.token_get(token)
        # No valid token provided
        if token is None:
            return GenerationResult.UNAUTHORIZED, None
        # Deleting token
        self.database.token_delete(token.token)
        # Setting new token
        token.token = str(uuid.uuid4())
        # Inserting token
        self.database.token_insert(token.token, token.perms)
        return GenerationResult.SUCCESS, token.token

    def token_set_perms(self, auth_token: str, token: str, perms: List[str]) -> (GenerationResult, Optional[List[str]]):
        # Getting token
        auth_token = self.token_get(auth_token)
        # Checking permissions
        check_result = check_perms(auth_token, "tokens.permissions.set", perms) if self.config.auth else (GenerationResult.SUCCESS, None)
        # No permission
        if check_result[0] != GenerationResult.SUCCESS:
            return check_result
        # Setting permission
        if self.database.token_permissions_set(token, perms):
            return GenerationResult.SUCCESS, None
        else:
            return GenerationResult.FAILURE, None

    def token_get(self, token: str) -> Optional[Token]:
        # Getting token
        token = self.database.token_get(token)
        # If it's the default token, set all perms
        if token is not None and token.token == "adminadm-inad-mina-dminadminadminad":
            token.perms = all_perms
        return token


def check_perms(token: Token, perm: str, perms: List[str]) -> (GenerationResult, Optional[List[str]]):
    # No token provided
    if token is None:
        return GenerationResult.UNAUTHENTICATED, None
    # If it has the permission needed
    if perm not in token.perms:
        return GenerationResult.UNAUTHORIZED, None
    # A token with no permissions is useless
    if len(perms) == 0:
        return GenerationResult.NO_PERMS, None
    unauthorized_perms = []
    unknown_perms = []
    for perm in perms:
        # is perm unknown?
        if perm not in all_perms:
            unknown_perms.append(perm)
        # is perm not authorized for the token which makes taht action
        elif perm not in token.perms:
            unauthorized_perms.append(perm)
    # Unknown perms were found
    if len(unknown_perms) > 0:
        return GenerationResult.UNKNOWN_PERMS, unknown_perms
    # Unauthorized perms were found
    if len(unauthorized_perms) > 0:
        return GenerationResult.UNAUTHORIZED_PERMS, unauthorized_perms
    else:
        # All went good
        return GenerationResult.SUCCESS, None
