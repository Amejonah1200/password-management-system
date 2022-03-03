import json
import os
from typing import Optional, List, Union
from uuid import UUID


class User:
    def __init__(self, name, pwd: bytes, appId):
        super().__init__()
        self.username: str = name
        self.pwd: bytes = pwd
        self.appId: str = appId

    def __str__(self):
        return f"User({self.username}, {self.pwd}, {self.appId})"


class Token:
    def __init__(self, token: Union[str, UUID], perms: List[str]):
        self.token: str = str(token)
        self.perms = perms

    def __str__(self):
        return f"Token({str(self.token)}, {self.perms})"


class Database:
    """
    A Database class to implement the "abstract" methods.
    In Java this would be an interface.
    """

    def user_registered(self, username, appId) -> bool:
        raise NotImplementedError("user_registered")

    def user_create(self, username, pwd: bytes, appId) -> bool:
        raise NotImplementedError("user_create")

    def user_delete(self, username, appId) -> bool:
        raise NotImplementedError("user_delete")

    def user_delete_all(self, username: str) -> bool:
        raise NotImplementedError("user_delete_all")

    def user_change_password(self, username, pwd: bytes, appId) -> bool:
        raise NotImplementedError("user_change_password")

    def user_get(self, username, appId) -> Optional[User]:
        raise NotImplementedError("user_get")

    def user_get_all(self, username) -> list:
        raise NotImplementedError("user_get_all")

    def token_insert(self, token: str, perms: List[str]) -> bool:
        raise NotImplementedError("token_insert")

    def token_get(self, token: str) -> Optional[Token]:
        raise NotImplementedError("token_permissions_get")

    def token_permissions_set(self, token: str, perms: List[str]) -> bool:
        raise NotImplementedError("token_permissions_set")

    def token_delete(self, token: str) -> bool:
        raise NotImplementedError("token_delete")


class InMemoryDatabase(Database):
    """
    An implementation of the Database class for testing and development.
    The data ist stored only in memory.
    """

    def __init__(self):
        self.users = list()
        self.tokens = {}

    def user_registered(self, username, appId) -> bool:
        # Iterating over the users and returning if one was found
        for user in self.users:
            if user.username == username and user.appId == appId:
                return True
        return False

    def user_create(self, username, pwd: bytes, appId) -> bool:
        # Appending user if user not registered and return true on success
        if not self.user_registered(username, appId):
            self.users.append(User(username, pwd, appId))
            return True
        return False

    def user_delete(self, username, appId=None) -> bool:
        # Executing alias if appId was not provided
        if appId is None:
            return self.user_delete_all(username)
        # Iterating over a copy of the users list
        for user in self.users[:]:
            if user.username == username and user.appId == appId:
                # Removing the user if found in the real list
                self.users.remove(user)
                # Returning deletion success
                return True
        return False

    def user_delete_all(self, username) -> bool:
        result = False
        # Iterating over a copy of the users list
        for user in self.users[:]:
            if user.username == username:
                # Removing the user if found in the real list
                self.users.remove(user)
                # Setting success to the result, not returning,
                # because there are possibly another user account
                result = True
        return result

    def user_change_password(self, username, pwd: bytes, appId) -> bool:
        # Iterating over the users and changing password, then returning
        for user in self.users:
            if user.username == username and user.appId == appId:
                user.pwd = pwd
                return True
        return False

    def user_get(self, username, appId) -> Optional[User]:
        # Iterating over the users, returning one when found
        for user in self.users:
            if user.username == username and user.appId == appId:
                return user
        return None

    def user_get_all(self, username) -> list:
        userlist = []
        # Iterating over the users
        for user in self.users:
            if user.username == username:
                # Appending user if username matches
                userlist.append(user)
        return userlist

    def token_insert(self, token: str, perms: List[str]) -> bool:
        # Checking if token not registered
        if token not in self.tokens:
            # Register token
            self.tokens[token] = perms
            # Returning success
            return True
        else:
            return False

    def token_get(self, token: str) -> Optional[Token]:
        # This is an important part, this allows to have an virtual token which is not in the database
        # It exists only if there are no tokens at all
        if token == "adminadm-inad-mina-dminadminadminad" and len(self.tokens) == 0:
            return Token("adminadm-inad-mina-dminadminadminad", list())
        # Checking if the token is registered and return if found
        if token in self.tokens:
            return Token(token, self.tokens[token])
        else:
            return None

    def token_permissions_set(self, token: str, perms: List[str]) -> bool:
        # Checking if token registered
        if token in self.tokens:
            # Replacing perms
            self.tokens[token] = perms
            return True
        else:
            return False

    def token_delete(self, token: str) -> bool:
        # You cannot delete an virtual token
        if token == "adminadm-inad-mina-dminadminadminad" and token not in self.tokens:
            return True
        # Removing only the token if it's registered
        if token in self.tokens:
            del self.tokens[token]
            # Returning success
            return True
        return False


class JsonDatabase(InMemoryDatabase):

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self.load()

    def load(self):
        # If the file is not existent, creating one
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                # Writing default json
                json.dump({"users": [], "tokens": {}}, f)
        # Opening the file (again)
        with open(self.path, "r", encoding="utf-8") as f:
            # Reading json
            json_obj = json.load(f)
            # Mapping every user (in the json array) to a an User object, creating a list
            self.users = [User(user["username"], user["pwd"].encode(), user["appId"]) for user in json_obj["users"]]
            # Loading every token using it's key (which is the token itself)
            for token, perms in json_obj["tokens"].items():
                self.tokens[token] = perms

    def save(self):
        # Opening the file
        with open(self.path, "w", encoding="utf-8") as f:
            # Creating the json
            json.dump({"tokens": self.tokens,  # Setting tokens
                       "users": [{  # Mapping for every User as a dict
                           "username": user.username,
                           "pwd": user.pwd.decode(),
                           "appId": user.appId
                       } for user in self.users]}, f)

    def user_create(self, username, pwd: bytes, appId) -> bool:
        # Making the action, saving on success and returning the result
        if super().user_create(username, pwd, appId):
            self.save()
            return True
        else:
            return False

    def user_delete(self, username, appId=None) -> bool:
        # Making the action, saving on success and returning the result
        if super().user_delete(username, appId):
            self.save()
            return True
        else:
            return False

    def user_delete_all(self, username: str) -> bool:
        # Making the action, saving on success and returning the result
        if super().user_delete_all(username):
            self.save()
            return True
        else:
            return False

    def user_change_password(self, username, pwd: bytes, appId) -> bool:
        # Making the action, saving on success and returning the result
        if super().user_change_password(username, pwd, appId):
            self.save()
            return True
        else:
            return False

    def token_insert(self, token: str, perms: List[str]) -> bool:
        # Making the action, saving on success and returning the result
        if super().token_insert(token, perms):
            self.save()
            return True
        else:
            return False

    def token_permissions_set(self, token: str, perms: List[str]) -> bool:
        # Making the action, saving on success and returning the result
        if super().token_permissions_set(token, perms):
            self.save()
            return True
        else:
            return False

    def token_delete(self, token: str) -> bool:
        # Making the action, saving on success and returning the result
        if super().token_delete(token):
            self.save()
            return True
        else:
            return False
