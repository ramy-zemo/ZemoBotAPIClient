import jwt
from requests.models import Request, Response
from requests import request
from dataclasses import dataclass
from config import API_URL, JWT_SECRET


class ClientCreationError(Exception):
    """Raised when neither username and password or API key are passed to Client constructor.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message
        super().__init__(message)


class AuthenticationError(Exception):
    """Raised when neither username or password for the API are invalid."""

    def __init__(self):
        super().__init__("Invalid username or password.")


class RequestCreationError(Exception):
    """Raised when Request creation fails.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        super().__init__("Error creating request.\n" + message)


class EndpointException(Exception):
    """Raised when an invalid endpoint is passed."""

    def __init__(self):
        super().__init__("Invalid endpoint passed.\nTo get a list of valid endpoints, use Client.endpoints()")


@dataclass
class Endpoint:
    url: str
    method: str

    def __repr__(self):
        return self.url


class ZemoBotApiClient:
    def __init__(self, username: str = "", password: str = "", API_KEY: str = ""):
        self.base_api_url = API_URL
        self.JWT_SECRET = JWT_SECRET

        # Declaring endpoints
        # Authentication
        self.create_user = Endpoint("/auth/create_user", "POST")
        self.create_admin = Endpoint("/auth/create_admin", "POST")
        self.get_all_users = Endpoint("/auth/get_all_users", "GET")
        self.generate_token = Endpoint("/auth/generate_token", "GET")
        self.delete_user = Endpoint("/auth/delete_user", "DELETE")

        # Admin commands
        self.create_admin_command = Endpoint("/admin_commands/create_admin_command", "POST")
        self.get_all_admin_commands = Endpoint("/admin_commands/get_all_admin_commands", "GET")
        self.delete_admin_command = Endpoint("/admin_commands/delete_admin_command", "DELETE")

        # Command categories
        self.get_all_guild_categories = Endpoint("/command_categories/get_all_guild_categories", "GET")

        # Commands
        self.create_command = Endpoint("/commands/create_command", "POST")
        self.get_all_guild_commands_and_category = Endpoint("/commands/get_all_guild_commands_and_category", "GET")
        self.get_all_guild_commands_from_category = Endpoint("/commands/get_all_guild_commands_from_category", "GET")
        self.delete_command = Endpoint("/commands/delete_command", "DELETE")

        # Disabled commands
        self.disable_command = Endpoint("/disabled_commands/disable_command", "POST")
        self.enable_command = Endpoint("/disabled_commands/enable_command", "POST")
        self.check_command_status_for_guild = Endpoint("/disabled_commands/check_command_status_for_guild", "GET")
        self.get_all_disabled_commands_from_guild = Endpoint("/disabled_commands/get_all_disabled_commands_from_guild",
                                                             "GET")

        # Invites
        self.log_invite = Endpoint("/invites/log_invite", "POST")
        self.get_invites_to_user = Endpoint("/invites/get_invites_to_user", "GET")
        self.get_user_invites = Endpoint("/invites/get_user_invites", "GET")

        # Level
        self.add_user_xp = Endpoint("/level/add_user_xp", "POST")
        self.get_server_ranks = Endpoint("/level/get_server_ranks", "GET")
        self.get_xp_from_user = Endpoint("/level/get_xp_from_user", "GET")

        # Messages
        self.log_message = Endpoint("/messages/log_message", "POST")
        self.get_user_messages = Endpoint("/messages/get_user_messages", "GET")

        # Config
        self.activate_guild = Endpoint("/config/activate_guild", "POST")
        self.deactivate_guild = Endpoint("/config/deactivate_guild", "POST")
        self.change_prefix = Endpoint("/config/change_prefix", "POST")
        self.setup_config = Endpoint("/config/setup_config", "POST")
        self.change_msg_welcome_channel = Endpoint("/config/change_msg_welcome_channel", "POST")
        self.update_twitch_username = Endpoint("/config/update_twitch_username", "POST")
        self.change_auto_role = Endpoint("/config/change_auto_role", "POST")
        self.change_welcome_message = Endpoint("/config/change_welcome_message", "POST")
        self.get_prefix = Endpoint("/config/get_prefix", "GET")
        self.check_server_status = Endpoint("/config/check_server_status", "GET")
        self.get_all_twitch_data = Endpoint("/config/get_all_twitch_data", "GET")
        self.get_twitch_username = Endpoint("/config/get_twitch_username", "GET")
        self.get_welcome_role_id = Endpoint("/config/get_welcome_role_id", "GET")
        self.get_welcome_message = Endpoint("/config/get_welcome_message", "GET")
        self.delete_all_configs = Endpoint("/config/delete_all_configs", "DELETE")

        # Trashtalk
        self.add_trashtalk = Endpoint("/trashtalk/add_trashtalk", "POST")
        self.get_trashtalk = Endpoint("/trashtalk/get_trashtalk", "GET")

        # Trashtalk log
        self.reset_user_trashtalk = Endpoint("/trashtalk_log/reset_user_trashtalk", "POST")
        self.log_trashtalk = Endpoint("/trashtalk_log/log_trashtalk", "POST")
        self.get_user_trashtalk = Endpoint("/trashtalk_log/get_user_trashtalk", "GET")

        # Voice
        self.add_user_voice_time = Endpoint("/voice/add_user_voice_time", "POST")
        self.get_user_voice_time = Endpoint("/voice/get_user_voice_time", "GET")

        if username == "" and password == "" and API_KEY == "":
            error = "You must pass either a username and password or an API key when creating the client."
            raise ClientCreationError(error)

        elif API_KEY:
            assert self.validate_api_key(API_KEY)
            self.API_KEY = API_KEY

        else:
            self.API_KEY = self.get_api_key(username, password)

    def validate_api_key(self, API_KEY: str) -> bool:
        """Validates passed API keys by decoding them and trying to generate now API key."""
        decoded_key = jwt.decode(API_KEY, self.JWT_SECRET, algorithms=['HS256'])
        self.get_api_key(decoded_key["username"], decoded_key["password_hash"])

        return True

    def get_api_key(self, username: str, password: str) -> str:
        """Generates API KEY by passing username and password to the API"""
        generate_token_params = {"username": username, "password": password}

        request_object = Request(self.generate_token.method, url=self.generate_token.url, params=generate_token_params)
        result = self.send_request(request_object)

        try:
            api_key = result["Token"]
        except:
            raise AuthenticationError()

        return api_key

    def send_request(self, request_to_send: Request):
        """This is a request handler which makes a request based on the request input."""
        if request_to_send.url in [x.url for x in self.__dict__.values() if hasattr(x, "url")]:
            if hasattr(self, "API_KEY"):
                request_to_send.params["API_Key"] = self.API_KEY

            response = request(request_to_send.method, self.base_api_url + request_to_send.url,
                               headers=request_to_send.headers, params=request_to_send.params)
            try:
                return response.json()
            except:
                return response.content.decode()

        else:
            raise EndpointException()

    def request(self, endpoint: Endpoint, headers: dict = {}, params: dict = {}):
        """Create request based on endpoint, headers and url params & make the request."""
        request_to_send = Request(endpoint.method, endpoint.url, headers=headers, params=params)
        response = self.send_request(request_to_send)

        return response

    def endpoints(self) -> list:
        """DebugCommand to get a list of all available endpoints."""
        return [endpoint for endpoint in self.__dict__.values() if isinstance(endpoint, Endpoint)]
