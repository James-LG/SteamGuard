"""
Utility classes that don't belong anywhere else.
"""
import time
import json

import requests

class APIEndpoints():
    #A series of URL constants
    steam_api_base = "https://api.steampowered.com"
    community_base = "https://steamcommunity.com"
    mobile_auth_base = steam_api_base + "/IMobileAuthService/%s/v0001"
    mobile_auth_get_wg_token = mobile_auth_base.replace("%s", "GetWGToken")
    two_factor_base = steam_api_base + "/ITwoFactorService/%s/v0001"
    two_factor_time_query = two_factor_base.replace("%s", "QueryTime")

class TimeAlign():
    """ Align local time to Steam's server times and store is statically. """
    difference = 0
    aligned = False

    @classmethod
    def get_time(cls):
        """ Public function to get the time accounting for the local time difference to Steam's servers. """
        if not cls.aligned:
            cls.align()
        return time.time() + cls.difference

    @classmethod
    def align(cls):
        """ Gets the time difference between local and Steam. """
        current = time.time()
        response = requests.post(APIEndpoints.two_factor_time_query, data="steamid=0")
        try:
            query = json.loads(response.text)
            cls.difference = int(query['response']['server_time']) - current
            cls.aligned = True
        except json.decoder.JSONDecodeError:
            print("align failed")
            print(response.text)

