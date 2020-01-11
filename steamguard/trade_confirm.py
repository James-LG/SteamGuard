'''
Created on May 14, 2016

@author: Tygon
'''

import base64
import hashlib
import hmac
import http
import json
import re
import time
import urllib

from enum import Enum

import rsa

import requests

from .util import APIEndpoints, TimeAlign
from .guard_code import get_code


class LoginResult(Enum):
    #Login constants
    LOGIN_OK = 1
    BAD_CREDENTIALS = 2
    NEED_CAPTCHA = 3
    NEED_EMAIL = 4
    NEED_2FA = 5
    TOO_MANY_LOGINS = 6
    GENERAL_FAILURE = 7
    BAD_RSA = 8

def confirm(account):
    login = UserLogin(account.username,account.password,account.shared)
    response = None
    while (True):
        response = login.do_login()

        if response == LoginResult.LOGIN_OK:
            print("success")
            break

        elif response == LoginResult.NEED_EMAIL:
            email = input("Please enter your email: ")
            login.email_code = email

        elif response == LoginResult.NEED_CAPTCHA:
            print(APIEndpoints.community_base + "/public/captcha.php?gid=" + login.captcha_gid)
            captcha = input("Please enter captcha: ")
            login.captcha_text = captcha

        elif response == LoginResult.NEED_2FA:
            print("code error,waiting 30 sec")
            time.sleep(30)

        else:
            print("unknown error",response)
            input("press to continue")
        
    steam_account = SteamGuardAccount(account.shared,account.identity,account.device_id,login.session)
    confs = None
    for i in range(0,2): #@UnusedVariable
        try:
            confs = steam_account.fetch_confirmations()
            break
        except ValueError:
            time.sleep(5)
            continue
    if confs:
        for conf in confs:
            steam_account.accept_confirmation(conf)

#SessionData
class SessionData():
    def __init__(self):
        self.session_id = None
        self.steam_login = None
        self.steam_login_secure = None
        self.web_cookie = None
        self.oauth_token = None
        self.steam_id = None
    #Returns a list of dictionaries comprising of cookies to login to Steam
    def add_cookies(self,cookies):
        cookies.append({"name":"mobileClientVersion","value":"0 (2.1.3)","path":"/","domain":".steamcommunity.com","secure":False})
        cookies.append({"name":"mobileClient","value":"android","path":"/","domain":".steamcommunity.com","secure":False})
        cookies.append({"name":"steamid","value":self.steam_id,"path":"/","domain":".steamcommunity.com","secure":False})
        cookies.append({"name":"steamLogin","value":self.steam_login,"path":"/","domain":".steamcommunity.com","secure":False})
        cookies.append({"name":"steamLoginSecure","value":self.steam_login_secure,"path":"/","domain":".steamcommunity.com","secure":True})
        cookies.append({"name":"Steam_Language","value":"english","path":"/","domain":".steamcommunity.com","secure":False})
        cookies.append({"name":"dob","value":"","path":"/","domain":".steamcommunity.com","secure":False})
        cookies.append({"name":"sessionid","value":self.session_id,"path":"/","domain":".steamcommunity.com","secure":False})
        return cookies
    
#SteamWeb
#Function simply to call a Request() but with preset values. Like a constant for a function
def mobile_login_request(url,method,data=None,cookies=None,headers=None):
    return request(url,method,data,cookies,headers,APIEndpoints.community_base+"/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client")

#Actually send data to the Steam servers
def request(url,method,data=None,cookies=None,headers=None,referer=APIEndpoints.community_base):
    if (data == None):
        query = ""
    else:
        #Essentially turns a dictionary into a url safe query string. ex. username=fred&password=nope
        array = []
        for key,value in data.items():
            print(key,value)
            temp = urllib.parse.quote(key,safe='')+"="
            if type(value) is float:
                temp += urllib.parse.quote(str(round(value)),safe='')
            elif value is not None:
                temp += urllib.parse.quote(value,safe='')
            array.append(temp)
        s = "&"
        query = s.join(array)

    if (method == "GET"):
        #Append query to url
        if ("?" in url):
            url += "&"+query
        else:
            url += "?"+query
            
    session = requests.Session()
    #Headers to impersonate an Android device
    headers = {"user-agent":"Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
               'accept':"text/javascript, text/html, application/xml, text/xml, */*",
               'referer':referer}
    
    #Add extra headers if post
    if (method == "POST"):
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        headers["Content-Length"] = str(len(query))
        
    #Turn the inputted cookies dictionary into an actual cookiejar used to send the request
    jar = http.cookiejar.CookieJar()
    for cookie_dict in cookies:
        cookie = http.cookiejar.Cookie(version=0,
                                       name=cookie_dict['name'],
                                       value=cookie_dict['value'],
                                       port=None,
                                       port_specified=False,
                                       domain=cookie_dict['domain'],
                                       domain_specified=True,
                                       domain_initial_dot=True,
                                       path=cookie_dict['path'],
                                       path_specified=True,
                                       secure=cookie_dict['secure'],
                                       expires=None,
                                       discard=True,
                                       comment=None,
                                       comment_url=None,
                                       rest=None)
        jar.set_cookie(cookie)
    #Send the request and set the response
    response = session.post(url,data=query,headers=headers,cookies=jar)
    
    return response
    
    
#UserLogin
class LoginResponse():
    def __init__(self,j):
        #Load the object from a json text
        self.__dict__ = json.loads(j)
        
        #If the json was missing info, add blank attributes
        if not hasattr(self,'captcha_needed'):
            self.captcha_needed = False
        if not hasattr(self,'emailauth_needed'):
            self.emailauth_needed = False
        if not hasattr(self,'message'):
            self.message = None
        if not hasattr(self,'oauth'):
            self.oauth = None
        if self.oauth != None:
            self.oauth = json.loads(self.oauth)

class UserLogin():
    
    def __init__(self,username,password,shared_secret):
        self.username = username
        self.password = password
        self.logged_in = False
        self.cookies = None
        self.twofactorcode = ""
        self.requires_captcha = False
        self.requires_email = False
        self.requires_2fa = False
        self.steam_id = None
        self.session = None
        self.shared_secret = shared_secret
        
    #Login to the authenticator and get the cookies required to continue
    def do_login(self):
        cookies = self.cookies
        #If object's cookies are blank, add some basic ones
        if (cookies == None):
            cookies = [{"name":"mobileClientVersion","value":"0 (2.1.3)","path":"/","domain":".steamcommunity.com","secure":False},
                       {"name":"mobileClient","value":"android","path":"/","domain":".steamcommunity.com","secure":False},
                       {"name":"Steam_Language","value":"english","path":"/","domain":".steamcommunity.com","secure":False}]
            
            headers = {"X-Requested-With":"com.valvesoftware.android.steam.community"}
            
            #Get the sessionID from steam
            response_data = mobile_login_request("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client", "GET", None, cookies, headers)

            session_id = response_data.cookies['sessionid']
        
        #Get the rsa modulus and exponent for the username provided
        post_data = {"username":self.username}
        response_data = mobile_login_request(APIEndpoints.community_base + "/login/getrsakey", "POST", post_data, cookies)
        response = response_data.text
        if (response == None or "<BODY>\nAn error occurred while processing your request." in response):
            return LoginResult.GENERAL_FAILURE
        
        if (not response['success']):
            return LoginResult.BAD_RSA
        
        #Encrypt the password using RSA
        #Encode password to bytes
        password_bytes = self.password.encode(encoding='ASCII')
        
        #Turn keys to hexidecimal
        exponent = int(response['publickey_exp'],16)
        modulus = int(response['publickey_mod'],16)
        
        #Create an RSA key using the modulus and exponent
        pub_key = rsa.PublicKey(modulus,exponent)
        
        #Encrypt the password using the key and encode to base64
        encrypted_password_bytes = rsa.encrypt(password_bytes,pub_key)
        encrypted_password = base64.b64encode(encrypted_password_bytes)
        
        #Get current guard code
        self.twofactorcode = get_code(self.shared_secret)
        #Clear previous post data and set new ones based on what is required
        post_data.clear()
        post_data = {"username":self.username,
                    "password":encrypted_password,
                    "twofactorcode":self.twofactorcode,
                    "captchagid":self.captcha_gid if self.requires_captcha else "-1",
                    "captcha_text":self.captcha_text if self.requires_captcha else "",
                    "emailsteamid":self.steam_id if (self.requires_2fa or self.requires_email) else "",
                    "emailauth":self.email_code if self.requires_email else "",
                    "rsatimestamp":response['timestamp'],
                    "remember_login":"false",
                    "oauth_client_id":"DE45CD61",
                    "oauth_scope":"read_profile write_profile read_client write_client",
                    "loginfriendlyname":"#login_emailauth_friendlyname_mobile",
                    "donotcache":time.time()}
        #Send the login request
        response_data = mobile_login_request(APIEndpoints.community_base+"/login/dologin", "POST", post_data, cookies)
        response = response_data.text
        print("login",response)
        
        #Check that everything worked out okay
        if (response == None):
            return LoginResult.GENERAL_FAILURE
        login_response = LoginResponse(response)
        print("loginResponse",login_response.__dict__)
        
        if (login_response.message != None and "Incorrect login" in login_response.message):
            print("Bad credentials")
            return LoginResult.BAD_CREDENTIALS

        if (login_response.captcha_needed):
            print("Captcha needed")
            self.requires_captcha = True
            self.captcha_gid = login_response.captcha_gid
            return LoginResult.NEED_CAPTCHA

        if (login_response.emailauth_needed):
            print("Email auth needed")
            self.requires_email = True
            self.steam_id = login_response.email_steam_id
            return LoginResult.NEED_EMAIL

        if (login_response.requires_twofactor and not login_response.success):
            print("Two Factor needed")
            self.requires_2fa = True
            return LoginResult.NEED_2FA

        if (login_response.message != None and "too many login failures" in login_response.message):
            print("Too many login failures")
            return LoginResult.TOO_MANY_LOGINS

        if (login_response.oauth == None):
            print("oauth missing")
            return LoginResult.GENERAL_FAILURE

        print("oauth",login_response.oauth,type(login_response.oauth))
        if (len(login_response.oauth['oauth_token']) == 0):
            print("oauth token missing")
            return LoginResult.GENERAL_FAILURE

        if (not login_response.login_complete):
            print("Bad Credentials")
            return LoginResult.BAD_CREDENTIALS
        
        
        #If everything worked, set all the session data to the object
        session = SessionData()
        session.o_auth_data = login_response.oauth['oauth_token']
        session.steam_id = login_response.oauth['steamid']
        session.steam_login = session.steam_id + "%7C%7C" + login_response.oauth['wgtoken']
        session.steam_login_secure = session.steam_id + "%7C%7C" + login_response.oauth['wgtoken_secure']
        session.web_cookie = login_response.oauth['webcookie']
        session.session_id = session_id
        self.session = session
        self.logged_in = True
        print("Logged IN!")
        return LoginResult.LOGIN_OK
        
#Confirmation
class Confirmation():
    #Some constants
    generic_confirmation = 1
    trade = 2
    market_sell_transaction = 3
    unknown = 4
    def __init__(self,conf_id,conf_key,conf_type,conf_creator):
        self.id = conf_id
        self.key = conf_key
        self.type = conf_type
        self.creator = conf_creator
        
        if type == 1:
            self.conf_type = Confirmation.generic_confirmation
        elif type == 2:
            self.conf_type = Confirmation.trade
        elif type == 3:
            self.conf_type = Confirmation.market_sell_transaction
        else:
            self.conf_type = Confirmation.unknown
        
#SteamGuardAccount
class SteamGuardAccount():
    def __init__(self,shared_secret,identity_secret,device_id,session):
        self.shared_secret = shared_secret
        self.identity_secret = identity_secret
        self.device_id = device_id
        self.session_data = session
        
    def fetch_confirmations(self):
        #Get the url for the confirmation
        url = self.generate_confirmation_url()
        print("url",url)
        
        #Add default cookies
        cookies = []
        cookies = self.session_data.add_cookies(cookies)
        #Get the actions to confirm
        r = request(url, "GET", None, cookies)
        response = r.text
        
        if "Service Unavailable" in response:
            print("Service Unavailable")
            raise ValueError("Unavailable")
        
        #Regular expressions to find a confirmation's data
        conf_regex = re.compile("<div class=\"mobileconf_list_entry\" id=\"conf[0-9]+\" data-confid=\"(\\d+)\" data-key=\"(\\d+)\" data-type=\"(\\d+)\" data-creator=\"(\\d+)\"")
        
        if ("Change phone number") in response:
            print("Someone requesting to change phone number")
            raise Exception("Phone number request")
        
        #Check that all the confirmation's data is available
        if (response == None or not re.search(conf_regex,response)):
            if (response == None or "<div>Nothing to confirm</div>" not in response):
                print ("Invalid")
                print(r.url)
                raise Exception("Locked out of steam")
            else:
                print ("Nothing to confirm")
            return None
        
        #Get all the confirmations' data
        confirmations = re.findall(conf_regex, response)
        
        #Create and fill a list of Confirmations
        ret = []
        try:
            for conf in confirmations:
                conf_id = conf[0]
                conf_key = conf[1]
                conf_type = conf[2]
                conf_creator = conf[3]
#                 
                conf = Confirmation(conf_id,conf_key,conf_type,conf_creator)
                 
                ret.append(conf)
        except IndexError:
            print("Index error, printing response:")
            print(response)
        
        return ret
    
    def accept_confirmation(self,conf):
        return self.send_confirmation_ajax(conf, "allow")
    
    #Accepts or denies a confirmation
    def send_confirmation_ajax(self,conf,op):
        #Generate the url to send the request to
        url = APIEndpoints.community_base + "/mobileconf/ajaxop"
        query_string = "?op=" + op + "&"
        query_string += self.generate_confirmation_query_params(op)
        query_string += "&cid=" + conf.id + "&ck=" + conf.key
        url += query_string
        
        print(url)
        
        #Add basic cookies
        cookies = []
        cookies = self.session_data.add_cookies(cookies)
        
        #Send the actual request to accept or deny a confirmation
        response = request(url,"GET",None,cookies,None,referer=self.generate_confirmation_url())
        if not response:
            return False
        
        #Return if it was a success
        print(response.text)
        conf_response = json.loads(response.text)
        return conf_response['success']
    
    def generate_confirmation_url(self, tag = "conf"):
        endpoint = APIEndpoints.community_base + "/mobileconf/conf?"
        query_string = self.generate_confirmation_query_params(tag)
        return endpoint + query_string
        
    def generate_confirmation_query_params(self,tag):
        if not tag:
            raise Exception("Device ID is not present")
        time = TimeAlign.get_time()
        #Return a string of attributes for the confirmation url
        return "p="+self.device_id+"&a="+self.session_data.steam_id+"&k="+self.generate_confirmation_hash_for_time(time, tag)+"&t="+str(int(time))+"&m=android&tag="+tag

    def generate_confirmation_hash_for_time(self,time,tag):
        #Encode the identity secret to base64
        decode = base64.b64decode(self.identity_secret)
        n2=4
        if tag != None:
            #Set n2 based on the tag
            if (tag == "allow"):
                n2 = 3 + len(tag)
            elif (tag == "conf"):
                n2 = 4 + len(tag)
        #Turn the time to bytes with a size of n2
        byte_array = int(time).to_bytes(n2, byteorder='big', signed=False)
        #Combine the tag in bytes and the time in bytes
        encoded_tag = bytes(tag,encoding="utf-8")
        byte_array += encoded_tag
         
        #Encrypt the time using the identity secret and encode it to base64
        hashed_data = hmac.new(decode,msg=byte_array,digestmod=hashlib.sha1).digest()
        encoded_data = base64.b64encode(hashed_data)
        
        #Make the hash safe for urls and return
        hash_value = urllib.parse.quote_plus(encoded_data)
        print(hash_value)
        return hash_value

