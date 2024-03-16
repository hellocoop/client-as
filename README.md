# AS4Mobile
Authorization Server for Mobile Apps


## Webview 

POST /token HTTP/1.1
Host: app.tiltingpoint.com
Content-Type: application/x-www-form-urlencoded

grant_type=cookie_token

200
{
    "loggedIn":false,
    "nonce":"1234567890"
}

User is not logged in. Start a login flow with the returned nonce value.

{
    "loggedIn":true
}

User is logged in. access_token and refresh_token cookies have been updated


## SDK

After the user has successfully logged in, call 

POST /token HTTP/1.1
Host: app.tiltingpoint.com
Content-Type: application/x-www-form-urlencoded
DPoP: zzzzz

grant_type=authorization_code&
client_id=SDK-1.0.0
code=<nonce>

{
    "access_token": "xxx",
    "token_type": "DPoP",
    "refresh_token": "yyy",
    "expires_in": 300
}

POST /token HTTP/1.1
Host: app.tiltingpoint.com
Content-Type: application/x-www-form-urlencoded
DPoP: zzzzz

Refresh
grant_type=refresh_token&
refresh_token=yyy


Endpoints

/token // public

grant_type="cookie_token"
device_info ???

/jwks

/revoke

/.wellknown/oauth-authorization-server

/login
    - called by client after successful login




