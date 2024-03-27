# AS4Mobile
Authorization Server for Mobile Apps

## Environment Configuration

### PORT
- default 3000
http port to listen on 

### HOST
- default `http://localhost:${PORT}`
hostname to be used in issuer ('iss' claim in access_token) -- will be `https:${HOST}` 

### NODE_ENV
- default is `undefined`
`'production'|'development'`

### REDIS_HOST
tbd


### USE_DPOP
- default is `undefined`
set to any value to enable checking for DPoP header and returns `"token_type":"DPoP"` rather than `"token_type":"Bearer"` from token endpoint

## Webview 
```
POST /token HTTP/1.1
Host: app.tiltingpoint.com
Content-Type: application/x-www-form-urlencoded

grant_type=cookie_token
```
returns
```
200
{
    "loggedIn":false,
    "nonce":"1234567890"
}
```
User is not logged in. Start a login flow with the returned nonce value. Once logged in, it will return

```
200

{
    "loggedIn":true
}
```

User is logged in. access_token and refresh_token cookies have been created and updated


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




