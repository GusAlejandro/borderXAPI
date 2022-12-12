from enum import Enum
from flask import request, make_response, g
from functools import wraps

# TODO: need to refactor access_token_required/refresh_token_required as its the same code, create common function for them to call

class TokenError(Enum):
    INVALID_TOKEN = "Access token is invalid"
    EXPIRED_TOKEN = "Access token has expired"
    DECODE = "Token could not be decoded"
    INVALID_SIGNATURE = "Error related to token signature"
    WRONG_TOKEN = "The wrong token was passed in"

class TokenType(Enum):
    ACCESS_TOKEN = 'access'
    REFRESH_TOKEN = 'refresh'

def access_token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        from model import User
        token = request.cookies.get('access')
        if not token or 'null' in token:
            return make_response({
                'Error':'Request does not include token'
            }, 401)

        payload = User.decode_auth_token(token, TokenType.ACCESS_TOKEN)

        match payload:
            case TokenError.EXPIRED_TOKEN:
                return make_response({"Error": TokenError.EXPIRED_TOKEN.value}, 401)
            case TokenError.WRONG_TOKEN:
                return make_response({"Error": TokenError.WRONG_TOKEN.value}, 401)
            case TokenError.INVALID_TOKEN:
                return make_response({"Error": TokenError.INVALID_TOKEN.value}, 401)
            case TokenError.EXPIRED_TOKEN:
                return make_response({"Error": TokenError.EXPIRED_TOKEN.value}, 401)
            case TokenError.DECODE:
                return make_response({"Error": TokenError.DECODE.value}, 401)
            case TokenError.INVALID_SIGNATURE:
                return make_response({"Error": TokenError.INVALID_SIGNATURE.value}, 401)
            case other:
                g.user = payload['sub']
                g.name = payload['user']
                return fn(*args, **kwargs)
    
    return wrapper 
                    
def refresh_token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        from model import User
        token = request.cookies.get('refresh')
        if not token or 'null' in token:
            return make_response({
                'Error':'Request does not include token'
            }, 401)

        payload = User.decode_auth_token(token, TokenType.REFRESH_TOKEN)

        match payload:
            case TokenError.EXPIRED_TOKEN:
                return make_response({"Error": TokenError.EXPIRED_TOKEN.value}, 401)
            case TokenError.WRONG_TOKEN:
                return make_response({"Error": TokenError.WRONG_TOKEN.value}, 401)
            case TokenError.INVALID_TOKEN:
                return make_response({"Error": TokenError.INVALID_TOKEN.value}, 401)
            case TokenError.EXPIRED_TOKEN:
                return make_response({"Error": TokenError.EXPIRED_TOKEN.value}, 401)
            case TokenError.DECODE:
                return make_response({"Error": TokenError.DECODE.value}, 401)
            case TokenError.INVALID_SIGNATURE:
                return make_response({"Error": TokenError.INVALID_SIGNATURE.value}, 401)
            case other:
                g.user = payload['sub']
                g.name = payload['user']
                return fn(*args, **kwargs)
    
    return wrapper 
