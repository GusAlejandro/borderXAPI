from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
import jwt
import datetime
import bcrypt
import uuid
from app_config import config
from utilities import TokenError, TokenType

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(String, primary_key=True)
    username = Column(String, unique=True)
    password = Column(LargeBinary)
    posts = relationship('Post', backref='user')



    def __init__(self, username: str, raw_password: str) -> None:
        self.username = username
        self.id = str(uuid.uuid4())
        self.password = User.hash_password(raw_password)

    @staticmethod
    def hash_password(raw_password: str) -> LargeBinary:
        bytes = raw_password.encode('utf-8')
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(bytes, salt)
    
    def is_raw_password_correct(self, raw_password: str) -> bool:
        # returns true or false if raw_password is valid 
        bytes = raw_password.encode('utf-8')
        encrypted_password = bcrypt.hashpw(bytes, self.password)
        return encrypted_password == self.password

    @staticmethod 
    def encode_auth_token(token_type: str, user_id: str, username: str) -> str:
        exp_time_limit: int = 30 if token_type == 'access' else 1800
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes= exp_time_limit),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id,
            'user': username,
            'type': token_type
        }

        return jwt.encode(payload, config['secret_key'], algorithm='HS256')

    @staticmethod
    def decode_auth_token(auth_token: str, expected_token_type: TokenType) -> dict:
        try:
            payload = jwt.decode(auth_token, config['secret_key'], algorithms=['HS256'])
            if payload['type'] == expected_token_type.value:
                return payload
            else:
                return TokenError.WRONG_TOKEN
        except jwt.ExpiredSignatureError:
            return TokenError.EXPIRED_TOKEN
        except jwt.InvalidSignatureError:
            return TokenError.INVALID_SIGNATURE
        except jwt.DecodeError:
            return TokenError.DECODE
        except jwt.InvalidTokenError:
            return TokenError.INVALID_TOKEN
        



class Post(Base):
    __tablename__ = 'post'
    user_id = Column(String, ForeignKey("user.id"))
    user = relationship("User") # this is the bidirectional RL that points back to the parent 
    id = Column(String, primary_key=True)
    caption = Column(String)
    media = Column(String)
    upvotes = Column(Integer)

    def __init__(self, user):
        self.upvotes = 0
        self.id = str(uuid.uuid4())
        self.user.append(user)


        