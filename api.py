from flask import make_response, request, g
from model import Base, User, Post
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from schema import UserSchema, CredentialsSchema
from marshmallow import exceptions
from app_config import config
from utilities import TokenType, access_token_required, refresh_token_required

from application import create_app

# TODO: Implement Refresh Refresh token endpoint
# TODO: Implment photo upload functionality 
# TODO: Implement text post upload functionality

app = create_app(config)
user_schema = UserSchema()
creds_schema = CredentialsSchema()


@app.route('/userdata', methods=['GET'])
@access_token_required
def getUserData():
    return make_response({"data":
    {
        "user id": g.user,
        "username": g.name
    }}, 200)


@app.route('/refresh',methods=['POST'])
@refresh_token_required
def get_new_access_token():
    new_access_token: str = User.encode_auth_token(TokenType.ACCESS_TOKEN.value, g.user, g.name)
    response = make_response({"status":"new access token has been issued"}, 200)
    response.set_cookie('access', new_access_token, httponly=True)
    return response


@app.route('/user', methods=['GET'])
def getUser():
    username: str = request.get_json()["username"]
    with Session(db_engine) as session:
        container = session.query(User)
        for user in container:
            print(type(user.username))
        return make_response({"type": "good"})

@app.route('/', methods=['GET'])
def hello():
    resp = make_response({"username":"gus"})
    return resp

@app.route('/register', methods=['POST'])
def register_user():
    """
    
    sample payload
    {
        "username" : "xxx",
        "password" : "xxx"
    }
    
    """
    raw_credentials = {"username": request.get_json()["username"], "password": request.get_json()["password"]}
    try:
        # deserializes into object, checking validations
        creds = creds_schema.load(raw_credentials)
    except exceptions.ValidationError as err:
        return make_response({"error": err.messages}, 403)
    
    new_user = User(creds['username'], creds['password'])

    with Session(db_engine) as session:
        try:
            session.add(new_user)
            session.commit()
            return make_response({"status": "new user created"}, 200)
        except IntegrityError as e:
            session.rollback()
            return make_response({"error": "username is already taken"}, 403)


@app.route('/login', methods=['POST'])
def login_user():
    """
    TODO: Refactor to use private key to sign jwt tokens. 
    
    sample payload
    {
        "username" : "xxx",
        "password" : "xxx"
    }

    """
    raw_credentials = {"username": request.get_json()["username"], "password": request.get_json()["password"]}
    try:
        creds = creds_schema.load(raw_credentials)
    except exceptions.ValidationError as err:
        return make_response({"error": err.messages}, 403)
    
    with Session(db_engine) as session:
        try:
            user: User = session.query(User).filter(User.username == creds['username']).first()

        except SQLAlchemyError as e:
            return make_response({"error": e})
    if user:
        # user found, now check password
        
        if user.is_raw_password_correct(creds['password']):
            # passsword is correct, issue tokens
            access_token = User.encode_auth_token(TokenType.ACCESS_TOKEN.value, user.id, user.username)
            refresh_token = User.encode_auth_token(TokenType.REFRESH_TOKEN.value, user.id, user.username)
            response = make_response({"status": "succesful Log In"}, 200)
            response.set_cookie('access', access_token, httponly=True)
            response.set_cookie('refresh', refresh_token, httponly=True)
            return response
        else:
            
            # password is incorrect, return username/password combination is wrong 
            return make_response({"status":"wrong username/password combination"}, 401)
    else:
        # username does not exist, return "wrong username/password" combination
        return make_response({"status":"wrong username/password combination"}, 401)



@app.route('/post',methods=['POST'])
@access_token_required
def post_update():
    with Session(db_engine) as session: 
        # fetch current user  
        curr_user: User = session.query(User).filter(User.id == g.user).first()

        new_post: Post = Post(curr_user)

        # TODO: add in some schema checking later  
        new_post.caption = request.get_json()['text']
        session.add(new_post)

        print("is the user in the session: " + str(curr_user in session))

        session.commit()

        return make_response({"status":"new post made sucessfully"}, 200)
    


@app.route('/feed', methods=['GET'])
def get_feed():
    return None 

@app.route('/upvote', methods=['POST'])
def upvote_post():
    return None 

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
