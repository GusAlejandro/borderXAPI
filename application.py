from flask import Flask 
from flask_cors import CORS
from model import Base 
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine 


def create_app(config_obj: dict):
    db_engine: Engine = create_engine(config_obj['db_config'])
    Base.metadata.create_all(db_engine)
    app = Flask(__name__)
    CORS(app)
    return app

