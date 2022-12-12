from marshmallow import Schema, fields, post_load
from marshmallow_custom_fields import LargeBinaryField

class UserSchema(Schema):
    id = fields.Str()
    usernanme = fields.Str()
    password = LargeBinaryField()

class CredentialsSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)