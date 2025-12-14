from marshmallow import Schema, fields, validate

class UserCreateDTO(Schema):
    pseudo = fields.String(required=True)
    mail = fields.Email(required=True)
    password = fields.String(required=True)

class UserUpdateDTO(Schema):
    pseudo = fields.Str(
        required=False, 
        validate=validate.Length(min=2, max=30),
        error_messages={"validator_failed": "Pseudo must be 2-30 characters"}
    )
    mail = fields.Email(
        required=False,
        validate=validate.Length(max=30),
        error_messages={"validator_failed": "Invalid email format or too long"}
    )
    password = fields.Str(
        required=False, 
        validate=validate.Length(min=6, max=128),
        error_messages={"validator_failed": "Password must be at least 6 characters"}
    )