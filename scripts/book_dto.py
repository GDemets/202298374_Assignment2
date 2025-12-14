from marshmallow import Schema, fields, validate

class BookCreateDTO(Schema):
    author = fields.Str(
        required=True,
        validate=validate.Length(max=50)
    )
    title = fields.Str(
        required=True,
        validate=validate.Length(max=50)
    )
    category_id = fields.Int(
        required=True,
        validate=validate.Range(min=1)
    )
    publisher = fields.Str(
        required=True,
        validate=validate.Length(max=50)
    )

    summary = fields.Str(
        required=False,
        validate=validate.Length(max=200),
        load_default="No summary available" 
    )
    isbn = fields.Str(
        required=True,
        validate=validate.Length(equal=10)
    )
    price = fields.Int(
        required=True,
        validate=validate.Range(min=0)
    )
    publication_date = fields.Date(required=True, format="%Y-%m-%d")
