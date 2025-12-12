from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pseudo = db.Column(db.String(30), unique=True, nullable=False)
    mail = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    reviews = db.relationship('Review', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'pseudo': self.pseudo,
            'mail': self.mail,
            'role': self.role
        }


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(20), nullable=False)
    publisher = db.Column(db.String(50), nullable=False)
    summary = db.Column(db.String(200))
    isbn = db.Column(db.String(10), unique=True, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    publication_date = db.Column(db.String(10), nullable=False)
    reviews = db.relationship('Review', backref='book', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'author': self.author,
            'title': self.title,
            'category': self.category,
            'publisher': self.publisher,
            'summary': self.summary,
            'isbn': self.isbn,
            'price': self.price,
            'publication_date': self.publication_date
        }


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    message = db.Column(db.String(100), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'book_id': self.book_id,
            'score': self.score,
            'message': self.message
        }
