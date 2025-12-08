from app import app
from models import db, User, Book, Post

with app.app_context():

    db.drop_all()
    db.create_all()

    u1 = User(pseudo="Alice", mail="alice@mail.com", password="1234", role="user")
    u2 = User(pseudo="Bob", mail="bob@mail.com", password="1234", role="admin")

    db.session.add_all([u1, u2])
    db.session.commit()

    b1 = Book(
        author="Tolkien",
        title="Le Seigneur des Anneaux",
        category="Fantasy",
        publisher="HarperCollins",
        summary="Un roman épique.",
        isbn="123456789012",
        price=29.90,
        publication_date="1954-07-29",
    )

    db.session.add(b1)
    db.session.commit()

    p1 = Post(user_id=u1.id, book_id=b1.id, score=5, message="Chef d’œuvre !")
    db.session.add(p1)
    db.session.commit()

    print("Database seeded successfully.")
