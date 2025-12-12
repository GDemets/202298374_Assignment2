from app import app
from models import db, User, Book, Review, Category

with app.app_context():

    db.drop_all()
    db.create_all()

    u1 = User(pseudo="Alice", mail="alice@mail.com", password="1234", role="user")
    u2 = User(pseudo="John", mail="john@mail.com", password="1234", role="user")
    u3 = User(pseudo="Doe", mail="doe@mail.com", password="1234", role="user")
    u4 = User(pseudo="Admin", mail="admin@mail.com", password="admin", role="admin")

    db.session.add_all([u1, u2,u3,u4])
    db.session.commit()

    c1 = Category(name="Fantasy")
    c2 = Category(name="Fiction")

    db.session.add_all([c1, c2])
    db.session.commit()

    b1 = Book(
        author="Tolkien",
        title="Le Seigneur des Anneaux",
        category_id=c1.id,
        publisher="HarperCollins",
        summary="Un roman épique.",
        isbn="0123456789",
        price=25000,
        publication_date="1954-07-29",
    )

    b2 = Book(
        author="Lorem",
        title="Lorem Ipsum",
        category_id=c2.id,
        publisher="Fiction House",
        summary="A lorem ipsum text.",
        isbn="0987654321",
        price=10500,
        publication_date="1954-07-29",
    )

    db.session.add(b1)
    db.session.add(b2)
    db.session.commit()

    p1 = Review(user_id=u1.id, book_id=b1.id, score=5, message="Really great book !")
    p2 = Review(user_id=u1.id, book_id=b2.id, score=4, message="Interesting read.")
    p3 = Review(user_id=u2.id, book_id=b1.id, score=3, message="It was okay.")    


    db.session.add_all([p1, p2, p3])
    db.session.commit()

    print("Database seeded successfully.")
