from app import app
from models import db, User, Book, Review, Category, Wishlist
from faker import Faker
import random

fake = Faker("en_US")

with app.app_context():

    db.drop_all()
    db.create_all()

    users = []
    u1=User(
            pseudo="Alice",
            mail="alice@mail.com",
            role="user"
        )
    u1.set_password("1234")
    users.append(u1)
    for _ in range(30):
        user = User(
            pseudo=fake.user_name(),
            mail=fake.unique.email(),
            role="user"
        )
        user.set_password("1234")
        users.append(user)

    admin = User(
        pseudo="admin",
        mail="admin@mail.com",
        role="admin"
    )
    admin.set_password("admin")
    db.session.add_all(users + [admin])
    db.session.commit()

    category_names = [
        "Fantasy", "Science-Fiction", "Romance", "Thriller",
        "Horror", "Biography", "History", "Poetry",
        "Adventure", "Fiction"
    ]
    categories = [Category(name=name) for name in category_names]
    db.session.add_all(categories)
    db.session.commit()

    books = []
    for _ in range(120):
        book = Book(
            author=fake.name(),
            title=fake.sentence(nb_words=4),
            category_id=random.choice(categories).id,
            publisher=fake.company(),
            summary=fake.text(max_nb_chars=200),
            isbn=fake.unique.isbn13(),
            price=random.randint(5000, 30000),
            publication_date=fake.date_between(start_date="-50y", end_date="today")
        )
        books.append(book)
    db.session.add_all(books)
    db.session.commit()

    reviews = []
    for _ in range(60):
        review = Review(
            user_id=random.choice(users).id,
            book_id=random.choice(books).id,
            score=random.randint(1, 5),
            message=fake.sentence()
        )
        reviews.append(review)
    db.session.add_all(reviews)
    db.session.commit()

    wishlists = []
    for _ in range(40):
        wishlist = Wishlist(
            user_id=random.choice(users).id,
            book_id=random.choice(books).id
        )
        wishlists.append(wishlist)
    db.session.add_all(wishlists)
    db.session.commit()


    print("Database seeded successfully!")
