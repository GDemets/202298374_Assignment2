import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))
from app import app as flask_app, db
from models import User, Book, Category, Review, Wishlist
from flask_jwt_extended import create_access_token

@pytest.fixture
def app():
    """Créer l'application Flask pour les tests"""
    flask_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:', 
        'JWT_SECRET_KEY': 'test-secret-key',
        'SECRET_KEY': 'test-secret-key',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    })
    
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """Create Flask client for test"""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Run cli runner"""
    return app.test_cli_runner()

@pytest.fixture
def category(app):
    c1 = Category(name="Fiction")
    db.session.add(c1)
    db.session.commit()
    return c1.id

@pytest.fixture
def book(app, category):
    book = Book(
        author="Tolkien",
        title="Le Seigneur des Anneaux",
        category_id=category,  
        publisher="HarperCollins",
        summary="Un roman épique.",
        isbn="0123456789",
        price=25000,
        publication_date="1954-07-29",
    )
    db.session.add(book)
    db.session.commit()
    return book.id

@pytest.fixture
def review(app,book,user):
    r1 = Review(user_id=str(user),book_id=str(book),score=4,message="A beautiful story")
    db.session.add(r1)
    db.session.commit()
    return r1.id

@pytest.fixture
def user(app):
    """Create an user"""
    with app.app_context():
        user = User(
            pseudo="testuser",
            mail="test@example.com",
            role="user"
        )
        user.set_password("1234")
        db.session.add(user)
        db.session.commit()
        return user.id
    
@pytest.fixture
def user_token(app, user):
    return create_access_token(
        identity=str(user),
        additional_claims={"role": "user"}
    )

@pytest.fixture
def admin(app):
    admin = User(
        pseudo="admin",
        mail="admin@example.com",
        role="admin"
    )
    admin.set_password("admin123")
    db.session.add(admin)
    db.session.commit()
    return admin.id

@pytest.fixture
def admin_token(app, admin):
    return create_access_token(
        identity=str(admin),
        additional_claims={"role": "admin"}
    )