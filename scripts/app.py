from flask import Flask, request, jsonify, abort, render_template
from models import db, User, Post, Book
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import logging
from datetime import datetime

### Flask App and Database Configuration ###
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///BookStore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "0123456789"   
db.init_app(app)
jwt = JWTManager(app)

def create_tables():
    db.create_all()

app.before_request(create_tables)

### Middleware to log requests ###
@app.before_request
def log_request_info():
    logging.info(f"{datetime.utcnow().isoformat()} - {request.method} {request.path}")

######################################################################################
#                                      USERS
######################################################################################

### GET ###
@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'An error occurred while fetching users'}), 500
    return jsonify({
        'status': 'success',
        'message': 'Users successfully retrieved',
        'data': [user.to_dict() for user in users]
    }), 200

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    return jsonify({
        'status': 'success',
        'message': 'User successfully retrieved',
        'data': user.to_dict()
    }), 200

### POST ###
@app.route('/users', methods=['POST'])
def create_user():
    if not request.json or 'pseudo' not in request.json or 'mail' not in request.json or 'password' not in request.json:
        return jsonify({'status':'error','message': 'Format invalid or missing values'}), 400
    
    user = User(
        pseudo=request.json['pseudo'],
        mail=request.json['mail'],
        password=request.json['password'],
        role="user" #user role by default
    )
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'User already exists'}), 409
    
    return jsonify({
        'status': 'success',
        'message': 'User successfully created',
        'data': user.to_dict()
    }), 201

### PUT ###
@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    if not request.json or 'mail' not in request.json:
        return {'message': 'Format invalid or missing values', 'status': 'error'}, 400
    
    try:
        user = User.query.get(user_id)
        user.pseudo = request.json.get('pseudo', user.pseudo)
        user.mail = request.json.get('mail', user.mail)
        user.password = request.json.get('password', user.password)

        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'User does not exist'}), 404

    return jsonify({
        'status': 'success',
        'message': 'User successfully modified',
        'data': user.to_dict()
    }), 200

### DELETE ###
@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'User does not exist'}), 404

    return jsonify({'status': 'success', 'message': 'User successfully deleted'}), 200

### User Login ###
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or "mail" not in data or "password" not in data:
        return jsonify({'status': 'error', 'message':'Mail and password are required'}), 400

    user = User.query.filter_by(mail=data["mail"]).first()

    if user and user.password == data["password"]:
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'status': 'success',
            'access_token': access_token,
            'message': 'Login successful',
        }), 200

    return jsonify({'status': 'error', 'message':'Invalid credentials'}), 401


######################################################################################
#                                      POSTS
######################################################################################

### GET ###
@app.route('/users/<int:user_id>/posts', methods=['GET'])
def get_posts_user(user_id):
    posts = Post.query.get_or_404(user_id)

    return jsonify({
        'status': 'success',
        'message': 'Posts successfully retrieved',
        'data': [post.to_dict() for post in posts]
    }), 200

@app.route('/books/<int:book_id>/posts', methods=['GET'])
def get_posts_book(book_id):
    posts = Post.query.filter_by(book_id=book_id).all()
    if not posts:
        return jsonify({'status': 'error', 'message': 'The corresponding books were not found.'}), 404

    return jsonify({
        'status': 'success',
        'message': 'Posts successfully retrieved',
        'data': [post.to_dict() for post in posts]
    }), 200

### POST ###
@app.route('/users/<int:user_id>/books/<int:book_id>/posts', methods=['POST'])
@jwt_required()
def create_post(user_id, book_id):
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    book = Book.query.get(book_id)
    if not book:
        return jsonify({'status': 'error', 'message': 'Book not found'}), 404

    if not request.json :
        return jsonify({'status': 'error', 'message': 'Invalid JSON'}), 400

    if 'score' not in request.json or 'message' not in request.json:
        return jsonify({'status': 'error', 'message': 'Missing score or message'}), 400

    post = Post(
        user_id=user_id,
        book_id=book_id,
        score=request.json.get('score'),
        message=request.json.get('message')
    )

    try:
        db.session.add(post)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'Error while creating post'}), 500

    return jsonify({
        'status': 'success',
        'message': 'Post successfully created',
        'data': post.to_dict()
    }), 201

### PUT ###
@app.route('/posts/<int:post_id>', methods=['PUT'])
def update_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        if not request.json:
            abort(400)        
        post.score = request.json.get('score', post.score)
        post.message = request.json.get('message', post.message)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'Post does not exist'}), 404
    return jsonify({
        'status': 'success',
        'message': 'Post successfully modified',
        'data': post.to_dict()}),200

### DELETE ###
@app.route('/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        db.session.delete(post)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'Post does not exist'}), 404

    return jsonify({'status': 'success', 'message': 'Post successfully deleted'}), 200

######################################################################################
#                                      BOOKS
######################################################################################

### GET Books ###
@app.route('/books', methods=['GET'])
def get_books():
    books = Book.query.all()
    return jsonify({
        'status': 'success',
        'message': 'Books successfully retrieved',
        'data': [book.to_dict() for book in books]
    }), 200

@app.route('/books/<int:book_id>', methods=['GET'])
def book_user(book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify({'status': 'error', 'message': 'Book not found'}), 404

    return jsonify({
        'status': 'success',
        'message': 'Book successfully retrieved',
        'data': book.to_dict()
    }), 200

### POST ###
@app.route('/books', methods=['POST'])
def create_book():
    requiered_fields = ['author', 'title', 'category', 'publisher', 'isbn', 'price', 'publication_date']
    if not request.json or not all(key in request.json for key in requiered_fields):
        return {'status': 'error','message': 'Format invalid or missing values'}, 400
    book=Book(
        author=request.json['author'],
        title=request.json['title'],
        category=request.json['category'],
        publisher=request.json['publisher'],
        summary=request.json.get('summary','No summary available'),
        isbn=request.json['isbn'],
        price=request.json['price'],
        publication_date=request.json['publication_date']
    )
    try:
        db.session.add(book)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'ISBN already used'}), 409
    return jsonify({
        'status': 'success',
        'message': 'Book successfully created',
        'data': book.to_dict()
    }), 201

### DELETE ###
@app.route('/books/<int:book_id>', methods=['DELETE'])
def delete_book(book_id):
    try:
        book = Book.query.get_or_404(book_id)
        db.session.delete(book)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'Book does not exist'}), 404

    return jsonify({'status': 'success', 'message': 'Book successfully deleted'}), 200

### PUT ###
@app.route('/books/<int:book_id>', methods=['PUT'])
def update_book(book_id):
    if not request.json:
        return jsonify({'message': 'Invalid or missing JSON', 'status': 'error'}), 400
    
    book = Book.query.get(book_id)
    if book is None:
        return jsonify({'status': 'error', 'message': 'Book does not exist'}), 404

    try:
        book.author = request.json.get('author', book.author)
        book.title = request.json.get('title', book.title)
        book.category = request.json.get('category', book.category)
        book.publisher = request.json.get('publisher', book.publisher)
        book.summary = request.json.get('summary', book.summary)
        book.isbn = request.json.get('isbn', book.isbn)
        book.price = request.json.get('price', book.price)
        book.publication_date = request.json.get('publication_date', book.publication_date)

        db.session.commit()

    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'ISBN already used'}), 409

    return jsonify({
        'status': 'success',
        'message': 'Book successfully modified',
        'data': book.to_dict()
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
