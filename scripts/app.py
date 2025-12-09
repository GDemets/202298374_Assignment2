from flask import Flask, request, jsonify, abort, render_template
from flasgger import Swagger
from models import db, User, Post, Book
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import logging
from datetime import datetime

### Flask App and Database Configuration ###
app = Flask(__name__)
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "BookStore API",
        "description": "API documentation",
        "version": "1.0"
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\""
        }
    }
})
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
    """
    Get all the users.
    ---
    tags:
      - Users
    responses:
      200:
        description: Users successfully retrieved.
        schema:
          type: object
          properties:
            message:
              type: string
    """
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
    """
    Get a user by its ID
    ---
    tags:
      - Users
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: User successfully retrieved
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
            data:
              type: object
      404:
        description: User not found
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
    """
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
    """
    Create a new user
    ---
    tags:
      - Users
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        description: User information to create
        schema:
          type: object
          required:
            - pseudo
            - mail
            - password
          properties:
            pseudo:
              type: string
              example: johndoe
            mail:
              type: string
              example: johndoe@example.com
            password:
              type: string
              example: mysecretpassword
    responses:
      201:
        description: User successfully created
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
            data:
              type: object
      400:
        description: Missing or invalid fields
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
      409:
        description: User already exists
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
    """
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
@jwt_required()
def update_user(user_id):
    """
    Update a user's information
    ---
    tags:
      - Users
    parameters:
      - name: user_id
        in: path
        required: true
        type: integer
        description: ID of the user to update
      - in: body
        name: body
        required: true
        description: Fields to update
        schema:
          type: object
          properties:
            pseudo:
              type: string
              example: newPseudo
            mail:
              type: string
              example: newmail@example.com
            password:
              type: string
              example: newpassword123
          required:
            - mail
    responses:
      200:
        description: User updated successfully
      400:
        description: Invalid or missing fields
      404:
        description: User not found
    """
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
@jwt_required()
def delete_user(user_id):
    """
    Delete a user by ID
    ---
    tags:
      - Users
    parameters:
      - name: user_id
        in: path
        required: true
        type: integer
        description: ID of the user to delete
    responses:
      200:
        description: User successfully deleted
      404:
        description: User not found
    """
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
    """
    User login
    ---
    tags:
      - Authentication
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            mail:
              type: string
              example: "admin@mail.com"
            password:
              type: string
              example: "password123"
          required:
            - mail
            - password
    responses:
      200:
        description: Login successful
        schema:
          type: object
          properties:
            status:
              type: string
            access_token:
              type: string
            message:
              type: string
      400:
        description: Missing mail or password
      401:
        description: Invalid credentials
    """
    data = request.get_json()

    if not data or "mail" not in data or "password" not in data:
        return jsonify({'status': 'error', 'message': 'Mail and password are required'}), 400

    user = User.query.filter_by(mail=data["mail"]).first()

    if user and user.password == data["password"]:
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'status': 'success',
            'access_token': access_token,
            'message': 'Login successful'
        }), 200

    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401


######################################################################################
#                                      POSTS
######################################################################################

### GET ###
@app.route('/users/<int:user_id>/posts', methods=['GET'])
def get_posts_user(user_id):
    """
    Get all posts created by a specific user
    ---
    tags:
      - Posts
    parameters:
      - name: user_id
        in: path
        required: true
        type: integer
        description: ID of the user whose posts you want to retrieve
    responses:
      200:
        description: Posts successfully retrieved
      404:
        description: User not found or no posts found
    """
    posts = Post.query.get_or_404(user_id)

    return jsonify({
        'status': 'success',
        'message': 'Posts successfully retrieved',
        'data': [post.to_dict() for post in posts]
    }), 200

@app.route('/books/<int:book_id>/posts', methods=['GET'])
def get_posts_book(book_id):
    """
    Get all posts related to a specific book
    ---
    tags:
      - Posts
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
        description: ID of the book whose posts you want to retrieve
    responses:
      200:
        description: Posts successfully retrieved
      404:
        description: No posts found for this book
    """
    posts = Post.query.filter_by(book_id=book_id).all()
    if not posts:
        return jsonify({'status': 'error', 'message': 'The corresponding books were not found.'}), 404

    return jsonify({
        'status': 'success',
        'message': 'Posts successfully retrieved',
        'data': [post.to_dict() for post in posts]
    }), 200

### POST ###
@app.route('/books/<int:book_id>/posts', methods=['POST'])
@jwt_required()
def create_post(book_id):
    """
    Create a new post for a specific user and book
    ---
    tags:
      - Posts
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
        description: ID of the book the post refers to
      - in: body
        name: body
        required: true
        description: Post data
        schema:
          type: object
          properties:
            score:
              type: integer
              example: 4
            message:
              type: string
              example: "Excellent book, I loved it!"
          required:
            - score
            - message
    responses:
        201:
            description: Post successfully created
        400:
            description: Invalid JSON or missing fields
        403:
            description: Unauthorized action
        404:
            description: User or book not found
        500:
            description: Error while creating the post

    """
    current_user_id = get_jwt_identity()

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    book = Book.query.get(book_id)
    if not book:
        return jsonify({'status': 'error', 'message': 'Book not found'}), 404

    if not request.json or 'score' not in request.json or 'message' not in request.json:
        return jsonify({'status': 'error', 'message': 'Invalid JSON or Missing score or message'}), 400

    post = Post(
        user_id=current_user_id,
        book_id=book_id,
        score=request.json['score'],
        message=request.json['message']
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
@jwt_required()
def update_post(post_id):
    """
    Update an existing post
    ---
    tags:
      - Posts
    parameters:
      - name: post_id
        in: path
        required: true
        type: integer
        description: ID of the post to update
      - in: body
        name: body
        required: true
        description: Fields to update for the post
        schema:
          type: object
          properties:
            score:
              type: integer
              example: 5
            message:
              type: string
              example: "Updated review message"
    responses:
      200:
        description: Post updated successfully
      400:
        description: Invalid or missing JSON body
      404:
        description: Post not found
    """
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
@jwt_required()
def delete_post(post_id):
    """
    Delete a post by ID
    ---
    tags:
      - Posts
    parameters:
      - name: post_id
        in: path
        required: true
        type: integer
        description: ID of the post to delete
    responses:
      200:
        description: Post successfully deleted
      404:
        description: Post not found
    """
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
    """
    Get all books
    ---
    tags:
      - Books
    responses:
      200:
        description: List of all books
    """
    books = Book.query.all()
    return jsonify({
        'status': 'success',
        'message': 'Books successfully retrieved',
        'data': [book.to_dict() for book in books]
    }), 200

@app.route('/books/<int:book_id>', methods=['GET'])
def get_book(book_id):
    """
    Get a book by its ID
    ---
    tags:
      - Books
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
        description: ID of the book to retrieve
    responses:
      200:
        description: Book successfully retrieved
      404:
        description: Book not found
    """
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
@jwt_required()
def create_book():
    """
    Create a new book
    ---
    tags:
      - Books
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - author
              - title
              - category
              - publisher
              - isbn
              - price
              - publication_date
            properties:
              author:
                type: string
              title:
                type: string
              category:
                type: string
              publisher:
                type: string
              summary:
                type: string
                default: "No summary available"
              isbn:
                type: string
              price:
                type: number
              publication_date:
                type: string
                format: date
    responses:
      201:
        description: Book successfully created
      400:
        description: Format invalid or missing values
      409:
        description: ISBN already used
    """
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
@jwt_required()
def delete_book(book_id):
    """
    Delete a book by its ID
    ---
    tags:
      - Books
    parameters:
      - name: book_id
        in: path
        required: true
        schema:
          type: integer
    responses:
      200:
        description: Book successfully deleted
      404:
        description: Book does not exist
    """
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
@jwt_required()
def update_book(book_id):
    """
    Update a book by its ID
    ---
    tags:
      - Books
    parameters:
      - name: book_id
        in: path
        required: true
        schema:
          type: integer
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              author:
                type: string
              title:
                type: string
              category:
                type: string
              publisher:
                type: string
              summary:
                type: string
              isbn:
                type: string
              price:
                type: number
              publication_date:
                type: string
                format: date
            example:
              author: "New Author"
              title: "Updated Book Title"
              category: "Science"
              publisher: "New Publisher"
              summary: "Updated summary"
              isbn: "9781234567897"
              price: 19.99
              publication_date: "2021-07-12"
    responses:
      200:
        description: Book successfully modified
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                message:
                  type: string
                data:
                  type: object
      400:
        description: Invalid or missing JSON
      404:
        description: Book does not exist
      409:
        description: ISBN already used
    """
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
