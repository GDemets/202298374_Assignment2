from flask import Flask, request, jsonify, abort, render_template
from flasgger import Swagger
from models import db, User, Review, Book, Category, Wishlist
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token,jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
from datetime import datetime
from dotenv import load_dotenv
from datetime import timedelta
from error_response import error_response

import logging
import os

# TODO: 
# Book : get a book by is category, title
# THE CODE IS TOO LONG
# Bcrypt for password hashing
# gestion des erreurs
# Ajout tests
 
### Flask App and Database Configuration ###
load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "BookStore API",
        "description": "API documentation",
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Add 'Bearer <your_token>'"
        }
    }
})

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
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')
    return jsonify({
        'status': 'success',
        'message': 'Users successfully retrieved',
        'data': [user.to_dict() for user in users]
    }), 200
    

@app.route('/users/me', methods=['GET'])
@jwt_required(optional=True)
def get_me():
    """
    Get a user information
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
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
      403:
        description: You are not connected
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
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
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')
    
    user = User.query.get(current_user_id)
    if not user:
        return error_response(status=404,code='USER_NOT_FOUND',message='User ID does not exist')
        
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
    if not request.json :
        return error_response(status=400,code='BAD_REQUEST',message='The request is not formatted correctly')
    if 'pseudo' not in request.json or 'mail' not in request.json or 'password' not in request.json:
        return error_response(status=400,code='INVALID_QUERY_PARAM',message='Invalid query parameter value')

    user = User(
        pseudo=request.json['pseudo'],
        mail=request.json['mail'],
        password=request.json['password'],
        role="user" #set user role as default
    )
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=409,code='DUPLICATE_RESSOURCE',message='Data already exists')
    
    return jsonify({
        'status': 'success',
        'message': 'User successfully created',
        'data': user.to_dict()
    }), 201

### PUT ###
@app.route('/users/me', methods=['PUT'])
@jwt_required(optional=True)
def update_user():
    """
    Update a user's information
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    parameters:
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
      403:
        description: Unauthorized action
      404:
        description: User not found
    """
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')
    if not request.json :
        return error_response(status=400,code='BAD_REQUEST',message='The request is not formatted correctly')
    if 'mail' not in request.json :
        return error_response(status=400,code='INVALID_QUERY_PARAM',message='Invalid query parameter value')
    
    try:
        user = User.query.get(current_user_id)
        user.pseudo = request.json.get('pseudo', user.pseudo)
        user.mail = request.json.get('mail', user.mail)
        user.password = request.json.get('password', user.password)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=404,code='USER_NOT_FOUND',message='User ID does not exist')

    return jsonify({
        'status': 'success',
        'message': 'User successfully modified',
        'data': user.to_dict()
    }), 200

### PATCH ###
@app.route('/users/<int:user_id>/make_admin', methods=['PATCH'])
@jwt_required()
def make_user_admin(user_id):
    """
    Promote a user to admin (admin only)
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    parameters:
      - name: user_id
        in: path
        required: true
        type: integer
        description: ID of the user to promote
    responses:
      200:
        description: User promoted to admin successfully
      403:
        description: Forbidden, only admin can promote
      404:
        description: User not found
      500:
        description: Error while updating user
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return error_response(status=403,code='FORBIDDEN',message='No access')
    
    user_to_promote = User.query.get(user_id)
    if not user_to_promote:
        return error_response(status=404,code='USER_NOT_FOUND',message='User ID does not exist')

    if user_to_promote.role == 'admin':
        return error_response(status=409,code='STATE_CONFLICT',message='Resource state conflict: already admin')

    try:
        user_to_promote.role = 'admin'
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Error promoting user:", e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')

    return jsonify({
        'status': 'success',
        'message': f'User {user_to_promote.pseudo} has been promoted to admin',
        'user': user_to_promote.to_dict()
    }), 200
### DELETE ###
@app.route('/users/me', methods=['DELETE'])
@jwt_required(optional=True)
def delete_user():
    """
    Delete a user connected
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    responses:
      200:
        description: User successfully deleted
      404:
        description: User not found
    """
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')
    
    try:
        user = User.query.get_or_404(current_user_id)
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=404,code='USER_NOT_FOUND',message='User ID does not exist')

    return jsonify({'status': 'success', 'message': 'User successfully deleted'}), 200

######################################################################################
#                                      Authentication
######################################################################################

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
              example: "john@mail.com"
            password:
              type: string
              example: "1234"
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
        description: Invalid password
    """
    data = request.get_json()
    user = User.query.filter_by(mail=data["mail"]).first()

    if user is None:
        return error_response(status=404,code='USER_NOT_FOUND',message='User ID does not exist')

    if user.password != data["password"]:
        return error_response(status=400,code='VALIDATION_FAILED',message='Field validation failed')

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role}
    )

    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify({
        'status': 'success',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'message': 'Login successful'
    }), 200

@app.route("/refresh", methods=["POST"])
@jwt_required(optional=True)
def refresh():
    """
    Refresh access token
    ---
    tags:
      - Authentication
    security:
      - BearerAuth: []
    responses:
      200:
        description: New access token created
      401:
        description: Missing or invalid refresh token
    """
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')

    new_access_token = create_access_token(
        identity=current_user_id
    )

    return jsonify({
        "status": "success",
        "access_token": new_access_token,
        "message": "Access token successfully refreshed"
    }), 200

######################################################################################
#                                      REVIEWS
######################################################################################

### GET ###
@app.route('/reviews/me', methods=['GET'])
@jwt_required(optional=True)
def get_reviews_user():
    """
    Get all reviews for connected user
    ---
    tags:
      - Reviews
    security:
      - BearerAuth: []
    responses:
      200:
        description: Reviews successfully retrieved
      403:
        description: You are not connected
    """
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')
  
    reviews = Review.query.filter_by(user_id=current_user_id).all()

    return jsonify({
        'status': 'success',
        'message': 'Reviews successfully retrieved',
        'data': [review.to_dict() for review in reviews]
    }), 200

@app.route('/books/<int:book_id>/reviews', methods=['GET'])
def get_reviews_book(book_id):
    """
    Get all reviews related to a specific book
    ---
    tags:
      - Reviews
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
    responses:
      200:
        description: Reviews successfully retrieved
      404:
        description: No reviews found for this book
    """
    reviews = Review.query.filter_by(book_id=book_id).all()
    if not reviews:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Book ID does not exist')

    return jsonify({
        'status': 'success',
        'message': 'Reviews successfully retrieved',
        'data': [review.to_dict() for review in reviews]
    }), 200

### POST ###
@app.route('/books/<int:book_id>/reviews', methods=['POST'])
@jwt_required()
def create_review(book_id):
    """
    Create a new review for a specific user and book
    ---
    tags:
      - Reviews
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
        description: ID of the book the review refers to
      - in: body
        name: body
        required: true
        description: Review data
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
            description: Review successfully created
        400:
            description: Invalid JSON or missing fields
        403:
            description: Unauthorized action
        404:
            description: User or book not found
        500:
            description: Error while creating the review

    """
    if not request.json :
        return error_response(status=400,code='BAD_REQUEST',message='The request is not formatted correctly')
    if 'score' not in request.json or 'message' not in request.json :
        return error_response(status=400,code='INVALID_QUERY_PARAM',message='Invalid query parameter value')
    
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')
    user = User.query.get(current_user_id)
    if not user:
        return error_response(status=404,code='USER_NOT_FOUND',message='User ID does not exist')

    book = Book.query.get(book_id)
    if not book:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Ressource ID does not exist')
    
    review = Review(
        user_id=current_user_id,
        book_id=book_id,
        score=request.json['score'],
        message=request.json['message']
    )

    try:
        db.session.add(review)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')

    return jsonify({
        'status': 'success',
        'message': 'Review successfully created',
        'data': review.to_dict()
    }), 201

### PUT ###
@app.route('/reviews/<int:review_id>', methods=['PUT'])
@jwt_required()
def update_review(review_id):
    """
    Update an existing review
    ---
    tags:
      - Reviews
    parameters:
      - name: review_id
        in: path
        required: true
        type: integer
        description: ID of the review to update
      - in: body
        name: body
        required: true
        description: Fields to update for the review
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
        description: Review updated successfully
      400:
        description: Invalid or missing JSON body
      404:
        description: Review not found
    """
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')
    review= Review.query.get_or_404(review_id)
    if not request.json:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Review ID does not exist')   
    
    try:
        review.score = request.json.get('score', review.score)
        review.message = request.json.get('message', review.message)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')
    return jsonify({
        'status': 'success',
        'message': 'Review successfully modified',
        'data': review.to_dict()}),200

### DELETE ###
@app.route('/reviews/<int:review_id>', methods=['DELETE'])
@jwt_required()
def delete_review(review_id):
    """
    Delete a review by ID
    ---
    tags:
      - Reviews
    parameters:
      - name: review_id
        in: path
        required: true
        type: integer
        description: ID of the review to delete
    responses:
      200:
        description: Review successfully deleted
      404:
        description: Review not found
    """
    try:
        review = Review.query.get_or_404(review_id)
        db.session.delete(review)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Review ID does not exist')  

    return jsonify({'status': 'success', 'message': 'Reviewsuccessfully deleted'}), 200

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
    try:
      books = Book.query.all()
    except Exception as e:
        print(e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')
    
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
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Book ID does not exist') 

    return jsonify({
        'status': 'success',
        'message': 'Book successfully retrieved',
        'data': book.to_dict()
    }), 200

@app.route('/books/author', methods=['GET'])
def get_books_author():
    """
    Get all books filter by author.
    ---
    tags:
      - Books
    parameters:
      - in: query
        name: author
        schema:
          type: string
        required: false
        description: Filter books by author's name
    responses:
      200:
        description: List of books
    """
    if not request.json :
        return error_response(status=400,code='BAD_REQUEST',message='The request is not formatted correctly')
    if 'author' not in request.json :
        return error_response(status=400,code='INVALID_QUERY_PARAM',message='Invalid query parameter value')
    
    try:
      books = Book.query.all()
    except Exception as e:
        print(e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')
    
    book_author=[]
    for book in books:
        if book.author==request.args.get("author",type=str):
            book_author.append(book)

    return jsonify({
        'status': 'success',
        'message': 'Books successfully retrieved',
        'data': [book.to_dict() for book in book_author]
    }), 200

### POST ###
@app.route('/books', methods=['POST'])
@jwt_required(optional=True)
def create_book():
    """
    Create a new book
    ---
    tags:
      - Books
    security:
      - BearerAuth: []
    parameters:
      - in: body
        name: body
        required: true
        description: Book data
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
              example: "John Doe"
            title:
              type: string
              example: "Lorem Ipsum"
            category:
              type: string
              example: "Romance"
            publisher:
              type: string
              example: "Lorem Publishing"
            summary:
              type: string
              example: "A good romance"
            isbn:
              type: string
              example: "0000000000"
            price:
              type: number
              example: 15000
            publication_date:
              type: string
              example: "1999-07-08"
              format: date
    responses:
      201:
        description: Book successfully created
      400:
        description: Invalid or missing fields
      403:
        description: Only admins can create books
      409:
        description: ISBN already used
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return error_response(status=403,code='FORBIDDEN',message='No access')
    
    requiered_fields = ['author', 'title', 'category', 'publisher', 'isbn', 'price', 'publication_date']
    if not request.json :
        return error_response(status=400,code='BAD_REQUEST',message='The request is not formatted correctly')
    if not all(key in request.json for key in requiered_fields) :
        return error_response(status=400,code='INVALID_QUERY_PARAM',message='Invalid query parameter value')
    
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
        return error_response(status=409,code='STATE_CONFLICT',message='Resource state conflict: ISBN already used')
    
    return jsonify({
        'status': 'success',
        'message': 'Book successfully created',
        'data': book.to_dict()
    }), 201

### DELETE ###
@app.route('/books/<int:book_id>', methods=['DELETE'])
@jwt_required(optional=True)
def delete_book(book_id):
    """
    Delete a book by its ID
    ---
    tags:
      - Books
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        schema:
          type: integer
    responses:
      200:
        description: Book successfully deleted
      403:
        description: Only admins can delete books
      404:
        description: Book does not exist
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return error_response(status=403,code='FORBIDDEN',message='No access')
    try:
        book = Book.query.get_or_404(book_id)
        db.session.delete(book)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Book ID does not exist') 

    return jsonify({'status': 'success', 'message': 'Book successfully deleted'}), 200

### PUT ###
@app.route('/books/<int:book_id>', methods=['PUT'])
@jwt_required(optional=True)
def update_book(book_id):
    """
    Update a book by its ID
    ---
    tags:
      - Books
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        schema:
          type: integer
      - in: body
        name: body
        required: true
        description: Book data
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
              example: "John Doe"
            title:
              type: string
              example: "Lorem Ipsum"
            category:
              type: string
              example: "Romance"
            publisher:
              type: string
              example: "Lorem Publishing"
            summary:
              type: string
              example: "A good romance"
            isbn:
              type: string
              example: "0000000000"
            price:
              type: number
              example: 15000
            publication_date:
              type: string
              example: "1999-07-08"
              format: date
    responses:
      200:
        description: Book successfully modified
      400:
        description: Invalid or missing JSON
      403:
        description: Only admins can modify books
      404:
        description: Book does not exist
      409:
        description: ISBN already used
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return error_response(status=403,code='FORBIDDEN',message='No access')
    
    requiered_fields = ['author', 'title', 'category', 'publisher', 'isbn', 'price', 'publication_date']
    if not request.json :
        return error_response(status=400,code='BAD_REQUEST',message='The request is not formatted correctly')
    if not all(key in request.json for key in requiered_fields) :
        return error_response(status=400,code='INVALID_QUERY_PARAM',message='Invalid query parameter value')
    
    book = Book.query.get(book_id)
    if book is None:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Book ID does not exist') 

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
        return error_response(status=409,code='STATE_CONFLICT',message='Resource state conflict: ISBN already used')

    return jsonify({
        'status': 'success',
        'message': 'Book successfully modified',
        'data': book.to_dict()
    }), 200

######################################################################################
#                                      CATEGORIES
######################################################################################

### GET Books ###
@app.route('/categories', methods=['GET'])
def get_categories():
    """
    Get all categories
    ---
    tags:
      - Categories
    responses:
      200:
        description: List of all categories
    """    
    try:
      categories = Category.query.all()
    except Exception as e:
        print(e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')
    
    return jsonify({
        'status': 'success',
        'message': 'Categories successfully retrieved',
        'data': [cat.to_dict() for cat in categories]
    }), 200

@app.route('/categories/<int:cat_id>', methods=['GET'])
def get_category(cat_id):
    """
    Get a category by its ID
    ---
    tags:
      - Categories
    parameters:
      - name: cat_id
        in: path
        required: true
        type: integer
    responses:
      200:
        description: Book successfully retrieved
      404:
        description: Book not found
    """
    cat = Category.query.get(cat_id)
    if not cat:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Category ID does not exist') 

    return jsonify({
        'status': 'success',
        'message': 'Category successfully retrieved',
        'data': cat.to_dict()
    }), 200

@app.route('/categories/<int:category_id>/books', methods=['GET'])
def get_books_by_category(category_id):
    """
    Get all books for a given category
    ---
    tags:
      - Categories
    parameters:
      - in: path
        name: category_id
        required: true
        type: integer
    responses:
      200:
        description: Books retrieved
      404:
        description: Category not found
    """

    category = Category.query.get(category_id)
    if not category:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Category ID does not exist') 

    books = [book.to_dict() for book in category.books]
    return jsonify({
        "status": "success",
        "message": "Books retrieved",
        "data": books
    }), 200

### POST ###
@app.route('/categories', methods=['POST'])
@jwt_required(optional=True)
def create_category():
    """
    Create a new category
    ---
    tags:
      - Categories
    security:
      - BearerAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
              example: "Action"
    responses:
      201:
        description: Category successfully created
      400:
        description: Invalid or missing fields
      403:
        description: Only admins can create categories
      409:
        description: Category already exists
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return error_response(status=403,code='FORBIDDEN',message='No access')
      
    if not request.json :
        return error_response(status=400,code='BAD_REQUEST',message='The request is not formatted correctly')
    if 'name' not in request.json:
        return error_response(status=400,code='INVALID_QUERY_PARAM',message='Invalid query parameter value')
    
    cat = Category(name=request.json['name'])

    try:
        db.session.add(cat)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=409,code='STATE_CONFLICT',message='Resource state conflict: Category already used')
    
    return jsonify({
        'status': 'success',
        'message': 'Category successfully created',
        'data': cat.to_dict()
    }), 201

### PATCH ###
@app.route('/categories/<int:category_id>', methods=['PATCH'])
@jwt_required(optional=True)
def update_category(category_id):
    """
    Update category name
    ---
    tags:
      - Categories
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: category_id
        required: true
        type: integer
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
              example: "NewCat"
    responses:
      200:
        description: Category updated
      400:
        description: Invalid fields
      403:
        description: Only admins can update categories
      404:
        description: Category not found
      409:
        description: Category name already exists
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return error_response(status=403,code='FORBIDDEN',message='No access')

    if not request.json :
        return error_response(status=400,code='BAD_REQUEST',message='The request is not formatted correctly')
    if 'name' not in request.json:
        return error_response(status=400,code='INVALID_QUERY_PARAM',message='Invalid query parameter value')
    
    new_name = request.json["name"]
    category = Category.query.get(category_id)
    if not category:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Category ID does not exist') 

    try:
        category.name = new_name
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=409,code='STATE_CONFLICT',message='Resource state conflict: Category already used')

    return jsonify({
        'status': 'success',
        'message': 'Category successfully updated',
        'data': category.to_dict()
    }), 200

### DELETE ###
@app.route('/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    """
    Delete a category
    ---
    tags:
      - Categories
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: category_id
        required: true
        type: integer
    responses:
      200:
        description: Category deleted
      403:
        description: Only admins can delete categories
      404:
        description: Category not found
      409:
        description: Category has books attached
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return error_response(status=403,code='FORBIDDEN',message='No access')

    category = Category.query.get(category_id)
    if not category:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Category ID does not exist')

    if len(category.books) > 0:
        return error_response(status=409,code='STATE_CONFLICT',message='Resource state conflict: Category already used')

    try:
        db.session.delete(category)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')

    return jsonify({
        "status": "success",
        "message": "Category successfully deleted",
        "data": category.to_dict()
    }), 200

######################################################################################
#                                      WISHLIST
######################################################################################

### GET ###
@app.route('/wishlist/me', methods=['GET'])
@jwt_required(optional=True)
def get_wishlist():
    """
    Get wishlist for connected user
    ---
    tags:
      - Wishlist
    security:
      - BearerAuth: []
    responses:
      200:
        description: Wishlist successfully retrieved
      403:
        description: You are not connected
    """
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')

    wishlists = Wishlist.query.filter_by(user_id=current_user_id).all()

    return jsonify({
        'status': 'success',
        'message': 'Reviews successfully retrieved',
        'data': [wish.to_dict() for wish in wishlists]
    }), 200

@app.route('/wishlit/<int:book_id>/users', methods=['GET'])
@jwt_required(optional=True)
def get_users_by_favorite_book(book_id):
    """
    Get all users who have this book in their favorites
    ---
    tags:
      - Wishlist
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
    responses:
      200:
        description: List of users who favorited the book
      403:
        description: Only admins can update categories
      404:
        description: Book not found
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return error_response(status=403,code='FORBIDDEN',message='No access')
  
    book = Book.query.get(book_id)
    if not book:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Book ID does not exist')

    wishes = Wishlist.query.filter_by(book_id=book_id).all()
    users = [User.query.get(fav.user_id).to_dict() for fav in wishes]

    return jsonify({
        'status': 'success',
        'message': 'Users successfully retrieved',
        'data': users
    }), 200

### POST ###
@app.route('/wishlist/<int:book_id>', methods=['POST'])
@jwt_required()
def add_to_wishlist(book_id):
    """
    Add a book to the user's wishlist
    ---
    tags:
      - Wishlist
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
        description: ID of the book to add to wishlist
    responses:
        201:
            description: Book successfully added to wishlist
        400:
            description: Book already in wishlist
        404:
            description: User or book not found
        500:
            description: Error while adding book to wishlist
    """
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')
    
    user = User.query.get(current_user_id)
    if not user:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='User ID does not exist')

    book = Book.query.get(book_id)
    if not book:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Book ID does not exist')

    existing = Wishlist.query.filter_by(user_id=current_user_id, book_id=book_id).first()
    if existing:
        return jsonify({'status': 'error', 'message': 'Book already in wishlist'}), 400

    wish = Wishlist(
        user_id=current_user_id,
        book_id=book_id,
    )

    try:
        db.session.add(wish)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')

    return jsonify({
        'status': 'success',
        'message': 'Book successfully added to wishlist',
        'data': wish.to_dict()
    }), 201

### DELETE ###
@app.route('/wishlist/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_wishlist_item(book_id):
    """
    Delete a wishlist item
    ---
    tags:
      - Wishlist
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
    responses:
      200:
        description: Wishlist item deleted successfully
      403:
        description: Unauthorized action
      404:
        description: Wishlist item not found
      500:
        description: Error while deleting the wishlist item
    """
    current_user_id = get_jwt_identity()
    if current_user_id is None:
        return error_response(status=401,code='UNAUTHORIZED',message='No authentication token or invalid token')

    wish = Wishlist.query.filter_by(book_id=book_id, user_id=current_user_id).first()
    if not wish:
        return error_response(status=404,code='RESSOURCE_NOT_FOUND',message='Wishlist ID does not exist')

    try:
        db.session.delete(wish)
        db.session.commit()
    except Exception as e:
        print(e)
        return error_response(status=500,code='INTERNAl_SERVER_ERROR',message='Internal server error')

    return jsonify({
        'status': 'success',
        'message': 'Wishlist item deleted successfully'
    }), 200


if __name__ == '__main__':
    app.run(debug=True)
