from flask import Flask, request, jsonify, abort, render_template
from flasgger import Swagger
from models import db, User, Review, Book, Category
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
import logging
from datetime import datetime

# TODO: 
# JWT   user : delete post, update post, delete user, update user
# Authentication : logout, refresh token
# Book : get a book by is category, author or title
# THE CODE IS TOO LONG
# .env for secret key
# Bcrypt for password hashing
 


### Flask App and Database Configuration ###
app = Flask(__name__)
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///BookStore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "0123456789"   #openssl rand -hex 64
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
    print(f"azerty: {current_user_id}")
    if current_user_id is None:
        return jsonify({'status': 'error', 'message': 'You are not connected'}), 403
    
    user = User.query.get(current_user_id)
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
    print(f"azerty: {current_user_id}")
    if current_user_id is None:
        return jsonify({'status': 'error', 'message': 'You are not connected'}), 403
    
    if not request.json or 'mail' not in request.json:
        return {'message': 'Format invalid or missing values', 'status': 'error'}, 400
    
    try:
        user = User.query.get(current_user_id)
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
    print(f"azerty: {current_user_id}")
    if current_user_id is None:
        return jsonify({'status': 'error', 'message': 'You are not connected'}), 403
    
    try:
        user = User.query.get_or_404(current_user_id)
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'User does not exist'}), 404

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
        return jsonify({'status': 'error', 'message': 'User does not exist'}), 404

    if user.password != data["password"]:
        return jsonify({'status': 'error', 'message': 'Invalid password'}), 401

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role}
    )

    return jsonify({
        'status': 'success',
        'access_token': access_token,
        'message': 'Login successful'
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
        return jsonify({'status': 'error', 'message': 'You are not connected'}), 403
  
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
        return jsonify({'status': 'error', 'message': 'The corresponding books were not found.'}), 404

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
    current_user_id = get_jwt_identity()

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    book = Book.query.get(book_id)
    if not book:
        return jsonify({'status': 'error', 'message': 'Book not found'}), 404

    if not request.json or 'score' not in request.json or 'message' not in request.json:
        return jsonify({'status': 'error', 'message': 'Invalid JSON or Missing score or message'}), 400

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
        return jsonify({'status': 'error', 'message': 'Error while creating review'}), 500

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
    try:
        review= Review.query.get_or_404(review_id)
        if not request.json:
            abort(400)        
        review.score = request.json.get('score', review.score)
        review.message = request.json.get('message', review.message)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'Review does not exist'}), 404
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
        return jsonify({'status': 'error', 'message': 'Review does not exist'}), 404

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
        return jsonify({
            "status": "error",
            "message": "Only admins can create books"
        }), 403
    
    requiered_fields = ['author', 'title', 'category', 'publisher', 'isbn', 'price', 'publication_date']
    if not request.json or not all(key in request.json for key in requiered_fields):
        return jsonify({'status': 'error','message': 'Format invalid or missing values'}), 400
    
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
        return jsonify({
            "status": "error",
            "message": "Only admins can delete books"
        }), 403
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
        return jsonify({
            "status": "error",
            "message": "Only admins can modify books"
        }), 403
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
    categories = Category.query.all()
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
        return jsonify({'status': 'error', 'message': 'Category not found'}), 404

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
        return jsonify({
            "status": "error",
            "message": "Category not found"
        }), 404

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
        return jsonify({
            "status": "error",
            "message": "Only admins can create categories"
        }), 403
    
    if not request.json or "name" not in request.json:
        return jsonify({
            'status': 'error',
            'message': 'Format invalid or missing values'
        }), 400
    
    cat = Category(name=request.json['name'])

    try:
        db.session.add(cat)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({
            'status': 'error',
            'message': 'Category already exists'
        }), 409
    
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
        return jsonify({
            "status": "error",
            "message": "Only admins can update categories"
        }), 403

    if not request.json or "name" not in request.json:
        return jsonify({
            'status': 'error',
            'message': 'Missing or invalid fields'
        }), 400

    new_name = request.json["name"]

    category = Category.query.get(category_id)
    if not category:
        return jsonify({
            'status': 'error',
            'message': 'Category not found'
        }), 404

    category.name = new_name

    try:
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({
            'status': 'error',
            'message': 'Category name already exists'
        }), 409

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
        return jsonify({
            "status": "error",
            "message": "Only admins can delete categories"
        }), 403

    category = Category.query.get(category_id)
    if not category:
        return jsonify({
            "status": "error",
            "message": "Category not found"
        }), 404

    if len(category.books) > 0:
        return jsonify({
            "status": "error",
            "message": "Category cannot be deleted because books are associated with it"
        }), 409

    try:
        db.session.delete(category)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({
            "status": "error",
            "message": "An error occurred while deleting category"
        }), 500

    return jsonify({
        "status": "success",
        "message": "Category successfully deleted",
        "data": category.to_dict()
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
