from flask import Flask, request, jsonify, abort, render_template
from models import db, User, Post, Book
import logging
from datetime import datetime

### Flask App and Database Configuration ###
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///BookStore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def create_tables(): 
    db.create_all() 

app.before_request(create_tables) 

### Middleware to log requests ### 
@app.before_request 
def log_request_info(): 
    logging.info(f"{datetime.utcnow().isoformat()} - {request.method} {request.path}")

######################################################################################
#### GET Endpoints ###
######################################################################################

### Users ###
@app.route('/users', methods=['GET'])
def get_users():
    """Get all users"""
    users = User.query.all()
    return jsonify({
        'status': 'success',
        'message': 'Users successfully retrieved',
        'data': [user.to_dict() for user in users]
    }), 200

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a user by ID"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'status': 'error',
            'message': 'User not found'
        }), 404

    return jsonify({
        'status': 'success',
        'message': 'User successfully retrieved',
        'data': user.to_dict()  
    }), 200

#### Books ###
@app.route('/books', methods=['GET'])
def get_books():
    """Get all books"""
    books = Book.query.all()
    return jsonify({
        'status': 'success',
        'message': 'Books successfully retrieved',
        'data': [book.to_dict() for book in books]
    }), 200

@app.route('/books/<int:book_id>', methods=['GET'])
def book_user(book_id):
    """Get a book by ID"""
    book = Book.query.get(book_id)
    if not book:
        return jsonify({
            'status': 'error',
            'message': 'Book not found'
        }), 404

    return jsonify({
        'status': 'success',
        'message': 'Book successfully retrieved',
        'data': book.to_dict()  # Pas besoin de mettre dans une liste
    }), 200

### Posts ###
@app.route('/users/<int:user_id>/posts', methods=['GET'])
def get_posts_user(user_id):
    """Get all posts for a user"""
    posts = Post.query.filter_by(user_id=user_id).all()
    if not posts:
        return jsonify({
            'status': 'error',
            'message': 'The corresponding books were not found.'
        }), 404

    return jsonify({
        'status': 'success',
        'message': 'Posts successfully retrieved',
        'data': [post.to_dict() for post in posts]   
    }), 200

@app.route('/books/<int:book_id>/posts', methods=['GET'])
def get_posts_book(book_id):
    """Get all posts for a user"""
    posts = Post.query.filter_by(book_id=book_id).all()
    if not posts:
        return jsonify({
            'status': 'error',
            'message': 'The corresponding books were not found.'
        }), 404

    return jsonify({
        'status': 'success',
        'message': 'Posts successfully retrieved',
        'data': [post.to_dict() for post in posts]  
    }), 200
######################################################################################
#### POST Endpoints ####
######################################################################################
@app.route('/users',methods=['POST'])
def create_user():
    """Create a new user"""
    if not request.json or 'pseudo' not in request.json or 'mail' not in request.json or 'password' not in request.json:
        response_data = {
            'message': 'Format invalid or missing values',
            'status': 'error'
            }
        return response_data, 400
    
    user = User(
        pseudo=request.json.get('pseudo'),
        mail=request.json.get('mail'),
        password=request.json.get('password'),
        role="user"
    )

    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'status':'error',
                        'message':'User already exists'}), 409
    
    return jsonify({'status':'success',
                    'message':'User successfully created',
                    'data':[user.to_dict()]
                   }), 201

@app.route('/users/<int:user_id>/posts', methods=['POST'])
def create_post(user_id):
    """Create a new post for a specific user"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'status': 'error',
            'message': 'User not found'
        }), 404
    post = request.get_json()
    if 'score' not in post or 'message' not in post:
        return jsonify({
            'status': 'error',
            'message': 'Format invalid or missing values'
        }), 400
    new_post = Post(
            user_id=user_id,
            score=post['score'],
            message=post['message']
        )
    try:
        db.session.add(new_post)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({
            'status': 'error',
            'message': 'Error while creating post'
        }), 500

    return jsonify({
        'status': 'success',
        'message': 'Post successfully created',
        'data': new_post.to_dict()
    }), 201

######################################################################################
### PUT Endpoints ###
######################################################################################

@app.route('/users/mail/<int:user_id>', methods=['PUT'])
def update_mail_student(user_id):
    """Update the mail of an existing user"""   
    if not request.json or 'mail' not in request.json :
        response_data = {
            'message': 'Format invalid or missing values',
            'status': 'error'
            }
        return response_data, 400 
    try:
        user=User.query.get(user_id)
        user.mail = request.json.get('mail',user.mail)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({
            'status': 'error',
            'message': 'User does not exist'
        }), 404

    return jsonify({
        'status': 'success',
        'message': 'User successfully modified',
        'data': user.to_dict()
    }), 200

@app.route('/users/pseudo/<int:user_id>', methods=['PUT'])
def update_pseudo_student(user_id):
    """Update the pseudo of an existing user"""   
    if not request.json or 'pseudo' not in request.json :
        response_data = {
            'message': 'Format invalid or missing values',
            'status': 'error'
            }
        return response_data, 400 
    
    user=User.query.get(user_id)
    if user is None:
        return jsonify({
            'status': 'error',
            'message': 'User does not exist'
        }), 404
    
    try:
        user.pseudo = request.json.get('pseudo',user.pseudo)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({
            'status': 'error',
            'message': 'Pseudo already use'
        }), 409

    return jsonify({
        'status': 'success',
        'message': 'User successfully modified',
        'data': user.to_dict()
    }), 200

######################################################################################
### DELETE Endpoints ###
######################################################################################

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete an existing user"""
    try:
        user=User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({
            'status': 'error',
            'message': 'User does not exist'
        }), 404
    
    return jsonify({'status':'success',
                    'message':'User successfully deleted'
                   }), 200

@app.route('/users', methods=['DELETE'])
def delete_all_users():
    """Delete all users"""
    if len(User.query.all()) == 0:
        return jsonify({
            'status': 'error',
            'message': 'No users to delete'
        }), 404
    try:
        User.query.delete()
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while deleting users'
        }), 500

    return jsonify({
        'status': 'success',
        'message': 'All users successfully deleted'
    }), 200


if __name__=='__main__':
    app.run(debug=True)