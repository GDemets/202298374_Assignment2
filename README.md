# WSD Assignment2

## Description
This project is a **RESTful API developed with Flask** for managing a **bookstore**.

Key Components

Flask Application

Entry point: app.py

REST endpoints defined using Flask routes

Swagger documentation via Flasgger

Authentication & Security

JWT managed by flask-jwt-extended

Access token expiration: 15 minutes

Role-based access using JWT claims

Database Layer

ORM: SQLAlchemy

Automatic table creation on app startup (non-testing mode)

Entities: User, Book, Category, Review, Wishlist

Configuration Management

Environment variables loaded via python-dotenv

Sensitive values stored in .env

Error Handling

Custom error responses via error_response

Consistent JSON error format across the API

## Data Models Overview

* **User**: pseudo, email, password (hashed), role
* **Book**: author, title, category, publisher, ISBN, price, publication date
* **Category**: name, linked books
* **Review**: score and message linked to a user and a book
* **Wishlist**: association between users and books

---

## API Access

### API Root Address

### Swagger Documentation

Swagger UI is available in localhost at:

```
http://localhost:5000/apidocs
```

Swagger UI is available with Jcloud at:
```
http://113.198.66.75:10216/apidocs
```

---

## Installation & Setup

### Install dependencies

```bash
pip install -r requirements.txt
```
---

### Initialize the database

```bash
cd scripts
python seed.py
```
---

### Run the application

```bash
python app.py
```
---

## Testing

Tests are written using **pytest** and located in the `tests/` directory.

Run tests with:

```bash
pytest -v
```
---

## Project Structure

```
repo-root
├─ README.md
├─ .gitignore 
├─ postman/
│  └─ bookstore.postman_collection.json
├─ src/                  
├─ scripts/               
└─ tests/                 
```