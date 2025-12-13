
class TestBooks:

    def test_get_book(self, client):
        response = client.get('/books')
        assert response.status_code == 200
    
    def test_get_books_by_author(self, client, book):
        response = client.get(
            "/books/author",
            query_string={"author": "Tolkien"}
        )
        assert response.status_code == 200

    def test_get_books_by_author_wrong(self, client, book):
        response = client.get(
            "/books/author",
            query_string={"author": ""}
        )
        assert response.status_code == 400

    def test_create_book_not_admin(self, client,category):
        data = {
            "author":"NewTolkien",
            "title":"Le Seigneur des Anneaux",
            "category_id":category,  
            "publisher":"HarperCollins",
            "summary":"Lorem Ipsum",
            "isbn":"0000000000",
            "price":25000,
            "publication_date":"1954-07-29",
        }
        response = client.post('/books', json=data)
        assert response.status_code == 403

    def test_create_book_admin(self, client, category, admin_token):
        data = {
            "author": "NewTolkien",
            "title": "Le Seigneur des Anneaux",
            "category_id": category,
            "publisher": "HarperCollins",
            "summary": "A great book.",
            "isbn": "1111111111",
            "price": 25000,
            "publication_date": "1954-07-29",
        }

        headers = {"Authorization": f"Bearer {admin_token}"}
        response = client.post('/books', json=data, headers=headers)
        assert response.status_code == 201
    
    def test_update_book_admin(self, client, book, category, admin_token):
        data = {
            "author": "NewTest",
            "title": "Lorem Ipsum",
            "category_id": category,
            "publisher": "John Doe",
            "summary": "A book",
            "isbn": "0123456789",
            "price": 25000,
            "publication_date": "1954-07-29",
        }

        headers = {"Authorization": f"Bearer {admin_token}"}
        response = client.put(f'/books/{book}',json=data,headers=headers)
        assert response.status_code == 200
    
    def test_delete_book(self,client,book,admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = client.delete(f'/books/{book}',headers=headers)
        assert response.status_code == 200
    
    def test_delete_book_not_admin(self,client,book,):
        headers = {"Authorization": ""}
        response = client.delete(f'/books/{book}',headers=headers)
        assert response.status_code == 403

   