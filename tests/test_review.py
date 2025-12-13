
class TestReview:

    def test_get_reviews(self, client, book, review):
        response = client.get(f'/books/{book}/reviews')
        assert response.status_code == 200
    
    def test_create_review_connected(self, client, user, book, user_token):
        data={
            "user_id":user,
            "book_id":book,
            "score":4,
            "message":"A new review"
        }
        headers = {"Authorization": f"Bearer {user_token}"}
        response = client.post(f'/books/{book}/reviews', json=data, headers=headers)
        assert response.status_code == 201
    
    def test_create_review_not_connected(self, client, user, book):
        data={
            "user_id":user,
            "book_id":book,
            "score":4,
            "message":"A new review"
        }
        headers = {"Authorization": ""}
        response = client.post(f'/books/{book}/reviews', json=data, headers=headers)
        assert response.status_code == 401

    def test_create_review_missing_value(self, client, user_token,book):
        data={}
        headers = {"Authorization": f"Bearer {user_token}"}
        response = client.post(f'/books/{book}/reviews', json=data, headers=headers)
        assert response.status_code == 400