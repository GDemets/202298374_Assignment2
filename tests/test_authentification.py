 
class TestAuth:

    def test_login_success(self, client, user):
        data = {
            "mail": "test@example.com",
            "password": "1234"
        }
        response = client.post('/login', json=data)
        assert response.status_code == 200

    def test_login_wrong_email(self, client, user):
        data = {
            "mail": "wrong@mail.com",
            "password": "1234"
        }
        response = client.post('/login', json=data)
        assert response.status_code == 404
    
    def test_login_wrong_password(self, client, user):
        data = {
            "mail": "test@example.com",
            "password": "wrongpassword"
        }
        response = client.post('/login', json=data)
        assert response.status_code == 401
