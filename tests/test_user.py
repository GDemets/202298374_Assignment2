
class TestUsers:

    def test_get_user_profile(self, client):
        response = client.get('/users')
        assert response.status_code == 200

    def test_create_user(self, client):
        data = {
            "pseudo": "test",
            "mail": "test@mail.com",
            "password": "1234"
        }
        response = client.post('/users', json=data)
        assert response.status_code == 201

    def test_update_me(self, client, user_token):
        data = {
            "pseudo": "newtest",
            "mail": "newtest@mail.com",
            "password": "new1234"
        }
        headers = {"Authorization": f"Bearer {user_token}"}
        response = client.put('/users/me', json=data, headers=headers)
        assert response.status_code == 200
    
    def test_get_me_connected(self, client, user_token):
        headers = {"Authorization": f"Bearer {user_token}"}
        response = client.get('/users/me', headers=headers)
        assert response.status_code == 200
    
    def test_get_me_not_connected(self, client):
        headers = {"Authorization": ""}
        response = client.get('/users/me', headers=headers)
        assert response.status_code == 401
