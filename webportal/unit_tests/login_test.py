import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *

app = create_test_webportal()


class LoginTest(unittest.TestCase):
    amc = AccountManagementController()

    def setUp(self):
        """
        Setting up of the db with values.
        """
        password1 = flask_bcrypt.generate_password_hash("Password1_")
        self.client = app.test_client()
        with app.app_context():
            db.create_all()
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S1234123Q",
                              "1111-11-11", password1, None, None, 0)

    def testInit(self):
        """
        Test the initialization of values.
        """
        with app.app_context():
            user = User.query.filter_by(username="test").first()
            authenticate = self.amc.authenticate(user, "Password1_")
            self.assertEqual(authenticate, 1)

    def testLogin(self):
        """
        Tests login
        """
        with app.app_context():
            response = app.test_client().post('/login', data={"username": "test", "password": "Password1_"},
                                              follow_redirects=True)
            self.assertIn(b'Enter OTP Code', response.data)

    def testPassword(self):
        """
        Tests invalid password
        """
        with app.app_context():
            response = app.test_client().post('/login', data={"username": "test", "password": "password123"},
                                              follow_redirects=True)
            self.assertIn(b'Login Failed', response.data)

    def testUsername(self):
        """
        Tests invalid username
        """
        with app.app_context():
            response = app.test_client().post('/login', data={"username": "te5t@", "password": "p@ssword123_"},
                                              follow_redirects=True)
            self.assertIn(b'Invalid username', response.data)

    def testOtpX(self):
        """
        Test OTP > 6 numbers
        """
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"},
                                 follow_redirects=True)
                response = self.client.post('/otp-input', data={"token": "355467777"},
                                            follow_redirects=True)
                self.assertIn(b'Field must be exactly 6 characters long', response.data)

    def testOtpA(self):
        """
        Test OTP with alphanumerical
        """
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"},
                                 follow_redirects=True)
                response = self.client.post('/otp-input', data={"token": "a35546"},
                                            follow_redirects=True)
                self.assertIn(b'Invalid input', response.data)

    def testOtpC(self):
        """
        Test OTP with repeated OTP
        """
        with app.app_context():
            with self.client:
                user = User.query.filter_by(username="test").first()
                user.prev_token = "135546"
                update_db_no_close()
                self.client.post('/login', data={"username": "test", "password": "Password1_"},
                                 follow_redirects=True)
                response = self.client.post('/otp-input', data={"token": "135546"},
                                            follow_redirects=True)
                self.assertIn(b'Something went wrong', response.data)

    def tearDown(self):
        """
        Tear down the unit test.
        """
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
