import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *

app = create_test_webportal()


class ResetpwdTest(unittest.TestCase):
    amc = AccountManagementController()

    def setUp(self):
        """
        Test the setting up of the db with values.
        """
        password = flask_bcrypt.generate_password_hash("Password1_")
        self.client = app.test_client()
        with app.app_context():
            db.create_all()
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S1234123Q",
                              "1111-11-11", password, None, None, 0)
            user = User.query.filter_by(username="test").first()
            newpass = flask_bcrypt.generate_password_hash("Password11_")
            self.amc.reset_pwd(user, newpass)

    def testLogin(self):
        """
        Test the login with the newly changed password.
        """
        with app.app_context():
            user = User.query.filter_by(username="test").first()
            authenticate = self.amc.authenticate(user, "Password11_")
            self.assertEqual(authenticate, 1)

    def testIdentify(self):
        """
        Test the reset identify with all correct values
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/reset-identify?type=pwd', data={"username": "test", "nric": "S1234123Q",
                                                                              "dob": "1111-11-11"}, follow_redirects=True)
                self.assertIn(b'Authenticate Yourself', response.data)

    def testUsernameI(self):
        """
        Test the reset identify with wrong username
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/reset-identify?type=pwd', data={"username": "test1", "nric": "S1234123Q",
                                                                              "dob": "1111-11-11"}, follow_redirects=True)
                self.assertIn(b'Identification Failed', response.data)

    def testIDI(self):
        """
        Test the reset identify with wrong ID
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/reset-identify?type=pwd', data={"username": "test", "nric": "S1234123R",
                                                                              "dob": "1111-11-11"}, follow_redirects=True)
                self.assertIn(b'Identification Failed', response.data)

    def testDOBI(self):
        """
        Test the reset identify with wrong DOB
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/reset-identify?type=pwd', data={"username": "test", "nric": "S1234123Q",
                                                                              "dob": "1111-11-12"}, follow_redirects=True)
                self.assertIn(b'Identification Failed', response.data)

    def tearDown(self):
        """
        Tear down the unit test.
        """
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
