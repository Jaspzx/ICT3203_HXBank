import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.BankAccountManagementController import *

app = create_test_webportal()


class RegisterTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    acc_number1 = ""
    acc_number2 = ""

    def setUp(self):
        """
        Test the setting up of the db with values.
        """
        password1 = flask_bcrypt.generate_password_hash("Password1_")
        password2 = flask_bcrypt.generate_password_hash("Password2_")
        self.client = app.test_client()
        with app.app_context():
            db.create_all()
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S1234123Q",
                              "1111-11-11", password1, None, None, 0)
            self.amc.add_user("test1", "Bernard", "Tan", "10kkj", "bernardtan@gmail.com", "98765432", "S1234123W",
                              "1111-11-11", password2, None, None, 0)
            self.acc_number1, welcome_amt1 = self.bamc.add_bank_account(
                User.query.filter_by(username="test").first().id)
            self.acc_number2, welcome_amt2 = self.bamc.add_bank_account(
                User.query.filter_by(username="test1").first().id)

    def testInit(self):
        """
        Test the initialization of values.
        """
        with app.app_context():
            user = self.amc.decrypt_by_username(username="test")
            self.assertEqual(user.username, "test")
            self.assertEqual(user.firstname, "Raymond")
            self.assertEqual(user.lastname, "Tan")
            self.assertEqual(user.address, "10kkj")
            self.assertEqual(user.email, "raymondtan@gmail.com")
            self.assertEqual(user.mobile, "98765433")
            self.assertEqual(user.nric, "S1234123Q")
            self.assertEqual(user.dob, "1111-11-11")

    def testRegister(self):
        """
        Tests registration success
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S9584634E", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'I am done. Take me to Login.', response.data)

    def testRegisterIP(self):
        """
        Tests registration password validation
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "password1", "confirm_password": "password1",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S9584634E", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Password complexity not met', response.data)

    def testRegisterPNM(self):
        """
        Tests registration password match validation
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ13",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S9584634E", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Passwords must match', response.data)

    def testRegisterIE(self):
        """
        Tests registration email validation
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test", "mobile": "123123123",
                                                               "nric": "S9584634E", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Invalid email address.', response.data)

    def testRegisterIID(self):
        """
        Tests registration ID validation
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S95846343", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Invalid Identification no.', response.data)

    def testRegisterID(self):
        """
        Tests registration date validation
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S9584634Q", "dob": "test",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Not a valid date value.', response.data)

    def testRegisterIM(self):
        """
        Tests registration mobile validation
        """
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test@gmail.com", "mobile": "123123aaa",
                                                               "nric": "S9584634Q", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Invalid mobile', response.data)

    def testDuplicateUser(self):
        """
        Test if a duplicate user can be duplicated.
        """
        password1 = flask_bcrypt.generate_password_hash("password1")
        with app.app_context():
            self.assertEqual(self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433",
                                               "S12341235", "11-11-1111", password1, None, None, 0), None)

    def testDuplicateAccount(self):
        """
        Test if a bank account can be duplicated.
        """
        with app.app_context():
            self.assertEqual(self.bamc.add_bank_account(User.query.filter_by(username="test").first().id), (None, None))

    def tearDown(self):
        """
        Tear down the unit test.
        """
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
