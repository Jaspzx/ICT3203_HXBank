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
        password1 = flask_bcrypt.generate_password_hash("password1")
        password2 = flask_bcrypt.generate_password_hash("password2")
        with app.app_context():
            db.create_all()
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S12341235",
                         "11-11-1111", password1, None, None, 0)
            self.amc.add_user("test1", "Bernard", "Tan", "10kkj", "bernardtan@gmail.com", "98765432", "S12341234",
                         "11-11-1111", password2, None, None, 0)
            self.acc_number1, welcome_amt1 = self.bamc.add_bank_account(User.query.filter_by(username="test").first().id)
            self.acc_number2, welcome_amt2 = self.bamc.add_bank_account(User.query.filter_by(username="test1").first().id)

    def testInit(self):
        """
        Test the initilisation of values.
        """
        with app.app_context():
            user = self.amc.decrypt_by_username(username="test")
            self.assertEqual(user.username, "test")
            self.assertEqual(user.firstname, "Raymond")
            self.assertEqual(user.lastname, "Tan")
            self.assertEqual(user.address, "10kkj")
            self.assertEqual(user.email, "raymondtan@gmail.com")
            self.assertEqual(user.mobile, "98765433")
            self.assertEqual(user.nric, "S12341235")
            self.assertEqual(user.dob, "11-11-1111")

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
