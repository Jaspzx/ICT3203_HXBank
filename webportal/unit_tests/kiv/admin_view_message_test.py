import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.MessageManagementController import *
from webportal.controllers.BankAccountManagementController import *

app = create_test_webportal()


class AdminViewMessageTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    mmc = MessageManagementController()
    acc_number1 = ""
    acc_number2 = ""

    def setUp(self):
        """
        Test the setting up of the db with values.
        """
        password1 = flask_bcrypt.generate_password_hash("password1")
        password2 = flask_bcrypt.generate_password_hash("password2")
        password3 = flask_bcrypt.generate_password_hash("password3")
        with app.app_context():
            db.create_all()
            self.amc.add_user("admintest", "Marcus", "Tan", "10kkj", "marcustan@gmail.com", "98765123", "S12341236",
                              "11-11-1111", password2, None, None, 1)
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S12341235",
                         "11-11-1111", password1, None, None, 0)
            self.amc.add_user("test1", "Bernard", "Tan", "10kkj", "bernardtan@gmail.com", "98765432", "S12341234",
                         "11-11-1111", password2, None, None, 0)
            self.acc_number1, welcome_amt1 = self.bamc.add_bank_account(User.query.filter_by(username="test").first().id)
            self.acc_number2, welcome_amt2 = self.bamc.add_bank_account(User.query.filter_by(username="test1").first().id)

    def testViewLoginMessage(self):
        """
        Test if admin can view last login message.
        """
        with app.app_context():
            admin = self.amc.decrypt_by_username(username="admintest")
            self.assertEqual(self.mmc.send_last_login(admin), None)

    def testWelcomeMessage(self):
        """
        Test if admin can view welcome message.
        """
        with app.app_context():
            admin = self.amc.decrypt_by_username(username="admintest")
            self.assertEqual(self.mmc.send_welcome_msg(100, admin), None)



    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
