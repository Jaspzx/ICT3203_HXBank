import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.MessageManagementController import *
from webportal.controllers.BankAccountManagementController import *

app = create_test_webportal()


class AdminDeleteMessageTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    mmc = MessageManagementController()
    acc_number1 = ""
    acc_number2 = ""

    def setUp(self):
        """
        Test the setting up of the db with values.
        """
        password = flask_bcrypt.generate_password_hash("password1")
        with app.app_context():
            db.create_all()
            self.amc.add_user("admintest", "Marcus", "Tan", "10kkj", "marcustan@gmail.com", "98765123", "S12341236",
                              "11-11-1111", password, None, None, 1)

    def testDeleteLoginMessage(self):
        """
        Test if admin can delete last login message.
        """
        with app.app_context():
            admin = self.amc.decrypt_by_username(username="admintest")
            self.assertEqual(self.mmc.del_messasge(self.mmc.send_last_login(admin)), None)

    def testDeleteWelcomeMessage(self):
        """
        Test if admin can delete welcome message.
        """
        with app.app_context():
            admin = self.amc.decrypt_by_username(username="admintest")
            self.assertEqual(self.mmc.del_messasge(self.mmc.send_welcome_msg(100, admin)), None)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
