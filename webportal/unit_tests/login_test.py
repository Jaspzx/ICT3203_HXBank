import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.BankAccountManagementController import *

app = create_test_webportal()

class LoginTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    acc_number1 = ""

    def setUp(self):
        password1 = flask_bcrypt.generate_password_hash("password1")
        with app.app_context():
            db.create_all()
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S12341235",
                         "11-11-1111", password1, None, None, 0)
            self.acc_number1, welcome_amt1 = self.bamc.add_bank_account(User.query.filter_by(username="test").first().id)

    def testInit(self):
        with app.app_context():
            user = User.query.filter_by(username="test").first()
            authenticate = self.amc.authenticate(user, "password1")
            self.assertEqual(authenticate, 1)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
