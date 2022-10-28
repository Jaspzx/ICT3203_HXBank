import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.BankAccountManagementController import *

app = create_test_webportal()

class ResetpwdTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    acc_number1 = ""

    def setUp(self):
        password = flask_bcrypt.generate_password_hash("password")
        with app.app_context():
            db.create_all()
            self.amc.add_user("test2", "Benedict", "Tan", "10kkj", "benedicttan@gmail.com", "98765431", "S12341233",
                              "11-11-1111", password, None, None, 0)
            self.acc_number1, welcome_amt1 = self.bamc.add_bank_account(User.query.filter_by(username="test2").first().id)
            user = User.query.filter_by(username="test2").first()
            newpass = flask_bcrypt.generate_password_hash("password11")
            self.amc.reset_pwd(user, newpass)

    def testInit(self):
        with app.app_context():
            user = User.query.filter_by(username="test2").first()
            authenticate = self.amc.authenticate(user, "password11")
            self.assertEqual(authenticate, 1)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
