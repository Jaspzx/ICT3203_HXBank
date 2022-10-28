import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.BankAccountManagementController import *

app = create_test_webportal()


class TopUpAccountBalanceTest(unittest.TestCase):
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

    def testTopUpAmountLessThanOne(self):
        """
        Test if user can top up $0 to their account balance.
        """
        with app.app_context():
            user_id = User.query.filter_by(username="test").first().id
            amount = 0
            error_message = "Invalid amount (Minimum $1)"
            self.assertEqual(self.bamc.topup_balance(user_id, self.acc_number1, amount, "Top up $0"), error_message)

    def testTopUpAmount(self):
        """
        Test if user can top up to their account.
        """
        with app.app_context():
            user_id = User.query.filter_by(username="test").first().id
            amount = 10
            self.assertEqual(self.bamc.topup_balance(user_id, self.acc_number1, amount, "Top up "), None)



    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
