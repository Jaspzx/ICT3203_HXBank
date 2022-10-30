import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.BankAccountManagementController import *

app = create_test_webportal()


class TopUpAccountBalanceTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    user_id = ""

    def setUp(self):
        """
        Test the setting up of the db with values.
        """
        password1 = flask_bcrypt.generate_password_hash("password1")
        with app.app_context():
            db.create_all()
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S12341235",
                         "11-11-1111", password1, None, None, 0)
            self.user_id = User.query.filter_by(username="test").first().id
            self.bamc.add_bank_account(self.user_id)

    def testTopUpAmountLessThanOne(self):
        """
        Test if user can top up $0 to their account balance.
        """
        with app.app_context():
            amount = float(Decimal(0).quantize(TWO_PLACES))
            description = f"Self-service top up of ${Decimal(amount).quantize(TWO_PLACES)}"
            error_message = "Invalid amount (Minimum $1)"
            user = User.query.filter_by(username="test").first()
            self.assertEqual(self.bamc.topup_balance(self.user_id, user, amount, description), error_message)

    def testTopUpAmount(self):
        """
        Test if user can top up to their account.
        """
        with app.app_context():
            amount = float(Decimal(1000).quantize(TWO_PLACES))
            description = f"Self-service top up of ${Decimal(amount).quantize(TWO_PLACES)}"
            user = User.query.filter_by(username="test").first()
            self.assertEqual(self.bamc.topup_balance(self.user_id, user, amount, description), None)

    def tearDown(self):
        """
        Tear down the unit test.
        """
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
