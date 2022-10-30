import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.BankAccountManagementController import *
from flask_login import login_user

app = create_test_webportal()


class TopUpAccountBalanceTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    user_id = ""

    def setUp(self):
        """
        Test the setting up of the db with values.
        """
        password1 = flask_bcrypt.generate_password_hash("Password1_")
        self.client = app.test_client()
        with app.app_context():
            db.create_all()
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S1234123Q",
                              "1111-11-11", password1, None, None, 0)
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

    def testTopUpAmountI(self):
        """
        Test if user can top up to their account with invalid values
        """
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"}, follow_redirects=True)
                user = User.query.filter_by(id=self.user_id).first()
                user.email_verified = True
                update_db_no_close()
                login_user(user)
                response = self.client.post('/personal-banking/topup-balance', data={"amount": "aaa"},
                                            follow_redirects=True)
                self.assertIn(b'Not a valid float value', response.data)

    def tearDown(self):
        """
        Tear down the unit test.
        """
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
