import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.BankAccountManagementController import *

app = create_test_webportal()


class ViewtransactionsTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    user1_id = ""
    user2_id = ""

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
            self.user1_id = User.query.filter_by(username="test").first().id
            self.user2_id = User.query.filter_by(username="test1").first().id
            self.bamc.add_bank_account(self.user1_id)
            self.bamc.add_bank_account(self.user2_id)
            self.bamc.add_bank_account(self.user1_id)
            self.bamc.add_bank_account(self.user2_id)

    def testViewTransactionHistory(self):
        """
        Test that the transaction history is not empty.
        """
        with app.app_context():
            transferer_acc = Account.query.filter_by(userid=self.user1_id).first()
            transferee_acc = Account.query.filter_by(userid=self.user2_id).first()
            self.bamc.create_transaction(10, transferer_acc, transferee_acc, "test transaction")
            data = self.bamc.transaction_history(self.user1_id)
            self.assertIsNotNone(data, len(data) != 0)

    def tearDown(self):
        """
        Tear down the unit test.
        """
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
