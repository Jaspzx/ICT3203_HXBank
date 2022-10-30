import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.BankAccountManagementController import *
from webportal.models.Account import *
from webportal.models.Transaction import *
from flask_login import login_user

app = create_test_webportal()


class CreateTransactionsTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    random_gen = SystemRandom()
    user1_id = ""
    user2_id = ""

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
            self.user1_id = User.query.filter_by(username="test").first().id
            self.user2_id = User.query.filter_by(username="test1").first().id
            self.bamc.add_bank_account(self.user1_id)
            self.bamc.add_bank_account(self.user2_id)

    def testCreateTransaction(self):
        """
        Test the initialization of values.
        """
        with app.app_context():
            transferer_acc = Account.query.filter_by(userid=self.user1_id).first()
            transferee_acc = Account.query.filter_by(userid=self.user2_id).first()
            require_approval, transferer_acc_number, transferee_acc_number = self.bamc.create_transaction(10000, transferer_acc, transferee_acc, "test transaction")
            transaction = Transaction.query.filter_by(transferrer_acc_number=transferer_acc_number, transferee_acc_number=transferee_acc_number).first()
            if transaction:
                created = True
            self.assertEqual(True, created)

    def testTransactionAccI(self):
        """
        Test transfer using invalid account number
        """
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"}, follow_redirects=True)
                user = User.query.filter_by(id=self.user1_id).first()
                user.email_verified = True
                update_db_no_close()
                login_user(user)
                response = self.client.post('/personal-banking/transfer-onetime', data={"transferee_acc": "010102097e",
                                                                                        "amount": "100",
                                                                                        "description": "Test"},
                                            follow_redirects=True)
                self.assertIn(b'Invalid account number', response.data)

    def testTransactionAmountI(self):
        """
        Test transfer using invalid amount
        """
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"}, follow_redirects=True)
                user = User.query.filter_by(id=self.user1_id).first()
                user.email_verified = True
                update_db_no_close()
                login_user(user)
                transferee_acc_no = Account.query.filter_by(userid=self.user2_id).first().acc_number
                response = self.client.post('/personal-banking/transfer-onetime', data={"transferee_acc": transferee_acc_no,
                                                                                        "amount": "aaa",
                                                                                        "description": "Test"},
                                            follow_redirects=True)
                self.assertIn(b'Not a valid float value', response.data)

    def testTransactionDescI(self):
        """
        Test transfer using invalid description
        """
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"}, follow_redirects=True)
                user = User.query.filter_by(id=self.user1_id).first()
                user.email_verified = True
                update_db_no_close()
                login_user(user)
                transferee_acc_no = Account.query.filter_by(userid=self.user2_id).first().acc_number
                response = self.client.post('/personal-banking/transfer-onetime', data={"transferee_acc": transferee_acc_no,
                                                                                        "amount": "100",
                                                                                        "description": "<script onafterscriptexecute=alert(1)><script>1</script>"},
                                            follow_redirects=True)
                self.assertIn(b'Invalid Characters', response.data)

    def tearDown(self):
        """
        Tear down the unit test.
        """
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
