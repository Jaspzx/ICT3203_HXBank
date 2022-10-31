import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.MessageManagementController import *
from webportal.controllers.BankAccountManagementController import *
from webportal.models.Account import *
from webportal.models.Transferee import *
from flask_login import login_user


app = create_test_webportal()


class AdminApproveTransactionTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    random_gen = SystemRandom()
    user1_id = ""
    user2_id = ""

    def setUp(self):
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

    def testInit(self):
        with app.app_context():
            user = self.amc.decrypt_by_username(username="test")
            self.assertEqual(user.username, "test")
            self.assertEqual(user.firstname, "Raymond")
            self.assertEqual(user.lastname, "Tan")
            self.assertEqual(user.address, "10kkj")
            self.assertEqual(user.email, "raymondtan@gmail.com")
            self.assertEqual(user.mobile, "98765433")
            self.assertEqual(user.nric, "S1234123Q")
            self.assertEqual(user.dob, "1111-11-11")

    def testApproveTransaction(self):
        with app.app_context():
            transferer_acc = Account.query.filter_by(userid=self.user1_id).first()
            transferee_acc = Account.query.filter_by(userid=self.user2_id).first()
            require_approval, transferer_acc_number, transferee_acc_number = self.bamc.create_transaction(10000, transferer_acc, transferee_acc, "test transaction")
            self.assertEqual(require_approval, True)

    def testCreateTransaction(self):
        with app.app_context():
            transferer_acc = Account.query.filter_by(userid=self.user1_id).first()
            transferee_acc = Account.query.filter_by(userid=self.user2_id).first()
            require_approval, transferer_acc_number, transferee_acc_number = self.bamc.create_transaction(10000, transferer_acc, transferee_acc, "test transaction")
            transaction = Transaction.query.filter_by(transferrer_acc_number=transferer_acc_number, transferee_acc_number=transferee_acc_number).first()
            if transaction:
                created = True
            self.assertEqual(True, created)

    def testTransactionAccI(self):
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

    def testLogin(self):
        with app.app_context():
            response = app.test_client().post('/login', data={"username": "test", "password": "Password1_"},
                                              follow_redirects=True)
            self.assertIn(b'Enter OTP Code', response.data)

    def testPassword(self):
        with app.app_context():
            response = app.test_client().post('/login', data={"username": "test", "password": "password123"},
                                              follow_redirects=True)
            self.assertIn(b'Login Failed', response.data)

    def testUsername(self):
        with app.app_context():
            response = app.test_client().post('/login', data={"username": "te5t@", "password": "p@ssword123_"},
                                              follow_redirects=True)
            self.assertIn(b'Invalid username', response.data)

    def testOtpX(self):
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"},
                                 follow_redirects=True)
                response = self.client.post('/otp-input', data={"token": "355467777"},
                                            follow_redirects=True)
                self.assertIn(b'Field must be exactly 6 characters long', response.data)

    def testOtpA(self):
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"},
                                 follow_redirects=True)
                response = self.client.post('/otp-input', data={"token": "a35546"},
                                            follow_redirects=True)
                self.assertIn(b'Invalid input', response.data)

    def testOtpC(self):
        with app.app_context():
            with self.client:
                user = User.query.filter_by(username="test").first()
                user.prev_token = "135546"
                update_db_no_close()
                self.client.post('/login', data={"username": "test", "password": "Password1_"},
                                 follow_redirects=True)
                response = self.client.post('/otp-input', data={"token": "135546"},
                                            follow_redirects=True)
                self.assertIn(b'Something went wrong', response.data)

    def testRegister(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S9584634E", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'I am done. Take me to Login.', response.data)

    def testRegisterIP(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "password1", "confirm_password": "password1",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S9584634E", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Password complexity not met', response.data)

    def testRegisterPNM(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ13",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S9584634E", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Passwords must match', response.data)

    def testRegisterIE(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test", "mobile": "123123123",
                                                               "nric": "S9584634E", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Invalid email address.', response.data)

    def testRegisterIID(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S95846343", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Invalid Identification no.', response.data)

    def testRegisterID(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test@gmail.com", "mobile": "123123123",
                                                               "nric": "S9584634Q", "dob": "test",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Not a valid date value.', response.data)

    def testRegisterIM(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/register', data={"username": "test2", "firstname": "Brian",
                                                               "lastname": "O'neal", "address": "10kkj",
                                                               "password": "123!@qQ12", "confirm_password": "123!@qQ12",
                                                               "email": "test@gmail.com", "mobile": "123123aaa",
                                                               "nric": "S9584634Q", "dob": "1111-11-11",
                                                               "accept_tos": True}, follow_redirects=True)
                self.assertIn(b'Invalid mobile', response.data)

    def testDuplicateUser(self):
        password1 = flask_bcrypt.generate_password_hash("password1")
        with app.app_context():
            self.assertEqual(self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433",
                                               "S12341235", "11-11-1111", password1, None, None, 0), None)

    def testDuplicateAccount(self):
        with app.app_context():
            self.assertEqual(self.bamc.add_bank_account(User.query.filter_by(username="test").first().id), (None, None))

    def testLogin(self):
        with app.app_context():
            user = User.query.filter_by(username="test").first()
            authenticate = self.amc.authenticate(user, "Password11_")
            self.assertEqual(authenticate, 3)

    def testIdentify(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/reset-identify?type=pwd', data={"username": "test", "nric": "S1234123Q",
                                                                              "dob": "1111-11-11"},
                                            follow_redirects=True)
                self.assertIn(b'Authenticate Yourself', response.data)

    def testUsernameI(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/reset-identify?type=pwd', data={"username": "test1", "nric": "S1234123Q",
                                                                              "dob": "1111-11-11"},
                                            follow_redirects=True)
                self.assertIn(b'Identification Failed', response.data)

    def testIDI(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/reset-identify?type=pwd', data={"username": "test", "nric": "S1234123R",
                                                                              "dob": "1111-11-11"},
                                            follow_redirects=True)
                self.assertIn(b'Identification Failed', response.data)

    def testDOBI(self):
        with app.app_context():
            with self.client:
                response = self.client.post('/reset-identify?type=pwd', data={"username": "test", "nric": "S1234123Q",
                                                                              "dob": "1111-11-12"},
                                            follow_redirects=True)
                self.assertIn(b'Identification Failed', response.data)

    def testTopUpAmountLessThanOne(self):
        with app.app_context():
            amount = float(Decimal(0).quantize(TWO_PLACES))
            description = f"Self-service top up of ${Decimal(amount).quantize(TWO_PLACES)}"
            error_message = "Invalid amount (Minimum $1)"
            user = User.query.filter_by(username="test").first()
            self.assertEqual(self.bamc.topup_balance(self.user1_id, user, amount, description), error_message)

    def testTopUpAmount(self):
        with app.app_context():
            amount = float(Decimal(1000).quantize(TWO_PLACES))
            description = f"Self-service top up of ${Decimal(amount).quantize(TWO_PLACES)}"
            user = User.query.filter_by(username="test").first()
            self.assertEqual(self.bamc.topup_balance(self.user1_id, user, amount, description), None)

    def testTopUpAmountI(self):
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"}, follow_redirects=True)
                user = User.query.filter_by(id=self.user1_id).first()
                user.email_verified = True
                update_db_no_close()
                login_user(user)
                response = self.client.post('/personal-banking/topup-balance', data={"amount": "aaa"},
                                            follow_redirects=True)
                self.assertIn(b'Not a valid float value', response.data)

    def testViewTransactionHistory(self):
        with app.app_context():
            transferer_acc = Account.query.filter_by(userid=self.user1_id).first()
            transferee_acc = Account.query.filter_by(userid=self.user2_id).first()
            self.bamc.create_transaction(10, transferer_acc, transferee_acc, "test transaction")
            data = self.bamc.transaction_history(self.user1_id)
            self.assertIsNotNone(data, len(data) != 0)

    def testViewTransferee(self):
        with app.app_context():
            transferee_acc = Account.query.filter_by(userid=self.user2_id).first()
            self.bamc.add_transferee(self.user1_id, transferee_acc.acc_number)
            data = self.bamc.view_transferee(self.user1_id)
            self.assertIsNotNone(data, len(data) != 0)

    def testAddTransfereeI(self):
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"}, follow_redirects=True)
                user = User.query.filter_by(id=self.user1_id).first()
                user.email_verified = True
                update_db_no_close()
                login_user(user)
                response = self.client.post('/personal-banking/add-transferee', data={"transferee_acc": "010102097e"},
                                            follow_redirects=True)
                self.assertIn(b'Invalid account number', response.data)

    def testDeleteTransfereeI(self):
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"}, follow_redirects=True)
                user = User.query.filter_by(id=self.user1_id).first()
                user.email_verified = True
                update_db_no_close()
                login_user(user)
                response = self.client.post('/personal-banking/view-transferee', data={"transferee_acc": "010102097e"},
                                            follow_redirects=True)
                self.assertIn(b'Invalid account number', response.data)

    def testAddTransferee(self):
        with app.app_context():
            with self.client:
                self.client.post('/login', data={"username": "test", "password": "Password1_"}, follow_redirects=True)
                user = User.query.filter_by(id=self.user1_id).first()
                user.email_verified = True
                update_db_no_close()
                login_user(user)
                transferee_acc_no = Account.query.filter_by(userid=self.user2_id).first().acc_number
                response = self.client.post('/personal-banking/add-transferee',
                                            data={"transferee_acc": transferee_acc_no},
                                            follow_redirects=True)
                self.assertIn(b'You have added account number:', response.data)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()