import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *
from webportal.controllers.MessageManagementController import *
from webportal.controllers.BankAccountManagementController import *
from webportal.models.Account import *
from webportal.models.Transferee import *

app = create_test_webportal()


class AdminApproveTransactionTest(unittest.TestCase):
    amc = AccountManagementController()
    bamc = BankAccountManagementController()
    random_gen = SystemRandom()
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
            self.acc_number1 = "".join([str(self.random_gen.randrange(9) for i in range(10))])
            self.welcome_amt1 = self.random_gen.randrange(1000, 10000)
            self.acc_number2 = "".join([str(self.random_gen.randrange(9) for i in range(10))])
            self.welcome_amt2 = self.random_gen.randrange(1000, 10000)
            self.acc1 = Account(self.acc_number1, User.query.filter_by(username="test").first().id, self.welcome_amt1)
            self.acc2 = Account(self.acc_number2, User.query.filter_by(username="test1").first().id, self.welcome_amt2)

    def testApproveTransaction(self):
        """
        Test if admin can approve user's transaction that is above 10000.
        """
        with app.app_context():
            self.assertEqual(self.bamc.create_transaction(10000, self.acc1, self.acc2, "test"),(True, self.acc_number1, self.acc_number2))





    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == '__main__':
    unittest.main()
