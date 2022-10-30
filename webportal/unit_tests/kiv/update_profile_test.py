import unittest
from flask_bcrypt import Bcrypt
from webportal import db, create_webportal, create_test_webportal
from webportal.controllers.AccountManagementController import *

app = create_test_webportal()


class UpdateprofileTest(unittest.TestCase):
    amc = AccountManagementController()

    def setUp(self):
        """
        Test the setting up of the db with values.
        """
        password1 = flask_bcrypt.generate_password_hash("password1")
        with app.app_context():
            db.create_all()
            self.amc.add_user("test", "Raymond", "Tan", "10kkj", "raymondtan@gmail.com", "98765433", "S12341235",
                         "11-11-1111", password1, None, None, 0)
            self.user1_id = User.query.filter_by(username="test").first().id
            self.bamc.add_bank_account(self.user1_id)



        # password = flask_bcrypt.generate_password_hash("password")
        # with app.app_context():
        #     db.create_all()
        #     self.amc.add_user("test2", "Benedict", "Tan", "10kkj", "benedicttan@gmail.com", "98765431", "S12341233",
        #                       "11-11-1111", password, None, None, 0)
        #     user = User.query.filter_by(username="test2").first()
        #     newpass = flask_bcrypt.generate_password_hash("password11")
        #     self.amc.change_pw(user, newpass)

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
