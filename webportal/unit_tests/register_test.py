from flask_bcrypt import Bcrypt
from webportal.models.Transferee import User


class RegisterTest:

    def register(self):
        password1 = "password1"
        password2 = "password2"
        user1 = User("test", "Bernard", "Tan", "10kkj", "bernardtan@gmail.com", "98765432", "S12341234", "11-11-1111",
                     password1, None, None, 0)
        user2 = User("test2", "Junjie", "Koh", "10kkj", "jjk@gmail.com", "98765433", "S12341235", "11-11-1111",
                     password2, None, None, 0)
        
        assert(user1) != None, "Test Success"


    def run(self):
        self.register()
