import os
import bcrypt
from flask_seeder import Seeder, Faker, generator
from webportal.models.User import User


class Seed(Seeder):
    def run(self):
        faker = Faker(
          cls=User,
          init={
              "username": generator.Name(),
              "firstname": generator.Name(),
              "lastname": generator.Name(),
              "address": "HX Bank",
              "email": None,
              "mobile": "98761234",
              "nric": None,
              "dob": "11-11-1111",
              "password_hash": bcrypt.hashpw(os.getenv('SUPER_USER_PASSWORD').encode('utf-8'), bcrypt.gensalt()),
              "otp_secret": None,
              "token": None
          }
        )

        # Create 5 users
        for user in faker.create(1):
            print("Adding user: %s" % user)
            user.is_admin = 1
            self.db.session.add(user)
