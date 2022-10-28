from webportal import create_webportal
from webportal.unit_tests.register_test import *
from flask import Flask

app = create_webportal()

if __name__ == "__main__":
    # Run test cases.
    app.run(host="localhost", port="5000")


