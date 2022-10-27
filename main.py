from webportal import create_webportal
from webportal.unit_tests import test
from flask import Flask

app = create_webportal()

if __name__ == "__main__":
    app.run(host="localhost", port="5000")


