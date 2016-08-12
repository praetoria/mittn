# This is a minimal webapp for browsing and editing a database.
# It can be used to look at, verify, and remove findings created
# by the mittn scanner and fuzzer.


import logging

from flask.app import Flask
from flask_admin.base import Admin
from flask_admin.contrib.sqla.view import ModelView
from flask_sqlalchemy import SQLAlchemy

from mittn.fuzzer.fuzzerissue import FuzzerIssue

def build_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    db = SQLAlchemy(app)
    app.secret_key = 'super secret key'
    admin = Admin(app, name='Fuzz', template_mode='bootstrap3')
    admin.add_view(ModelView(FuzzerIssue, db.session))
    logging.basicConfig(level=logging.DEBUG)
    return app

if __name__ == '__main__':
    wsgi_app = build_app()
    wsgi_app.run(host='0.0.0.0', port=8000)
