from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

db = SQLAlchemy()
app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Syed@un110'  # Needed for Flask-Login
bcrypt = Bcrypt(app)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database Updated Successfully!")
