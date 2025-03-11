from database import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from models import db
from flask_login import UserMixin


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    student_id = db.Column(db.String, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(10), nullable=False)  # "Present" or "Absent"

    student = db.relationship('User', backref='attendances')

class User(db.Model, UserMixin):
    id = db.Column(db.String(100), primary_key=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)  
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def __repr__(self):
        return f"User('{self.name}', '{self.email}', '{self.role}')"