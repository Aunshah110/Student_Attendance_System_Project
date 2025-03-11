from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_bcrypt import Bcrypt
from werkzeug.security import check_password_hash
from flask_login import login_user, logout_user, login_required, current_user, login_manager, LoginManager
from flask_migrate import Migrate
from database import db
import io
import re
import csv



app = Flask(__name__)
app.secret_key = 'Syed@un'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_PERMANENT'] = False  # Ensure session remains active
app.config['SESSION_TYPE'] = "filesystem"

migrate = Migrate(app, db)

db.init_app(app)  

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['GOOGLE_CLIENT_ID'] = 'your_google_client_id'
app.config['GOOGLE_CLIENT_SECRET'] = 'your_google_client_secret'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from models import User, Attendance

@login_manager.user_loader 
def load_User(id):
    return User.query.get(id)

with app.app_context():
    db.create_all()

bcrypt = Bcrypt(app)

# Create database tables before the first request
@app.before_request
def create_tables():
    db.create_all()
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'Admin':
        flash("Access Denied! Admins only.", "danger")
        return redirect(url_for('login'))
    users = User.query.all()
    return render_template('admin.html')

@app.route('/teacher')
def teacher():
    if 'user_id' not in session or session.get('role') != 'Teacher':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    return render_template('teacher.html')

@app.route('/student')
def student():
    if 'user_id' not in session or session.get('role') != 'Student':
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    return render_template('student.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    session.clear()
    if request.method == 'POST':
        user_id = request.form.get('id') 
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        hashed_password = bcrypt.generate_password_hash(password)
        try:
            new_user = User(id=user_id, name=name, email=email, role=role)
            new_user.set_password(password)  # Hash the password
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))  
        except Exception as e:
            db.session.rollback()  # Rollback if any error occurs
            flash('Error: ' + str(e), 'danger')
        finally:
            db.session.close() 

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True) 
            session['user_id'] = user.id
            session['role'] = user.role  # Store user role in session
            
            flash('Login successful!', 'success')

            # Redirect based on role
            if user.role == 'Admin':
                return redirect(url_for('admin'))
            elif user.role == 'Teacher':
                return redirect(url_for('teacher'))
            elif user.role == 'Student':
                return redirect(url_for('student'))
            else:
                flash('Invalid role!', 'danger')
                return redirect(url_for('login'))
        
        else:
            flash('Invalid email or password!', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
        if 'user_id' in session:  # Check if user is logged in
            session.clear()
            flash('You have been logged out successfully.', 'success')
        else:
            flash('You are not logged in.', 'warning')
        return redirect(url_for('login'))

@app.route('/mark_attendance', methods=['GET', 'POST'])
def mark_attendance():
    if current_user.role != "Teacher":
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    # Fetch students and sort by the numeric part of their ID
    students = User.query.filter_by(role="Student").all()

    def extract_numeric_id(student):
        match = re.search(r'(\d+)$', student.id)  # Extract numeric part from ID
        return int(match.group(1)) if match else float('inf')  # Convert to integer for sorting

    students.sort(key=extract_numeric_id)  # Sort based on extracted numeric part

    if request.method == 'POST':
        missing_status = False  

        for student in students:
            attendance_status = request.form.get(f"attendance_{student.id}")

            if attendance_status is None:
                missing_status = True  
            else:
                new_attendance = Attendance(
                    student_id=student.id,
                    status=attendance_status, 
                )
                db.session.add(new_attendance)

        if missing_status:  
            flash("Please mark attendance for all students before submitting.", "warning")
            return render_template('mark_attendance.html', students=students)

        db.session.commit()
        flash("Attendance marked successfully!", "success")
        return redirect(url_for('teacher'))

    return render_template('mark_attendance.html', students=students)

@app.route('/view_attendance')
@login_required
def view_attendance():
    if current_user.role != "Student":
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    attendance_records = Attendance.query.filter_by(student_id=current_user.id).all()
    student_name = current_user.name
    student_id = current_user.id  # User-entered ID

    return render_template('view_attendance.html', records=attendance_records, student_name=student_name, student_id=student_id)

@app.route('/student_records')
@login_required
def student_records():
    if current_user.role != "Teacher" and current_user.role != "Admin":
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    students = User.query.filter_by(role="Student").order_by(User.id).all()  
    return render_template('student_records.html', students=students)

@app.route('/view_students', methods=['GET'])
@login_required
def view_students():
    if current_user.role != "Teacher":
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    students = User.query.filter_by(role="Student").all()
    return render_template('view_students.html', students=students)

@app.route('/view_attendance/<student_id>', methods=['GET'])
@login_required
def view_student_attendance(student_id):
    if current_user.role != "Teacher" and current_user.role != "Admin":
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    student = User.query.filter_by(id=student_id, role="Student").first()
    if not student:
        flash("Student not found!", "danger")
        return redirect(url_for('view_students'))

    attendance_records = Attendance.query.filter_by(student_id=student_id).order_by(Attendance.date.desc()).all()

    return render_template('view_student_attendance.html', student=student, attendance_records=attendance_records)


@app.route('/generate_reports')
def generate_reports():
    if current_user.role != "Teacher" and current_user.role != "Admin":
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    students = User.query.filter_by(role="Student").all()
    student_attendance_data = []

    for student in students:
        total_days = Attendance.query.filter_by(student_id=student.id).count()
        attended_days = Attendance.query.filter_by(student_id=student.id, status="Present").count()

        # Calculate percentage
        percentage = (attended_days / total_days * 100) if total_days > 0 else 0  

        student_attendance_data.append({
            'id': student.id,
            'name': student.name,
            'total_days': total_days,
            'attended_days': attended_days,
            'percentage': round(percentage, 2)
        })

    return render_template('generate_report.html', student_attendance_data=student_attendance_data)



@app.route('/export_csv')
def export_csv():
    if current_user.role != "Teacher":
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    students = User.query.filter_by(role="Student").all()
    attendance_data = []

    for student in students:
        total_days = Attendance.query.filter_by(student_id=student.id).count()
        attended_days = Attendance.query.filter_by(student_id=student.id, status="Present").count()
        percentage = (attended_days / total_days * 100) if total_days > 0 else 0

        attendance_data.append([student.id, student.name, total_days, attended_days, f"{percentage:.2f}%"])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Student ID", "Name", "Total Days", "Attended Days", "Percentage"])
    writer.writerows(attendance_data)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=attendance_report.csv"
    response.headers["Content-type"] = "text/csv"
    return response

from fpdf import FPDF
@app.route('/export_pdf')
def export_pdf():
    if current_user.role != "Teacher":
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    students = User.query.filter_by(role="Student").all()
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", style="B", size=14)
    pdf.cell(200, 10, txt="Attendance Report", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", size=10)
    pdf.cell(30, 10, "Student ID", 1)
    pdf.cell(40, 10, "Name", 1)
    pdf.cell(30, 10, "Total Days", 1)
    pdf.cell(30, 10, "Attended Days", 1)
    pdf.cell(30, 10, "Percentage", 1)
    pdf.ln()

    for student in students:
        total_days = Attendance.query.filter_by(student_id=student.id).count()
        attended_days = Attendance.query.filter_by(student_id=student.id, status="Present").count()
        percentage = (attended_days / total_days * 100) if total_days > 0 else 0

        pdf.cell(30, 10, str(student.id), 1)
        pdf.cell(40, 10, student.name, 1)
        pdf.cell(30, 10, str(total_days), 1)
        pdf.cell(30, 10, str(attended_days), 1)
        pdf.cell(30, 10, f"{percentage:.2f}%", 1)
        pdf.ln()

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers["Content-Disposition"] = "attachment; filename=attendance_report.pdf"
    response.headers["Content-type"] = "application/pdf"
    return response


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        new_name = request.form.get('name')
        new_email = request.form.get('email')
        
        # Update the user record in the database
        current_user.name = new_name
        current_user.email = new_email
        db.session.commit()
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=current_user)




if __name__ == '__main__':
    app.run(debug=True)
