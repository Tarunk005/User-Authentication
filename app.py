from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = '9f2a5d7c0b418d6cbf2be7cd92ac3ff1' # for session management

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT config
app.config['JWT_SECRET_KEY'] = '9f2a5d7c0b418d6cbf2be7cd92ac3ff1'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email}>"

# Create tables
with app.app_context():
    db.create_all()

# Home redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Login template
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            
            session['user_id'] = user.id  # store token in session
            print("login successfull")
            return render_template('dashboard.html')
        else:
            print("not redirected")
            return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

# Register template
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error="Email already registered")
        
        hashed_pw = generate_password_hash(password)
        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Dashboard template
@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    try:
        decoded = decode_token(user_id)
        user_id = decoded['sub']
        user = User.query.get(user_id)
        if not user:
            return redirect(url_for('login'))
        return render_template('dashboard.html')
    except Exception as e:
        return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
