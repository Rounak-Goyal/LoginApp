
from flask import Blueprint, render_template, redirect, url_for, request, session, flash
from models.user_model import db, User, bcrypt

auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/')
def index():
    return render_template('index.html')

@auth_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        if password != confirmpassword:
            render_template('register.html')
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('auth.index'))
    
    return render_template('register.html')

@auth_blueprint.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    loginfail = False

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Password is correct, log in the user
        session['user'] = username
        loginfail = False
        flash('Login successful!', 'success')
        return redirect(url_for('auth.dashboard'))
    
    flash('Login failed. Check your username and password.')
    error_message = "Incorrect username or password. Please try again."
    return render_template('index.html',error_message=error_message, loginfail=True)

@auth_blueprint.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html')
    return redirect(url_for('auth.index'))

@auth_blueprint.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('auth.index'))

@auth_blueprint.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            render_template('password_reset.html')

        user = User.query.filter_by(username=username).first()

        if user:
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            return redirect(url_for('auth.index'))

    return render_template('password_reset.html')
