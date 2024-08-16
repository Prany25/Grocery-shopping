from flask import render_template, request, flash, redirect, url_for
from app import app
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Category, Cart, Product, Transaction, Order

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill all the fields')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()

        if not user:
            flash('User does not exist')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.passhash, password):
            flash("Incorrect password")
            return redirect(url_for('login'))
        
        flash('User Successfully logged in')
        return redirect(url_for('index'))
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name')

        if not username or not password or not confirm_password or not name:
            flash('Please fill all the fields')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already taken')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)

        new_user = User(username=username, passhash=password_hash, name=name)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

