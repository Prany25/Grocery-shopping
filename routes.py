from flask import render_template, request, flash, redirect, url_for, session
from app import app
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Category, Cart, Product, Transaction, Order
from functools import wraps
from datetime import datetime

def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('Please login to continue')
            return redirect(url_for('login'))
    return inner

def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You are not authorized to access this page')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner

@app.route('/')
@auth_required
def index():
    user = User.query.get(session['user_id'])
    if user.is_admin:
        return redirect(url_for('admin'))
    return render_template('index.html')

@app.route('/profile', methods=['GET', 'POST'])
@auth_required
def profile():
    user = User.query.get(session['user_id'])
    if not user:
        flash('Please login to continue')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username')
        cpassword = request.form.get('cpassword')
        password = request.form.get('password')
        name = request.form.get('name')
    
        # Check for missing fields
        if not username or not cpassword or not name:
            flash("Please fill all the required details")
            return redirect(url_for('profile'))

        # Verify current password
        if not check_password_hash(user.passhash, cpassword):
            flash('Incorrect Current Password')
            return redirect(url_for('profile'))

        # Check if the new username already exists (and is not the current one)
        if username != user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists')
                return redirect(url_for('profile'))

        # Update the user details
        user.username = username
        user.name = name

        # Only update the password if a new one is provided
        if password:
            user.passhash = generate_password_hash(password)

        db.session.commit()
        flash('Profile Updated Successfully')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)


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

        session['user_id'] = user.id       
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

@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')
    flash('Succussfully logged out')
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin():
    categories = Category.query.all()
    return render_template('admin.html', categories=categories)

@app.route('/category/add')
@admin_required
def add_category():
    return render_template('category/add.html')

@app.route('/category/add', methods=['POST'])
@admin_required
def add_category_post():
    name= request.form.get('name')

    if not name:
        flash('Please fill out all fields')
        return redirect(url_for('add_category'))

    category =  Category(name=name)
    db.session.add(category)
    db.session.commit()

    flash('category added successfully')
    return redirect(url_for('admin'))

@app.route('/category/<int:id>/edit')
@admin_required
def edit_category(id):
    category=Category.query.get(id)
    if not category:
        flash('category does not exist')
        return redirect(url_for('admin'))
    return render_template('category/edit.html',category=category)

@app.route('/category/<int:id>/edit',methods=['POST'])
@admin_required
def edit_category_post(id):
    category=Category.query.get(id)
    if not category:
        flash('category does not exists')
        return redirect(url_for('admin'))
    name = request.form.get('name')
    if not name:
        flash('Please fill out all value')
        return redirect(url_for('edit_category',id=id))
    category.name = name
    db.session.commit()
    flash('Category updated successfully')
    return redirect(url_for('admin'))

@app.route('/category/<int:id>/Delete')
@admin_required
def delete_category(id):
    category = Category.query.get(id)
    if not category:
        flash('category does not exist')
        return redirect(url_for('admin'))
    return render_template('category/delete.html',category=category)

@app.route('/category/<int:id>/Delete',methods=['POST'])
@admin_required
def delete_category_post(id):
    category = Category.query.get(id)
    if not category:
        flash('category does not exist')
        return redirect(url_for('admin'))
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted Successfully')
    return redirect(url_for('admin'))

@app.route('/category/<int:id>/')
@admin_required
def show_category(id):
    category = Category.query.get(id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin'))
    return render_template('category/show.html',category=category)

@app.route('/product/add/<int:category_id>')
@admin_required
def add_product(category_id):
    categories = Category.query.all()
    category = Category.query.get(category_id)
    if not category:
        flash('Category does not exists')
        return redirect(url_for('admin'))
    now = datetime.now().strftime('%Y-%m-%d')
    return render_template('product/add.html',category=category,categories=categories,now=now)

@app.route('/product/add>', methods=['POST'])
@admin_required
def add_product_post():
    name = request.form.get('name')
    price = request.form.get('price')
    category_id = request.form.get('category_id')
    quantity = request.form.get('quantity')
    man_date = request.form.get('man_date')
    
    category = Category.query.get(category_id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin'))
    
    if  not name or not price or not quantity or not man_date:
        flash('Please fill out all detail')
        return redirect(url_for('add_product',category_id=category_id))
    try:
        quantity = int(quantity)
        price= float(price)
        man_date = datetime.strptime(man_date, '%Y-%m-%d')
    except ValueError:
        flash('Invalid quantity or price')
        return redirect(url_for('add_product',category_id=category_id))
    if price <= 0 or quantity<=0:
        flash('Invalid Quantity or Price')
        return redirect(url_for('add_product',category_id=category_id))
    
    if man_date > datetime.now():
        flash('Invalid manufacturing date')
        return redirect(url_for('add_product',category_id=category_id))

    product = Product(name=name, price=price, category=category, quantity=quantity, man_date=man_date)
    db.session.add(product)
    db.session.commit()
    flash('Product added successfully')
    return redirect(url_for('show_category',id=category_id))

@app.route('/product/<int:id>/edit')
@admin_required
def edit_product(id):
    
    categories = Category.query.all()
    product = Product.query.get(id)
    return render_template('product/edit.html',categories=categories,product=product)

@app.route('/product/<int:id>/edit',methods=['POST'])
@admin_required
def edit_product_post(id):
    name = request.form.get('name')
    price = request.form.get('price')
    category_id = request.form.get('category_id')
    quantity = request.form.get('quantity')
    man_date = request.form.get('man_date')
    
    category = Category.query.get(category_id)
    if not category:
        flash('Category does not exist')
        return redirect(url_for('admin'))
    
    if  not name or not price or not quantity or not man_date:
        flash('Please fill out all detail')
        return redirect(url_for('add_product',category_id=category_id))
    try:
        quantity = int(quantity)
        price= float(price)
        man_date = datetime.strptime(man_date, '%Y-%m-%d')
    except ValueError:
        flash('Invalid quantity or price')
        return redirect(url_for('add_product',category_id=category_id))
    if price <= 0 or quantity<=0:
        flash('Invalid Quantity or Price')
        return redirect(url_for('add_product',category_id=category_id))
    
    if man_date > datetime.now():
        flash('Invalid manufacturing date')
        return redirect(url_for('add_product',category_id=category_id))

    product = Product.query.get(id)
    product.name = name
    product.price = price
    product.category = category
    product.quantity = quantity
    product.man_date = man_date

    db.session.commit()
    flash('Product edited successfully')
    return redirect(url_for('show_category',id=category_id))

@app.route('/product/<int:id>/Delete')
@admin_required
def delete_product(id):
    product = Product.query.get(id)
    if not product:
        flash('Product does not exist')
        return redirect(url_for('admin'))
    return render_template('product/delete.html',product=product)

@app.route('/product/<int:id>/Delete',methods=['POST'])
@admin_required
def delete_product_post(id):
    product = Product.query.get(id)
    if not product:
        flash('product does not exist')
        return redirect(url_for('admin'))
    db.session.delete(product)
    db.session.commit()
    flash('Product was deleted Successfully')
    return redirect(url_for('show_category',id=product.category_id)) 