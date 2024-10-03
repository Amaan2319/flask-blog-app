from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import UserMixin, login_user, login_required, logout_user, current_user, LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///blogs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
UPLOAD_FOLDER = 'static/uploads' 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Models
class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    author = db.Column(db.String(20))
    post_date = db.Column(db.DateTime)
    image_filename = db.Column(db.String(200), nullable=True)  # Add this line
    content = db.Column(db.Text)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# Routes
@app.route("/")
def home():
    articles = Article.query.order_by(Article.post_date.desc()).all()
    if current_user.is_anonymous:
        name = 'guest'
    else:
        name = current_user.username
    return render_template("home.html", articles=articles, name=name)

@app.route('/about')
def about():
    return render_template('about.html')

from flask import request, redirect, url_for
import os

@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        content = request.form['content']

        # Handle file upload
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        image_filename = None  # Initialize the variable to store the filename

        if file and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            # Check for empty fields
        if not title or not author or not content or not file:
            flash('All fields are required!', 'danger')  # Flash message for empty fields
            return redirect(url_for('add_post'))  # Redirect back to the form

        # Create a new Article object
        new_article = Article(
            title=title,
            author=author,
            content=content,
            image_filename=image_filename,  # Save the filename to the database
            post_date=datetime.now()  # Assuming you want to save the current date
        )

        # Add the new article to the database
        db.session.add(new_article)
        db.session.commit()

        return redirect(url_for('home'))  # Redirect to home after successful upload

    return render_template('add_post.html')
    # if request.method == 'POST':
    #     title = request.form['title']
    #     author = request.form['author']
    #     content = request.form['content']
        
    #     # Handle file upload
    #     image = request.files['file']
    #     if image:
    #         image_filename = image.filename
    #         image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    #     else:
    #         image_filename = None
        
    #     # Create a new article instance
    #     new_article = Article(title=title, author=author, content=content, image_filename=image_filename)
    #     db.session.add(new_article)
    #     db.session.commit()
    #     return redirect(url_for('home'))
    # return render_template('add_post.html')


@app.route('/update/<int:id>', methods=['POST', 'GET'])
@login_required
def update(id):
    post = Article.query.get_or_404(id)
    if request.method == 'POST':
        post.title = request.form['title']
        post.author = request.form['author']
        post.content = request.form['content']
        db.session.commit()
        flash("Post updated successfully!")
        return redirect(url_for('home'))
    return render_template('update.html', edit=post)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    post = Article.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!")
    return redirect(url_for('home'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user:
            flash('Username already exists. Choose another.')
        else:
            # Use 'pbkdf2:sha256' for password hashing
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registered successfully. Please login.')
            return redirect(url_for('login'))
    return render_template("register.html")


# blog page
@app.route("/post/<int:article_id>")
def post(article_id):
    article = Article.query.filter_by(id=article_id).first()  # Make sure to match the correct column name
    if article is None:
        return "Article not found", 404  # Handle the case where the article is not found
    return render_template("post.html", article=article)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for('login'))

# Create tables
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
