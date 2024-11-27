import werkzeug.security
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LogInForm, CommentForm, ContactMeForm
from flask_gravatar import Gravatar
from functools import wraps
import bleach
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
csrf = CSRFProtect(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return function(*args, **kwargs)
    return decorated_function

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('Users', back_populates='posts')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship('Comment', back_populates='parent_post')

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship('Users', back_populates='comments')

    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')
    text = db.Column(db.Text, nullable=False)

class ContactSubmission(db.Model):
    __tablename__ = 'contact_submissions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)



db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=['GET', 'Post'])
def register():
    register_form = RegisterForm()
    error = None
    if register_form.validate_on_submit():
        email = Users.query.filter_by(email=register_form.email.data).first()
        if not email:
            new_users = Users(
                email=register_form.email.data,
                password=werkzeug.security.generate_password_hash(password=register_form.password.data,
                                                                  method='pbkdf2:sha256',
                                                                  salt_length=8),
                name=register_form.name.data
            )
            db.session.add(new_users)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        else:
            error = 'Already registered with this email!'
    return render_template("register.html", login_form=register_form, error=error, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LogInForm()
    error = None

    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        user = Users.query.filter_by(email=email).first()
        if not user:
            error = 'Unregistered Email!'
        elif user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                error = 'Invalid Credentials!'
    return render_template("login.html", login_form=login_form, error=error, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    error = None
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            error = 'Log in required to comment'
            return redirect(url_for('login'))
        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, current_user=current_user, comment_form=comment_form, error=error)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)

@app.route("/projects")
def projects():
    return render_template("projects.html", current_user=current_user)

@app.route("/snake")
def snake():
    return render_template("snake.html", current_user=current_user)
@app.route("/turtle")
def turtle():
    return render_template("turtle.html", current_user=current_user)

@app.route("/cookie")
def cookie():
    return render_template("cookie.html", current_user=current_user)



@app.route("/contact", methods=['GET', 'POST'])
def contact():
    contact_me_form = ContactMeForm()

    if contact_me_form.validate_on_submit():
        name = contact_me_form.name.data
        email = contact_me_form.email.data
        phone= contact_me_form.phone.data
        message = contact_me_form.message.data

        new_submission = ContactSubmission(
            name=name,
            email=email,
            phone=phone,
            message=message
        )

        db.session.add(new_submission)
        db.session.commit()

        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))
    return render_template("contact.html", contact_me_form=contact_me_form, current_user=current_user)

@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    new_post_form = CreatePostForm()
    if new_post_form.validate_on_submit():
        body_cleaned = bleach.clean(new_post_form.body.data)

        new_post = BlogPost(
            title=new_post_form.title.data,
            subtitle=new_post_form.subtitle.data,
            body=body_cleaned,
            img_url=new_post_form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", new_post_form=new_post_form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
