from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUser, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##login manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(id)

##CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    post = db.relationship("BlogPost", backref="author", lazy=True) # this allows you to tab in to User.
    # e.g. If post is an object of BlogPost, you can do post.author.email to get the email for the person who wrote the post
    comment = db.relationship("Comment",backref="author", lazy=True)

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.relationship("User", backref="post", lazy=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False) #inside ForeignKey needs to be the name of the parent table
    comment = db.relationship("Comment", backref="parent_post", lazy=True)

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    parent_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)

# Create all the tables in the database
db.create_all()

def admin_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id == 1:
                return f(*args, **kwargs)
        else:
            return abort(403)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    clearance = False
    if current_user.is_authenticated:
        if current_user.id ==1:
            clearance = True
    return render_template("index.html", all_posts=posts, clearance=clearance)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterUser()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():

            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        else:
            password = form.password.data
            password = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(email=form.email.data, name=form.name.data, password=password)
            db.session.add(new_user)
            db.session.commit()
            
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        entered_password = form.password.data
        user = User.query.filter_by(email=form.email.data).first()
        if check_password_hash(user.password, entered_password):
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    comments = Comment.query.filter_by(parent_post_id=post_id).all()

    if request.method == "POST":
        if current_user.is_authenticated:
            print(form.body.data)
            new_comment = Comment(text=form.body.data, author_id=current_user.id, parent_post_id=post_id)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("get_all_posts"))

    clearance = False
    if current_user.is_authenticated:
        if current_user.id==1:
            clearance = True

    return render_template("post.html", post=requested_post, clearance=clearance, form=form,
                           comments=comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_logged_in
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_logged_in
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))



    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    if current_user.is_authenticated:
        if current_user.id==1:
            post_to_delete = BlogPost.query.get(post_id)
            db.session.delete(post_to_delete)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
    else:
        return abort(402)


if __name__ == "__main__":
    app.run(debug=True)
