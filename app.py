import os
import hashlib
from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecretkey")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["RECAPTCHA_PUBLIC_KEY"] = "6LcLOV4rAAAAAAu4HijZJaDseffQo4ct2joy_pMB"
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LcLOV4rAAAAAHkUXujOSaq8NAR3EK1qHI_R_Dqx"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    is_subscribed = db.Column(db.Boolean, default=False)

    def gravatar(self, size=100):
        digest = hashlib.md5(self.email.lower().encode("utf-8")).hexdigest()
        return f"https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}"

class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Пароль", validators=[InputRequired(), Length(min=6)])
    confirm = PasswordField("Повторите пароль", validators=[EqualTo("password")])
    recaptcha = RecaptchaField()
    submit = SubmitField("Зарегистрироваться")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Пароль", validators=[InputRequired()])
    submit = SubmitField("Войти")

class ProfileEditForm(FlaskForm):
    first_name = StringField("Имя")
    last_name = StringField("Фамилия")
    submit = SubmitField("Сохранить")

@app.before_first_request
def create_tables():
    db.create_all()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/schedule")
def schedule():
    return render_template("schedule.html")

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/coaches")
def coaches():
    return render_template("coaches.html")

@app.route("/blog")
def blog():
    return render_template("blog.html")

@app.route("/gallery")
def gallery():
    return render_template("gallery.html")

@app.route("/contacts")
def contacts():
    return render_template("contacts.html")

@app.route("/reviews")
def reviews():
    return render_template("reviews.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Пользователь с таким email уже существует", "danger")
            return render_template("register.html", form=form)
        hashed_pw = generate_password_hash(form.password.data)
        user = User(email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash("Регистрация прошла успешно! Теперь вы можете войти.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash("Пользователь с таким email не найден", "danger")
            return render_template("login.html", form=form)
        if not check_password_hash(user.password, form.password.data):
            flash("Неверный пароль", "danger")
            return render_template("login.html", form=form)
        session["user_id"] = user.id
        flash("Вход выполнен успешно!", "success")
        return redirect(url_for("index"))
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("index"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = User.query.get(session.get("user_id"))
    if not user:
        return redirect(url_for("login"))
    form = ProfileEditForm(obj=user)
    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        db.session.commit()
        flash("Профиль обновлен!", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user, form=form)

@app.route("/subscribe")
def subscribe():
    user = User.query.get(session.get("user_id"))
    if not user:
        return redirect(url_for("login"))
    user.is_subscribed = True
    db.session.commit()
    flash("Вы подписались на сайт!", "success")
    return redirect(url_for("profile"))

@app.route("/unsubscribe")
def unsubscribe():
    user = User.query.get(session.get("user_id"))
    if not user:
        return redirect(url_for("login"))
    user.is_subscribed = False
    db.session.commit()
    flash("Подписка отменена.", "info")
    return redirect(url_for("profile"))

@app.errorhandler(404)
def page_not_found(e):
    try:
        return render_template("404.html"), 404
    except Exception:
        return "Страница не найдена :(", 404

if __name__ == "__main__":
    # Для SSL (локально): app.run(ssl_context=('cert/cert.pem', 'cert/key.pem'), debug=True)
    app.run(debug=True)
