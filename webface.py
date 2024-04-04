from flask import Flask, render_template, request, redirect, url_for, session, Markup, escape, flash
import functools
import datetime
from sqlitewrap import SQLite
from werkzeug.security import generate_password_hash, check_password_hash
from sqlite3 import IntegrityError
import string
import random

# from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = b"totoj e zceLa n@@@hodny retezec nejlep os.urandom(24)"
app.secret_key = b"x6\x87j@\xd3\x88\x0e8\xe8pM\x13\r\xafa\x8b\xdbp\x8a\x1f\xd41\xb8"



def prihlasit(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        if "user" in session:
            return function(*args, **kwargs)
        else:
            return redirect(url_for("login", url=request.path))

    return wrapper

@app.route("/", methods=["GET"])
def index():
    return render_template("base.html")

@app.route("/zkracovac/", methods=["GET"])
def zkracovac():
    shorturl=request.args.get("shorturl")

    with SQLite("data.sqlite") as cursor:
        response=cursor.execute("SELECT shorturl FROM url ")
        response=list(response.fetchall())
        print(response)
    return render_template("zkracovac.html", response=response, shorturl=shorturl  )

@app.route("/zkracovac/", methods=["POST"])
def zkracovac_post():
    shorturl=random_char(5)
    url=request.form.get("url").strip()
    print(url)

    with SQLite('data.sqlite') as cursor:
        if 'user' in session:
            response= cursor.execute("SELECT id FROM user WHERE login=?", [session["user"]])
            response= list(response.fetchone())
            if response:
                user_id=response[0]
            else:
                user_id=None
        else:
            user_id=None    
        

    with SQLite('data.sqlite') as cursor:
        cursor.execute('INSERT INTO url(url, shorturl,id_user) VALUES(?,?,?)', [url, shorturl, user_id])
    return redirect(url_for("zkracovac",shorturl=shorturl))


def random_char(y):
       return ''.join(random.choice(string.ascii_letters) for x in range(y))

@app.route("/zkracovac/<shorturl>/", methods=["GET"])
def smerovac(shorturl):
    with SQLite('data.sqlite') as cursor:
        response=cursor.execute("SELECT url FROM url WHERE shorturl=?", [shorturl])
        url=response.fetchone()[0]
    return redirect(url)

@app.route("/seznam/", methods=["GET"])
def seznam():
    if 'user' not in session:
        flash("Tato stránka je pouze pro příhlašné!", "error")
        return redirect(url_for("login", url=request.path)) 
    with SQLite('data.sqlite') as cursor:
        response=cursor.execute("SELECT id FROM user WHERE login=?", [session['user']])
        user_id = response.fetchone()[0]
        response_url=cursor.execute("SELECT url, shorturl FROM url WHERE id_user=?", [user_id])
        urla=response_url.fetchall()
    return render_template("seznam.html",urla=urla)

@app.route("/login/", methods=["GET"])
def login():
    return render_template("login.html")

@app.route("/login/", methods=["POST"])
def login_post():
    jmeno = request.form.get("jmeno","")
    heslo = request.form.get("heslo","")
    url=request.args.get("url", "")
    with SQLite("data.sqlite") as cursor:
        response= cursor.execute(
            f"SELECT login, passwd FROM user WHERE login =?", [jmeno]
        )
        response = response.fetchone()
        if response:
            login, passwd = response
            if check_password_hash(passwd, heslo):
                session["user"] = jmeno
                flash("Jsi přihlášen!", "success")
                if url:
                    return redirect(url)
                else:
                    return redirect(url_for("index"))
        flash("Špatné jméno nebo heslo!", "error")
        return redirect(url_for("login", url=url))

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Byl jsi odhlášen!", "succes")
    return redirect(url_for("index"))

@app.route("/register/", methods=["GET"])
def register():
    return render_template("register.html")

@app.route("/register/", methods=["POST"])
def register_post():
    jmeno = request.form.get("jmeno","")
    heslo1 = request.form.get("heslo1","")
    heslo2 = request.form.get("heslo2","")
    if len(jmeno) <5:
        flash("Jméno musí mít alespoň 5 znaků!!", "error")
        return render_template(url_for("register"))
    if len(heslo1) <5:
        flash("Heslo musí mít alespoň 5 znaků!!", "error")
        return render_template(url_for("register"))
    if heslo1 !=heslo2:
        flash("Musíte zadat dvakrát stejné heslo!", "error")
        return render_template("register")
    hash_ = generate_password_hash(heslo1)
    try:
        with SQLite("data.sqlite") as cursor:
            cursor.execute('INSERT INTO user (login,passwd) VALUES (?,?)', [jmeno, hash_])
            flash(f"Uživatel `{jmeno}` byl přidán!", "success")
    except IntegrityError:
        flash(f"Uživatel `{jmeno}` existuje!", "error")
    return redirect(url_for("register"))

