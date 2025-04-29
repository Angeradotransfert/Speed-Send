import eventlet
eventlet.monkey_patch()
import os
import random
import sqlite3
import string
from unittest import result
from flask_socketio import SocketIO, emit




from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message
import logging

from flask_wtf import FlaskForm  # Ajout de cette ligne
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
import bcrypt
from flask_login import login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FloatField, HiddenField, SubmitField
from wtforms.validators import DataRequired


load_dotenv()  # charge le fichier .env

# 🔒 Taux fixes (modifiable plus tard via l'admin si besoin)
FIXED_RATES = {
    ("Côte d'Ivoire", "Russie"): 0.136,   # 1 XOF ➜ 0,136 RUB
    ("Russie", "Côte d'Ivoire"): 6.6      # 1 RUB ➜ 6,6 XOF
}

# 🔒 Taux fixes
FIXED_RATES = {
    ("Côte d'Ivoire", "Russie"): 0.136,
    ("Russie", "Côte d'Ivoire"): 6.6,
    ("Sénégal", "Russie"): 0.136,
    ("Russie", "Sénégal"): 6.6,
    ("Guinée", "Russie"): 0.136,
    ("Russie", "Guinée"): 6.6,
    ("Burkina Faso", "Russie"): 0.136,
    ("Russie", "Burkina Faso"): 6.6,
    ("Cameroun", "Russie"): 0.128,
    ("Russie", "Cameroun"): 6.54,
    ("Congo Brazzaville", "Russie"): 0.128,
    ("Russie", "Congo Brazzaville"): 6.54,
    ("Congo Kinshasa", "Russie"): 0.128,
    ("Russie", "Congo Kinshasa"): 6.54,
    ("Tchad", "Russie"): 0.128,
    ("Russie", "Tchad"): 6.54
}

# 🔒 Frais fixes
FIXED_FEES = {
    ("Côte d'Ivoire", "Russie"): 370,
    ("Russie", "Côte d'Ivoire"): 30,
    ("Sénégal", "Russie"): 370,
    ("Russie", "Sénégal"): 30,
    ("Guinée", "Russie"): 370,
    ("Russie", "Guinée"): 30,
    ("Burkina Faso", "Russie"): 370,
    ("Russie", "Burkina Faso"): 30,
    ("Cameroun", "Russie"): 280,
    ("Russie", "Cameroun"): 25,
    ("Congo Brazzaville", "Russie"): 280,
    ("Russie", "Congo Brazzaville"): 25,
    ("Congo Kinshasa", "Russie"): 280,
    ("Russie", "Congo Kinshasa"): 25,
    ("Tchad", "Russie"): 280,
    ("Russie", "Tchad"): 25
}


# --- Ajout automatique des colonnes exchange_rate et converted_amount ----------
def add_rate_columns():
    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE pending_transfers ADD COLUMN exchange_rate REAL;")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE pending_transfers ADD COLUMN converted_amount REAL;")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

add_rate_columns()
# -------------------------------------------------------------------------------

def add_num_expediteur_column():
    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE pending_transfers ADD COLUMN numero_expediteur TEXT;")
    except sqlite3.OperationalError:
        pass  # colonne déjà présente
    conn.commit()
    conn.close()

add_num_expediteur_column()

app = Flask(__name__)

socketio = SocketIO(app)

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address)

app.secret_key = os.getenv('SECRET_KEY')

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

csrf.init_app(app)

# ✅ Variables de numéro selon le pays d’envoi
NUMERO_RUSSIE = os.getenv("NUMERO_RUSSIE")
NUMERO_COTEIVOIRE = os.getenv("NUMERO_COTEIVOIRE")

class TransfertForm(FlaskForm):
    nom_expediteur = StringField("Nom de l'expéditeur", validators=[DataRequired()])
    pays_envoi = SelectField("Pays d'envoi", choices=[
        ("Russie", "Russie"),
        ("Côte d'Ivoire", "Côte d'Ivoire"),
        ("Congo Brazzaville", "Congo Brazzaville"),
        ("Congo Kinshasa", "Congo Kinshasa"),
        ("Guinée", "Guinée"),
        ("Tchad", "Tchad"),
        ("Cameroun", "Cameroun"),
        ("Sénégal", "Sénégal"),
        ("Burkina Faso", "Burkina Faso")
    ], validators=[DataRequired()])

    methode_envoi = SelectField("Méthode d'envoi", choices=[
        ("Tinkoff", "Tinkoff"),
        ("Sberbank", "Sberbank"),
        ("Carte bancaire", "Carte bancaire"),
        ("Orange Money", "Orange Money"),
        ("MTN", "MTN"),
        ("Wave", "Wave"),
        ("Moov", "Moov")
    ], validators=[DataRequired()])

    montant = FloatField("Montant", validators=[DataRequired()])

    devise_expediteur = SelectField("Devise de l'expéditeur", choices=[
        ("XOF", "XOF"),
        ("XAF", "XAF"),
        ("USD", "USD"),
        ("EUR", "EUR"),
        ("GBP", "GBP"),
        ("NGN", "NGN"),
        ("RUB", "RUB (Rouble)")
    ], validators=[DataRequired()])

    numero_expediteur = StringField("Numéro de l'expéditeur", validators=[DataRequired()])

    # 🔵 Séparation propre
    pays_destinataire = SelectField("Pays du destinataire", choices=[
        ("Russie", "Russie"),
        ("Côte d'Ivoire", "Côte d'Ivoire"),
        ("Congo Brazzaville", "Congo Brazzaville"),
        ("Congo Kinshasa", "Congo Kinshasa"),
        ("Guinée", "Guinée"),
        ("Tchad", "Tchad"),
        ("Cameroun", "Cameroun"),
        ("Sénégal", "Sénégal"),
        ("Burkina Faso", "Burkina Faso")
    ], validators=[DataRequired()])

    nom_destinataire = StringField("Nom du destinataire", validators=[DataRequired()])
    numero_destinataire = StringField("Numéro du destinataire", validators=[DataRequired()])

    methode_reception = SelectField("Méthode de réception", choices=[
        ("Orange Money", "Orange Money"),
        ("MTN", "MTN"),
        ("Wave", "Wave"),
        ("Moov", "Moov"),
        ("Carte bancaire", "Carte bancaire"),
        ("Compte bancaire", "Compte bancaire")
    ], validators=[DataRequired()])

    devise_destinataire = SelectField("Devise du destinataire", choices=[
        ("XOF", "XOF"),
        ("XAF", "XAF"),
        ("USD", "USD"),
        ("EUR", "EUR"),
        ("GBP", "GBP"),
        ("NGN", "NGN"),
        ("RUB", "RUB (Rouble)")
    ], validators=[DataRequired()])

    exchange_rate = HiddenField()
    converted_amount = HiddenField()

    submit = SubmitField("Envoyer")

# Formulaire Flask-WTF pour la connexion
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

def init_db():
    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()

    # Créer la table users avec la colonne 'role' directement
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            verification_code TEXT,
            is_verified INTEGER DEFAULT 0,
            role TEXT DEFAULT 'user'  -- Colonne 'role' ajoutée avec valeur par défaut
        )
    ''')

    # Créer d'autres tables si nécessaire (wallets, balances, transactions, etc.)
    c.execute('''
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            currency TEXT NOT NULL,
            balance REAL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()



    # Ajouter la colonne role si elle n'existe pas déjà
    try:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';")
    except sqlite3.OperationalError:
        pass  # Ignore si la colonne existe déjà

    conn.commit()
    conn.close()

    # Table des utilisateurs
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            verification_code TEXT,
            is_verified INTEGER DEFAULT 0
        )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        currency TEXT NOT NULL,
        balance REAL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

    # Table des soldes
    c.execute('''
        CREATE TABLE IF NOT EXISTS balances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            currency TEXT NOT NULL,
            amount REAL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    c.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                recipient_id INTEGER,
                currency TEXT,
                amount REAL,
                date TEXT,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(recipient_id) REFERENCES users(id)
            )
        ''')

    c.execute('''
            CREATE TABLE IF NOT EXISTS external_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                amount REAL,
                currency TEXT,
                recipient_type TEXT, -- 'email', 'phone', 'bank'
                recipient_value TEXT, -- ex: email, numéro ou IBAN
                status TEXT DEFAULT 'pending',
                flutterwave_ref TEXT,
                date TEXT,
                FOREIGN KEY(sender_id) REFERENCES users(id)
            )
        ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS pending_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_name TEXT,
            sender_country TEXT,
            payment_method TEXT,
            amount REAL,
            total_with_fees REAL,
            currency TEXT,
            recipient_name TEXT,
            recipient_phone TEXT,
            recipient_operator TEXT,
            status TEXT DEFAULT 'en_attente',
            created_at TEXT
        )
    ''')

    conn.commit()
    conn.close()



@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register_form')
def register_form():
    return render_template('register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Hachage du mot de passe avant de l'enregistrer
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('transfert.db')
        c = conn.cursor()

        try:
            c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                      (name, email, hashed_pw))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Cet email est déjà utilisé.")
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute")  # Limite à 3 tentatives par minute
def login():
    form = LoginForm()  # Crée une instance du formulaire

    if form.validate_on_submit():  # Si le formulaire est soumis et valide
        email = form.email.data
        password = form.password.data

        conn = sqlite3.connect('transfert.db')
        c = conn.cursor()
        c.execute("SELECT password, is_verified, role FROM users WHERE email = ?", (email,))
        result = c.fetchone()
        conn.close()

        if result:
            db_password, is_verified, role = result
            if bcrypt.checkpw(password.encode('utf-8'), db_password):  # Le mot de passe dans la base de données est déjà en bytes
                if is_verified:
                    conn = sqlite3.connect('transfert.db')
                    c = conn.cursor()
                    c.execute("SELECT id FROM users WHERE email = ?", (email,))
                    user_id = c.fetchone()[0]
                    conn.close()

                    session['user_id'] = user_id
                    session['user_role'] = role  # Stocke le rôle dans la session

                    return redirect(url_for('welcome', user_id=user_id))
                else:
                    flash("Votre compte n'est pas encore vérifié. Un code vous a été envoyé.")
                    return redirect(url_for('verify', email=email))
            else:
                flash("Mot de passe incorrect.")
                return render_template('login.html', form=form)
        else:
            flash("Email introuvable.")
            return render_template('login.html', form=form)

    # Si GET ou si le formulaire est invalide
    return render_template('login.html', form=form)




@app.route('/dashboard/<int:user_id>')
def dashboard(user_id):
    conn = sqlite3.connect('transfert.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()

    wallets = []
    if user:
        c.execute("SELECT currency, balance FROM wallets WHERE user_id = ?", (user_id,))
        wallets = c.fetchall()
    conn.close()

    return render_template('dashboard.html', username=user['name'], wallets=wallets, user_id=user_id)

@app.route('/add_currency/<int:user_id>', methods=['GET', 'POST'])
def add_currency(user_id):
    if request.method == 'POST':
        currency = request.form['currency']

        conn = sqlite3.connect('transfert.db')
        c = conn.cursor()

        # Vérifie si la devise existe déjà
        c.execute("SELECT * FROM wallets WHERE user_id = ? AND currency = ?", (user_id, currency))
        exists = c.fetchone()

        if not exists:
            c.execute("INSERT INTO wallets (user_id, currency) VALUES (?, ?)", (user_id, currency))
            conn.commit()

        conn.close()
        return redirect(f"/dashboard/{user_id}")

    # Si GET, on affiche le formulaire
    return render_template("add_currency.html", user_id=user_id)


@app.route('/send_money_form/<username>')
def send_money_form(username):
    conn = sqlite3.connect('transfert.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Récupérer l'ID de l'utilisateur
    c.execute("SELECT id FROM users WHERE name = ?", (username,))
    user = c.fetchone()

    if not user:
        conn.close()
        return "Utilisateur introuvable"

    user_id = user['id']

    # Récupérer les soldes
    c.execute("SELECT currency, balance FROM wallets WHERE user_id = ?", (user_id,))
    wallets = c.fetchall()

    conn.close()

    return render_template("send_money.html", username=username, user_id=user_id, wallets=wallets)


@app.route('/send_money', methods=['POST'])
def send_money():
    sender = request.form['sender']
    recipient = request.form['recipient']
    currency = request.form['currency']
    amount = float(request.form['amount'])

    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()

    # Vérifier les IDs
    c.execute("SELECT id FROM users WHERE name = ?", (sender,))
    sender_id = c.fetchone()

    c.execute("SELECT id FROM users WHERE name = ?", (recipient,))
    recipient_id = c.fetchone()

    if not sender_id or not recipient_id:
        conn.close()
        return "Utilisateur introuvable."

    # Vérifier solde du sender
    c.execute("SELECT balance FROM wallets WHERE user_id = ? AND currency = ?", (sender_id[0], currency))
    sender_balance = c.fetchone()

    if not sender_balance or sender_balance[0] < amount:
        conn.close()
        return "Solde insuffisant."

    # Débiter sender
    c.execute("UPDATE wallets SET balance = balance - ? WHERE user_id = ? AND currency = ?",
              (amount, sender_id[0], currency))

    # Créditer recipient (créer la devise si elle n'existe pas)
    c.execute("SELECT balance FROM wallets WHERE user_id = ? AND currency = ?", (recipient_id[0], currency))
    recipient_wallet = c.fetchone()
    if recipient_wallet:
        c.execute("UPDATE wallets SET balance = balance + ? WHERE user_id = ? AND currency = ?",
                  (amount, recipient_id[0], currency))
    else:
        c.execute("INSERT INTO wallets (user_id, currency, balance) VALUES (?, ?, ?)",
                  (recipient_id[0], currency, amount))

    conn.commit()
    from datetime import datetime
    c.execute("INSERT INTO transactions (sender_id, recipient_id, currency, amount, date) VALUES (?, ?, ?, ?, ?)",
              (sender_id[0], recipient_id[0], currency, amount, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.close()

    return redirect(url_for('transfert_reussi', recipient=recipient, amount=amount, currency=currency))

@app.route('/verify_code', methods=['POST'])
def verify_code():
    code_entered = request.form['code']
    email = request.form['email']

    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()
    c.execute("SELECT verification_code FROM users WHERE email = ?", (email,))
    result = c.fetchone()

    if result and result[0] == code_entered.strip():
        c.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        flash("✔️ Votre compte a été vérifié avec succès. Vous pouvez maintenant vous connecter.")
        return redirect(url_for('login'))
    else:
        conn.close()
        error = "Code incorrect. Veuillez réessayer."
        return render_template('verify.html', email=email, error=error)


from flask import flash


@app.route('/resend_code', methods=['POST'])
def resend_code():
    from flask import request, flash, render_template
    import re

    email = request.form.get('email')

    print("Renvoyer le code à :", email)

    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        flash("Adresse email invalide.")
        return redirect(url_for('login'))

    try:
        # Génération du nouveau code
        new_code = ''.join(random.choices(string.digits, k=6))

        # Mise à jour dans la base de données
        conn = sqlite3.connect('transfert.db')
        c = conn.cursor()
        c.execute("UPDATE users SET verification_code = ? WHERE email = ?", (new_code, email))
        conn.commit()

        # Création du mail
        msg = Message('Nouveau code de vérification',
                      recipients=[email])
        msg.body = f'Bonjour,\n\nVotre nouveau code de vérification est : {new_code}\n\nMerci.'

        # Envoi du mail
        mail.send(msg)

        flash("📧 Un nouveau code a été envoyé à votre adresse email.")
        return render_template('verify.html', email=email)

    except Exception as e:
        print(f"[ERREUR MAIL] {e}")
        flash("❌ Échec de l'envoi du mail. Vérifiez votre adresse ou réessayez plus tard.")
        return render_template('verify.html', email=email)

    finally:
        conn.close()


@app.route('/verify', methods=['GET'])
def verify():
    email = request.args.get('email')
    return render_template('verify.html', email=email)

@app.route('/test_email')
def test_email():
    try:
        msg = Message('Test Email ✔️', recipients=['konea3873@gmail.com'])
        msg.body = 'Ceci est un test d’envoi d’email depuis ton application Flask.'
        mail.send(msg)
        return "Email de test envoyé avec succès ✅"
    except Exception as e:
        return f"Erreur lors de l’envoi : {e}"

@app.route('/welcome/<int:user_id>')
def welcome(user_id):
    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()
    c.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()

    if user:
        return render_template('welcome.html', user_id=user_id, username=user[0])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

from flask import render_template, request
from rave_python import Rave
from flutterwave_config import FLW_PUBLIC_KEY, FLW_SECRET_KEY

import requests
from dotenv import load_dotenv
import os

load_dotenv()

FLW_SECRET_KEY = os.getenv("FLW_SECRET_KEY")

@app.route('/payer', methods=['GET', 'POST'])
def payer():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        amount = request.form['amount']
        currency = request.form['currency']

        data = {
            "tx_ref": f"TRX-{random.randint(10000,99999)}",
            "amount": amount,
            "currency": currency,
            "redirect_url": "http://127.0.0.1:5000/flutterwave_callback",
            "customer": {
                "email": email,
                "name": name
            },
            "customizations": {
                "title": "SpeedSend - Envoi d'argent",
                "description": "Paiement sécurisé via Flutterwave"
            }
        }

        headers = {
            "Authorization": f"Bearer {FLW_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        response = requests.post("https://api.flutterwave.com/v3/payments", json=data, headers=headers)

        if response.status_code == 200:
            payment_link = response.json()['data']['link']
            return redirect(payment_link)
        else:
            return f"Erreur Flutterwave : {response.text}"

    return render_template('payer.html')

@app.route('/paiement_reussi')
def paiement_reussi():
    return "Paiement effectué avec succès ! ✅"

@app.route('/flutterwave_callback')
def flutterwave_callback():
    status = request.args.get('status')
    tx_ref = request.args.get('tx_ref')
    transaction_id = request.args.get('transaction_id')

    if status == 'successful':
        # Vérifier le paiement auprès de Flutterwave
        headers = {
            "Authorization": f"Bearer {FLW_SECRET_KEY}"
        }

        verify_url = f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify"
        response = requests.get(verify_url, headers=headers)

        if response.status_code == 200:
            data = response.json()['data']
            amount = data['amount']
            currency = data['currency']
            customer_email = data['customer']['email']

            # 🔍 Trouver l'utilisateur avec cet email
            conn = sqlite3.connect('transfert.db')
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE email = ?", (customer_email,))
            user = c.fetchone()

            if user:
                user_id = user[0]

                # 📥 Créditer le wallet
                c.execute("SELECT balance FROM wallets WHERE user_id = ? AND currency = ?", (user_id, currency))
                wallet = c.fetchone()
                if wallet:
                    c.execute("UPDATE wallets SET balance = balance + ? WHERE user_id = ? AND currency = ?",
                              (amount, user_id, currency))
                else:
                    c.execute("INSERT INTO wallets (user_id, currency, balance) VALUES (?, ?, ?)",
                              (user_id, currency, amount))

                conn.commit()
                conn.close()
                return "Paiement vérifié et crédité ✅"
            else:
                return "Utilisateur introuvable dans la base de données."

        else:
            return f"Erreur vérification Flutterwave : {response.text}"

    return "Paiement échoué ou annulé ❌"

@app.route('/credit_wallet/<int:user_id>')
def credit_wallet(user_id):
    currency = "XOF"
    amount = 50000  # tu peux changer le montant

    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()
    c.execute("SELECT balance FROM wallets WHERE user_id = ? AND currency = ?", (user_id, currency))
    result = c.fetchone()

    if result:
        c.execute("UPDATE wallets SET balance = balance + ? WHERE user_id = ? AND currency = ?", (amount, user_id, currency))
    else:
        c.execute("INSERT INTO wallets (user_id, currency, balance) VALUES (?, ?, ?)", (user_id, currency, amount))

    conn.commit()
    conn.close()
    return f"✅ Wallet de l'utilisateur {user_id} crédité avec {amount} {currency}."

@app.route('/seed_data')
def seed_data():
    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()

    # Création des utilisateurs
    users = [
        ('Alice', 'alice@example.com', 'pass123'),
        ('Bob', 'bob@example.com', 'pass123')
    ]

    user_ids = {}

    for name, email, password in users:
        try:
            c.execute("INSERT INTO users (name, email, password, is_verified) VALUES (?, ?, ?, 1)",
                      (name, email, password))
            user_id = c.lastrowid
            user_ids[name] = user_id
        except sqlite3.IntegrityError:
            # Si l'utilisateur existe déjà, on le récupère
            c.execute("SELECT id FROM users WHERE email = ?", (email,))
            user_id = c.fetchone()[0]
            user_ids[name] = user_id

    # Créditer Alice avec 100000 XOF
    currency = "XOF"
    amount = 100000
    c.execute("SELECT balance FROM wallets WHERE user_id = ? AND currency = ?", (user_ids['Alice'], currency))
    wallet = c.fetchone()

    if wallet:
        c.execute("UPDATE wallets SET balance = ? WHERE user_id = ? AND currency = ?",
                  (amount, user_ids['Alice'], currency))
    else:
        c.execute("INSERT INTO wallets (user_id, currency, balance) VALUES (?, ?, ?)",
                  (user_ids['Alice'], currency, amount))

    conn.commit()
    conn.close()

    return "✅ Données de test créées : Alice (100000 XOF), Bob (0 XOF)"

@app.route('/transfert_reussi')
def transfert_reussi():
    recipient = request.args.get('recipient')
    amount = request.args.get('amount')
    currency = request.args.get('currency')

    return render_template('transfert_reussi.html', recipient=recipient, amount=amount, currency=currency)

@app.route('/historique/<int:user_id>')
def historique(user_id):
    conn = sqlite3.connect('transfert.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Récupère les transactions envoyées par l'utilisateur
    c.execute('''
        SELECT t.amount, t.currency, t.date, u.name as recipient_name
        FROM transactions t
        JOIN users u ON t.recipient_id = u.id
        WHERE t.sender_id = ?
        ORDER BY t.date DESC
    ''', (user_id,))
    transactions = c.fetchall()

    conn.close()
    return render_template("historique.html", transactions=transactions)

@app.route('/send_external_form/<int:user_id>')
def send_external_form(user_id):
    return render_template('send_external_logged.html', user_id=user_id)

@app.route('/send_external', methods=['POST'])
def send_external():
    from datetime import datetime
    import requests

    sender_id = request.form['sender_id']
    amount = float(request.form['amount'])
    currency = request.form['currency']
    recipient_type = request.form['recipient_type']
    recipient_name = request.form['recipient_name']
    recipient_value = request.form['recipient_value']
    operator = request.form['operator']

    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()

    # Vérifier solde
    c.execute("SELECT balance FROM wallets WHERE user_id = ? AND currency = ?", (sender_id, currency))
    wallet = c.fetchone()

    if not wallet or wallet[0] < amount:
        conn.close()
        return "❌ Solde insuffisant"

    # Débiter
    c.execute("UPDATE wallets SET balance = balance - ? WHERE user_id = ? AND currency = ?",
              (amount, sender_id, currency))

    # 📦 Préparer les données Flutterwave
    reference = f"EXT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    headers = {
        "Authorization": f"Bearer {FLW_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    # Flutterwave bank code ou mobile operator code
    operator_code_map = {
        "Orange Money": "MOMO",  # à adapter selon pays
        "MTN": "MTN",
        "Wave": "WAVE"
    }

    payout_data = {
        "account_bank": operator_code_map.get(operator, "MOMO"),  # Code opérateur
        "account_number": recipient_value,  # numéro téléphone ou compte
        "amount": amount,
        "currency": currency,
        "beneficiary_name": recipient_name,
        "reference": reference,
        "narration": "Transfert externe via SpeedSend"
    }

    # 🔄 Appel API Flutterwave
    # 🔄 Appel API Flutterwave
    flutter_response = requests.post(
        "https://api.flutterwave.com/v3/transfers",
        json=payout_data,
        headers=headers
    )

    status = 'failed'
    flutter_ref = ''

    try:
        flutter_data = flutter_response.json()
        logging.info("Réponse Flutterwave : %s", flutter_data)
        if flutter_data['status'] == 'success':
            status = 'sent'
            flutter_ref = flutter_data['data']['id']
    except Exception as e:
        logging.error("Erreur Flutterwave : %s", e)
        flutter_data = {"message": str(e)}

    # 💾 Enregistrer la transaction dans tous les cas
    c.execute('''
        INSERT INTO external_transfers (
            sender_id, amount, currency, recipient_type,
            recipient_value, status, flutterwave_ref, date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (sender_id, amount, currency, recipient_type, recipient_value,
          status, str(flutter_ref), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()

    # 🔁 S'assurer qu'on retourne TOUJOURS une réponse
    if status == 'sent':
        return f"✅ Transfert vers {recipient_name} via {operator} lancé avec succès."
    else:
        return f"❌ Échec du transfert Flutterwave : {flutter_data.get('message', 'Erreur inconnue')}"

@app.route('/transfert_formulaire', methods=['GET', 'POST'])
def transfert_formulaire(transfert_id=None):
    form = TransfertForm()

    # 🔵 Choices globaux
    pays_choices = [
        ("Russie", "Russie"),
        ("Côte d'Ivoire", "Côte d'Ivoire"),
        ("Congo Brazzaville", "Congo Brazzaville"),
        ("Congo Kinshasa", "Congo Kinshasa"),
        ("Guinée", "Guinée"),
        ("Tchad", "Tchad"),
        ("Cameroun", "Cameroun"),
        ("Sénégal", "Sénégal"),
        ("Burkina Faso", "Burkina Faso")
    ]
    form.pays_envoi.choices = pays_choices
    form.pays_destinataire.choices = pays_choices

    ci_methods = [
        ("Orange Money", "Orange Money"),
        ("Wave", "Wave"),
        ("MTN", "MTN"),
        ("Moov", "Moov")
    ]
    ru_methods = [
        ("Tinkoff", "Tinkoff"),
        ("Sberbank", "Sberbank")
    ]
    autres_methods = [
        ("Orange Money", "Orange Money"),
        ("MTN", "MTN"),
        ("Airtel Money", "Airtel Money"),
        ("Wave", "Wave"),
        ("Orange Money Guinée", "Orange Money Guinée"),
        ("MTN Mobile Money", "MTN Mobile Money"),
        ("Orange Money Cameroun", "Orange Money Cameroun"),
        ("Wave Sénégal", "Wave Sénégal"),
        ("Orange Money Sénégal", "Orange Money Sénégal"),
        ("Orange Money Burkina", "Orange Money Burkina")
    ]

    devise_choices = [
        ("XOF", "XOF"),
        ("XAF", "XAF"),
        ("USD", "USD"),
        ("EUR", "EUR"),
        ("GBP", "GBP"),
        ("NGN", "NGN"),
        ("RUB", "RUB (Rouble)")
    ]
    form.devise_expediteur.choices = devise_choices
    form.devise_destinataire.choices = devise_choices

    # ⚡ Dynamiser les méthodes en fonction du pays choisi
    if request.method == "POST":
        pays_envoi = request.form.get('pays_envoi')
        pays_destinataire = request.form.get('pays_destinataire')

        if pays_envoi == "Russie":
            form.methode_envoi.choices = ru_methods
        elif pays_envoi == "Côte d'Ivoire":
            form.methode_envoi.choices = ci_methods
        else:
            form.methode_envoi.choices = autres_methods

        if pays_destinataire == "Russie":
            form.methode_reception.choices = ru_methods
        elif pays_destinataire == "Côte d'Ivoire":
            form.methode_reception.choices = ci_methods
        else:
            form.methode_reception.choices = autres_methods

    else:
        # GET - Valeurs par défaut
        form.methode_envoi.choices = autres_methods
        form.methode_reception.choices = autres_methods

    # 🎯 Validation
    if form.validate_on_submit():
        from datetime import datetime

        sender_name        = form.nom_expediteur.data
        sender_country     = form.pays_envoi.data
        payment_method     = form.methode_envoi.data
        amount             = form.montant.data
        currency           = form.devise_expediteur.data
        recipient_name     = form.nom_destinataire.data
        recipient_phone    = form.numero_destinataire.data
        recipient_operator = form.methode_reception.data
        recipient_country  = form.pays_destinataire.data
        numero_expediteur  = form.numero_expediteur.data
        currency_dest      = form.devise_destinataire.data

        # 🧮 Lire taux et frais depuis la base
        conn = sqlite3.connect('transfert.db')
        c = conn.cursor()
        c.execute('''
            SELECT rate FROM fees_and_rates
            WHERE source_country = ? AND destination_country = ?
        ''', (sender_country, recipient_country))
        rate_row = c.fetchone()
        rate = rate_row[0] if rate_row else 1

        # 2.5 % des frais
        frais = round(amount * 0.025, 2)

        # Devise des frais selon le pays d’envoi
        if sender_country in ["Russie"]:
            frais_currency = "RUB"
        else:
            frais_currency = "XOF"
        conn.close()

        converted = amount * rate
        converted = amount * rate
        total_source = amount + frais
        total_dest   = converted + frais
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 💾 Enregistrement en BDD
        conn = sqlite3.connect('transfert.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO pending_transfers (
                sender_name, sender_country, payment_method, amount,
                total_with_fees, currency, recipient_name, recipient_phone,
                recipient_operator, created_at, recipient_country,
                numero_expediteur, exchange_rate, converted_amount, currency_dest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            sender_name, sender_country, payment_method, amount,
            total_dest, currency, recipient_name, recipient_phone,
            recipient_operator, created_at, recipient_country,
            numero_expediteur, rate, converted, currency_dest
        ))
        conn.commit()
        conn.close()

        # ✅ Envoie le transfert au tableau admin en temps réel
        socketio.emit('nouveau_transfert', {
            'id': transfert_id,
            'sender_name': sender_name,
            'amount': amount,
            'currency': currency,
            'recipient_name': recipient_name,
            'created_at': created_at,
            'status': 'en_attente'
        })
        # 🔔 Notification Telegram
        msg = (
            "📥 NOUVEAU TRANSFERT MANUEL\n"
            f"👤 De : {sender_name} ({sender_country}) via {payment_method}\n"
            f"📞 Numéro : {numero_expediteur}\n"
            f"💸 Montant envoyé : {amount} {currency}\n"
            f"💱 Montant à recevoir : {converted} {currency_dest}\n"
            f"🔁 Frais : {frais} {frais_currency}\n"
            f"💰 Total payé : {total_source} {currency}\n"
            f"📲 Vers : {recipient_name} / {recipient_phone} ({recipient_operator})\n"
            f"🌍 Pays destinataire : {recipient_country}\n"
            f"🕒 Date : {created_at}"
        )
        send_telegram_message(msg)

        # 🔄 Redirection confirmation
        return redirect(url_for(
            'confirmer_transfert',
            sender_name=sender_name,
            total_source=total_source,
            currency=currency,
            payment_method=payment_method,
            recipient_name=recipient_name,
            recipient_phone=recipient_phone,
            recipient_operator=recipient_operator,
            created_at=created_at,
            amount=amount,
            sender_country=sender_country,
            recipient_country=recipient_country,
            numero_expediteur=numero_expediteur,
            exchange_rate=rate,
            converted_amount=converted,
            currency_dest=currency_dest,
            frais=frais,
            frais_currency=frais_currency
        ))

    if request.method == "POST":
        print("❌ Erreurs de validation :", form.errors)

    return render_template(
        'transfert_formulaire.html',
        form=form,
        numero_russie=NUMERO_RUSSIE,
        numero_cote=NUMERO_COTEIVOIRE
    )

from flask_wtf.csrf import generate_csrf  # ✅ à ajouter tout en haut si pas encore fait

from flask_wtf.csrf import generate_csrf

@app.route('/confirmer_transfert')
def confirmer_transfert():
    sender_name        = request.args.get('sender_name')
    total_source       = request.args.get('total_source')   # ← total payé
    currency           = request.args.get('currency')       # devise source
    payment_method     = request.args.get('payment_method')
    recipient_name     = request.args.get('recipient_name')
    recipient_phone    = request.args.get('recipient_phone')
    recipient_operator = request.args.get('recipient_operator')
    amount             = request.args.get('amount')
    created_at         = request.args.get('created_at')
    sender_country     = request.args.get('sender_country')
    recipient_country  = request.args.get('recipient_country')
    numero_expediteur  = request.args.get('numero_expediteur')

    # paramètres destinataire
    exchange_rate    = request.args.get('exchange_rate')
    converted_amount = request.args.get('converted_amount')
    currency_dest    = request.args.get('currency_dest')
    frais            = request.args.get('frais')
    frais_currency   = request.args.get('frais_currency')

    # ID du transfert
    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()
    c.execute(
        "SELECT id FROM pending_transfers WHERE sender_name = ? AND created_at = ?",
        (sender_name, created_at)
    )
    transfert    = c.fetchone()
    transfert_id = transfert[0] if transfert else None
    conn.close()

    return render_template(
        'confirmation_transfert.html',
        sender_name        = sender_name,
        total_source       = total_source,      # total à payer (devise source)
        currency           = currency,          # devise source
        currency_dest      = currency_dest,     # devise destinataire
        payment_method     = payment_method,
        recipient_name     = recipient_name,
        recipient_phone    = recipient_phone,
        recipient_operator = recipient_operator,
        amount             = amount,
        created_at         = created_at,
        transfert_id       = transfert_id,
        sender_country     = sender_country,
        recipient_country  = recipient_country,
        numero_expediteur  = numero_expediteur,
        exchange_rate      = exchange_rate,
        converted_amount   = converted_amount,
        frais              = frais,
        frais_currency     = frais_currency,
        numero_russie      = NUMERO_RUSSIE,
        numero_cote        = NUMERO_COTEIVOIRE,
        csrf_token         = generate_csrf()
    )

from flask import flash

@app.route('/payer_confirme', methods=['POST'])
def payer_confirme():
    transfert_id = request.form.get('transfert_id')
    if not transfert_id:
        return "Transfert non spécifié", 400

    flash("✅ Votre paiement a été confirmé. Le transfert est en cours de traitement.")
    return redirect(url_for('etat_transfert', transfert_id=transfert_id))


from flask_wtf.csrf import generate_csrf

@app.route('/admin_transferts')
def admin_transferts():
    if 'user_role' not in session or session['user_role'] != 'admin':
        return redirect(url_for('login'))

    conn = sqlite3.connect('transfert.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # 🔵 Récupérer tous les transferts
    c.execute("SELECT * FROM pending_transfers ORDER BY created_at DESC")
    transferts = c.fetchall()

    conn.close()

    csrf_token = generate_csrf()  # 🔐 Génère le token manuellement
    return render_template('admin_transferts.html', transferts=transferts, csrf_token=csrf_token)

from flask import jsonify

from flask import jsonify

@app.route('/marquer_effectue', methods=['POST'])
def marquer_effectue():
    transfert_id = request.form.get('transfert_id')
    if not transfert_id:
        return jsonify({'success': False}), 400

    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()
    c.execute("UPDATE pending_transfers SET status = 'effectué' WHERE id = ?", (transfert_id,))
    conn.commit()
    conn.close()

    # ✅ Notification socket
    socketio.emit('transfert_valide', {'transfert_id': int(transfert_id)})
    return jsonify({'success': True})

@app.route('/init_db')
def run_init_db():
    init_db()
    return "✅ Base mise à jour avec la table external_transfers"

# Configuration du bot Telegram
BOT_TOKEN = '8069658289:AAHzBhZbm8opr1rfGBclNpygLx4BSxD6plg'
CHAT_ID = 'TON_CHAT_ID_ICI'

def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': 7543021330,
        'text': message
    }
    try:
        requests.post(url, data=payload)
    except Exception as e:
        print("Erreur lors de l'envoi Telegram :", e)

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

@app.route('/transfert_valide')
def transfert_valide():
    return render_template('transfert_valide.html')

@app.route('/etat_transfert/<int:transfert_id>')
def etat_transfert(transfert_id):
    conn = sqlite3.connect('transfert.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM pending_transfers WHERE id = ?", (transfert_id,))
    transfert = c.fetchone()
    conn.close()

    if transfert is None:
        return "Transfert introuvable", 404

    return render_template('etat_transfert.html', transfert=transfert)

@app.route('/debug_list_img')
def debug_list_img():
    import os
    path = os.path.join(app.root_path, 'static', 'img')
    return '<br>'.join(os.listdir(path))


import webbrowser
import threading

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

# Lancer dans un thread séparé pour ne pas bloquer l'app
threading.Timer(1.5, open_browser).start()

if __name__ == '__main__':
    socketio.run(app, debug=True)# Utilise HTTP en mode développement

