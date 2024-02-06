from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

# Connexion à la base de données SQLite (crée le fichier db si inexistant)
conn = sqlite3.connect('user_database.db', check_same_thread=False)
cursor = conn.cursor()

# Création de la table si elle n'existe pas
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')
conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Vérification des informations d'identification
    cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = cursor.fetchone()

    if user:
        return "Connexion réussie."
    else:
        return "Échec de la connexion. Vérifiez votre nom d'utilisateur et votre mot de passe."

@app.route('/create_account')
def create_account():
    return render_template('create_account.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    confirm = request.form['confirm']

    # Vérifie si le nom d'utilisateur existe déjà
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        # return "Le nom d'utilisateur existe déjà. Choisissez un autre nom d'utilisateur."
        return render_template('create_account.html', err = 'utilisateur existe déjà')
    elif password != confirm:
        # return "Les deux mots de passe doivent etre identique."
        return render_template('create_account.html', err = 'Les deux mots de passe doivent etre identique')
    else:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        return "Compte créé avec succès."

if __name__ == '__main__':
    app.run(debug=True)
