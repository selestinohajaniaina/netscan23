# import des dependances
from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import psutil
import nmap
import nmap3
import os
from pc import PC

my_pc = PC(os)
# print(my_pc.release())

def perform_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments='-sn')  # -sn pour le ping scan
    hosts_list = [(x, nm[x]['status']['state'], nm[x]['status']['reason'], nm[x]['hostnames']) for x in nm.all_hosts()]
    return hosts_list


# recherche d'emplacement d'installation du nmap
# le chemin est seulment pour windows
nmap_path = 'C:\\Program Files (x86)\\Nmap'

# si le chemin n'est pas exacte
if nmap_path not in os.environ['PATH']:
    os.environ['PATH'] += os.pathsep + nmap_path

# configurer premier (main) pour flask
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

# url est egal a '/'
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
        return '<script>document.location.href = "home"</script>'
    else:
        return render_template('index.html', err = 'Authentification incorrecte.')

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
        return render_template('index.html', err = 'Connectez-vous manuellemnet pour confirmer.')


@app.route('/home')
def home():
    print(os)
    # Obtenir la liste des cartes réseau
    network_interfaces = psutil.net_if_addrs()

    prop = {
        'uid': my_pc.uid(),
        'user': my_pc.user(),
        'system': my_pc.system(),
        'bit': my_pc.bit(),
        'version': my_pc.version(),
        'release': my_pc.release(),
        'dist': my_pc.dist()
        }
    # print(prop)

    # Formater les données pour l'affichage
    formatted_data = []
    for interface, addresses in network_interfaces.items():
        info = {'interface': interface, 'addresses': []}
        for address in addresses:
            info['addresses'].append({'family': address.family, 'address': address.address})
        formatted_data.append(info)

    return render_template('home.html', data=formatted_data, propriete=prop)

@app.route('/scan', methods=['POST'])
def scan():
    ip_subnet = request.form['ip']  # L'utilisateur doit entrer un sous-réseau, par exemple, 192.168.1.0/24
    scan_results = perform_scan(ip_subnet)
    return render_template('results.html', scan_results=scan_results)

if __name__ == '__main__':
    app.run(debug=True)
