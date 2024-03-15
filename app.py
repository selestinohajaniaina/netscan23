# import des dependances
from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import psutil
import nmap
import subprocess
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

def get_netbios_name(ip):
    try:
        result = subprocess.check_output(['nmap', '-sU', '--script', 'nbstat.nse', '-p', '137', ip], text=True)
        for line in result.splitlines():
            if "NetBIOS name:" in line:
                print('line', result)
                return line.split("NetBIOS name:")[1].split(",")[0].strip()
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'exécution de nmap pour NetBIOS: {e}")
    return None

# get info pc by ip
def get_detailed_info(ip):
    nm = nmap.PortScanner()
    print("ici le ", nm.__dict__)
    try:
        nm.scan(ip, arguments='-O -sV')  # Assurez-vous que ce scan a les droits nécessaires pour récupérer l'adresse MAC
        print(f"Scan réussi pour {ip}")
    except nmap.PortScannerError as e:
        print(f"Erreur avec nmap : {e}")
        return {'osmatch': {'name': '', 'accuracy': '0', 'line': '0', 'osclass': [{'type': '', 'vendor': 'none', 'osfamily': 'none', 'osgen': None, 'accuracy': '0', 'cpe': []}]}, 'uptime': {'seconds': '00', 'lastboot': 'none'}, 'open_ports': [{'port': 0, 'name': 'none', 'product': 'none'}], 'mac_address': 'none'}
    except Exception as e:
        print(f"Erreur inattendue : {e}")
        return {'osmatch': {'name': '', 'accuracy': '0', 'line': '0', 'osclass': [{'type': '', 'vendor': 'none', 'osfamily': 'none', 'osgen': None, 'accuracy': '0', 'cpe': []}]}, 'uptime': {'seconds': '00', 'lastboot': 'none'}, 'open_ports': [{'port': 0, 'name': 'none', 'product': 'none'}], 'mac_address': 'none'}

    device_info = {'osmatch': {'name': '', 'accuracy': '0', 'line': '0', 'osclass': [{'type': '', 'vendor': 'none', 'osfamily': 'none', 'osgen': None, 'accuracy': '0', 'cpe': []}]}, 'uptime': {'seconds': '00', 'lastboot': 'none'}, 'open_ports': [{'port': 0, 'name': 'none', 'product': 'none'}], 'mac_address': 'none'}

    try:
        if 'osmatch' in nm[ip] and nm[ip]['osmatch']:
            print('ici ip', nm[ip])
            device_info['osmatch'] = nm[ip]['osmatch'][0]
            device_info['uptime'] = nm[ip]['uptime']

        for proto in nm[ip].all_protocols():
            lport = list(nm[ip][proto].keys())
            for port in lport:
                service_info = nm[ip][proto][port]
                device_info['open_ports'].append({
                    'port': port,
                    'name': service_info.get('name', ''),
                    'product': service_info.get('product', '')
                })

        # Tentez de récupérer l'adresse MAC
        if 'mac' in nm[ip]['addresses']:  # Vérifiez si l'information 'mac' est présente
            device_info['mac_address'] = nm[ip]['addresses']['mac']
    except KeyError:
        print(f"Erreur lors de la tentative d'obtention des détails pour {ip}. Cela peut indiquer que l'hôte est down ou ne répond pas aux scans.")
    device_name = get_netbios_name(ip)
    if device_name:
        device_info['device_name'] = device_name

    return device_info


@app.route('/get_info/<ip>', methods=['GET'])
def get_info(ip):
    detailed_info = get_detailed_info(ip)
    print('info ', detailed_info)
    return render_template('detailed_info.html', detailed_info=detailed_info, ip=ip)

if __name__ == '__main__':
    app.run(debug=True)