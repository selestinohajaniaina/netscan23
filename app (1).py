# import des dependances
from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import psutil
import nmap
import os
import subprocess
from pc import PC

my_pc = PC(os)

# Assurez-vous que nmap est installé et correctement configuré sur votre système.
# Le chemin pour nmap peut varier selon votre installation.
nmap_path = 'C:\\Program Files (x86)\\Nmap'
if nmap_path not in os.environ['PATH']:
    os.environ['PATH'] += os.pathsep + nmap_path

app = Flask(__name__)

# Initialisation de la connexion à la base de données dans une fonction pour éviter les problèmes de thread.
def get_db_connection():
    conn = sqlite3.connect('user_database.db')
    return conn


def get_detailed_info(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-O -sV')  # Assurez-vous que ce scan a les droits nécessaires pour récupérer l'adresse MAC
        print(f"Scan réussi pour {ip}")
    except nmap.PortScannerError as e:
        print(f"Erreur avec nmap : {e}")
        return {'os': 'Erreur avec nmap', 'open_ports': [], 'mac_address': 'Non disponible'}
    except Exception as e:
        print(f"Erreur inattendue : {e}")
        return {'os': 'Erreur inattendue', 'open_ports': [], 'mac_address': 'Non disponible'}

    device_info = {'os': '', 'open_ports': [], 'mac_address': 'Non disponible'}

    try:
        if 'osmatch' in nm[ip] and nm[ip]['osmatch']:
            device_info['os'] = nm[ip]['osmatch'][0]['name']

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




def get_netbios_name(ip):
    try:
        result = subprocess.check_output(['nmap', '-sU', '--script', 'nbstat.nse', '-p', '137', ip], text=True)
        for line in result.splitlines():
            if "NetBIOS name:" in line:
                return line.split("NetBIOS name:")[1].split(",")[0].strip()
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'exécution de nmap pour NetBIOS: {e}")
    return None








@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return redirect(url_for('home'))
    else:
        return render_template('index.html', err='Authentification incorrecte.')

@app.route('/create_account')
def create_account():
    return render_template('create_account.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    confirm = request.form['confirm']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        return render_template('create_account.html', err='Utilisateur existe déjà.')
    elif password != confirm:
        return render_template('create_account.html', err='Les deux mots de passe doivent être identiques.')
    else:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        return render_template('index.html', err='Compte créé avec succès. Veuillez vous connecter.')

@app.route('/home')
def home():
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

    formatted_data = []
    for interface, addresses in network_interfaces.items():
        info = {'interface': interface, 'addresses': []}
        for address in addresses:
            info['addresses'].append({'family': address.family, 'address': address.address})
        formatted_data.append(info)

    return render_template('home.html', data=formatted_data, propriete=prop)

@app.route('/scan', methods=['POST'])
def scan():
    ip_subnet = request.form['ip']  # Exemple d'entrée utilisateur: 192.168.1.0/24
    scan_results = perform_scan(ip_subnet)
    return render_template('results.html', scan_results=scan_results)

# Assurez-vous que perform_scan est défini
def perform_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments='-sn')  # -sn pour le ping scan
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    return hosts_list


@app.route('/get_info/<ip>', methods=['GET'])
def get_info(ip):
    detailed_info = get_detailed_info(ip)
    return render_template('detailed_info.html', detailed_info=detailed_info, ip=ip)

if __name__ == '__main__':
    app.run(debug=True)


