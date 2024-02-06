from flask import Flask, render_template, request
import psutil
import nmap
import os
nmap_path = 'C:\\Program Files (x86)\\Nmap'
if nmap_path not in os.environ['PATH']:
    os.environ['PATH'] += os.pathsep + nmap_path

def perform_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments='-sn')  # -sn pour le ping scan
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    return hosts_list


app = Flask(__name__)

@app.route('/')
def index():
    # Obtenir la liste des cartes réseau
    network_interfaces = psutil.net_if_addrs()

    # Formater les données pour l'affichage
    formatted_data = []
    for interface, addresses in network_interfaces.items():
        info = {'interface': interface, 'addresses': []}
        for address in addresses:
            info['addresses'].append({'family': address.family, 'address': address.address})
        formatted_data.append(info)

    return render_template('index.html', data=formatted_data)
    
@app.route('/scan', methods=['POST'])
def scan():
    ip_subnet = request.form['ip']  # L'utilisateur doit entrer un sous-réseau, par exemple, 192.168.1.0/24
    scan_results = perform_scan(ip_subnet)
    return render_template('results.html', scan_results=scan_results)



@app.route('/get_info', methods=['POST'])
def get_info():
    ip = request.form['ip']
    # Ici, vous pouvez utiliser nmap ou une autre bibliothèque pour obtenir des informations sur l'appareil.
    # Par exemple, un scan nmap pour déterminer le système d'exploitation.
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O')  # -O pour OS detection
    try:
        os_info = nm[ip]['osclass'][0]['osfamily'] if 'osclass' in nm[ip] else "Inconnu"
        # Vous pouvez ajouter d'autres informations ici.
    except KeyError:
        os_info = "Information indisponible"

    return render_template('info.html', ip=ip, os_info=os_info)

# ... le reste de votre code ...


if __name__ == '__main__':
    app.run(debug=True)