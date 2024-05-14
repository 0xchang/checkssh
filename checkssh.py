import platform
import sys
import time
import os
import subprocess
import logging
import threading
from datetime import datetime, timedelta

logging.basicConfig(filename='banip.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

console = logging.StreamHandler()
console.setLevel(logging.INFO)

logging.getLogger('').addHandler(console)

current_system = platform.system()

if current_system == "Linux":
    print('Start detecting SSH login status, every 30 seconds.')
else:
    print('This program currently only supports Linux systems.')
    sys.exit(0)

if os.getuid() != 0:
    print('The current user is not a root user and cannot execute the script.')

result = subprocess.run(["grep", "-E", "^Port", "/etc/ssh/sshd_config"], stdout=subprocess.PIPE)
port = result.stdout.decode("utf-8").strip()
if port == '':
    port = '22'
else:
    port = port.split()[-1]

result = subprocess.run(["which", "iptables"], stdout=subprocess.PIPE)

if result.returncode == 0:
    print("iptables command is available.")
else:
    print("iptables command is not available.")
    print('Please install iptables.')
    sys.exit(0)

print('server start...')


def unbanip(ip, port):
    current_time = datetime.now()
    two_hours_later = current_time + timedelta(hours=2)
    print('IP {} will be unblocked at {}'.format(ip, two_hours_later))
    time.sleep(3600 * 2)
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--dport", port, "-j", "DROP"],
            stdout=subprocess.PIPE)
        if result.returncode == 0:
            logging.info(
                'Successfully unblocked IP {}'.format(ip))
        else:
            logging.error('Failed unblocked IP {}'.format(ip))
    except Exception as e:
        print(e)


while True:
    check = dict()
    result = subprocess.run(["lastb"], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8").strip()
    output = output.split('\n')
    for o in output:
        if len(o.split()) != 10:
            continue
        ip = o.split()[2]
        if check.get(ip) is None:
            check[ip] = 1
        else:
            check[ip] = check.get(ip) + 1
    for ip, count in check.items():
        thread = threading.Thread(target=unbanip, args=(ip, port))
        thread.start()
        if count > 10:
            result = subprocess.run(["iptables-save"], stdout=subprocess.PIPE)
            output = result.stdout.decode("utf-8").strip()
            if ip not in output:
                result = subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", port, "-j", "DROP"],
                    stdout=subprocess.PIPE)
                if result.returncode == 0:
                    logging.info(
                        'Successfully added {} to prohibit access to the {} port firewall rule.'.format(ip, port))
                else:
                    logging.error('Failed added {} to prohibit access to the {} port firewall rule.'.format(ip, port))
    time.sleep(30)
