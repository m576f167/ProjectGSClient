#!/usr/bin/env python3

import json
import requests
import subprocess
import time
from argparse import ArgumentParser

def main():
    parser = ArgumentParser()
    parser.add_argument('host_address', help = 'The host address of the server')
    parser.add_argument('secret', help = 'The secret for authorization')
    parser.add_argument('ssh_user', help = 'The user name for ssh')
    parser.add_argument('identity_file', help = 'The identity file for ssh')

    args = parser.parse_args()
    host_address = args.host_address
    secret = args.secret
    ssh_user = args.ssh_user
    identity_file = args.identity_file

    ngrok_process = subprocess.Popen(
        ['ngrok', 'start', '--all'],
        stdout = subprocess.PIPE
    )

    time.sleep(10)
    print('Ngrok started')

    while True:
        print('Running')

        if ngrok_process.poll() is not None:
            print('Ngrok restarted')
            ngrok_process = subprocess.Popen(
                ['ngrok', 'start', '--all'],
                stdout = subprocess.PIPE
            )

        ngrok_tunnels  = json.loads(
            requests.request('GET', 'http://localhost:4040/api/tunnels').content
        )['tunnels']
        print('Ngrok tunnels retrieved')

        ssh_tunnel = list(filter(lambda x: x['name'] == 'ssh', ngrok_tunnels))[0]
        (ssh_host, ssh_port) = ssh_tunnel['public_url'][6:].split(':')

        update_port_process = subprocess.Popen(
            [
                './update_status.py',
                host_address,
                "{}:{}".format(ssh_host, ssh_port),
                secret
            ],
            stdout = subprocess.PIPE
        )
        print('Port updated')

        ssh_ping_process = subprocess.Popen(
            [
                'ssh',
                '-p', ssh_port,
                '-i', identity_file,
                '-o', 'StrictHostKeyChecking=no',
                "{}@{}".format(ssh_user, ssh_host),
                'bash', '-c', 'sleep 1 & exit'
            ],
            stdout = subprocess.PIPE
        )
        print('SSH pinged')
        time.sleep(5)

if __name__ == '__main__':
    main()
