#!/usr/bin/env python3

import json
import requests
import os
import base64
from argparse import ArgumentParser
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def report_error(error):
    print(
        "[-] Status: {}\n[-] Message: {}\n".format(
            error['status'],
            error['message']
        )
    )

def main():
    parser = ArgumentParser()
    parser.add_argument('host_address', help = 'The host address of the server')

    args = parser.parse_args()
    host_address = args.host_address

    print('[*] Getting Public Key\n')
    response = requests.request(
        'GET',
        "{}/get-public-key".format(host_address)
    )

    print('[*] Received Public Key\n')
    content = json.loads(response.content)

    if response.status_code != 200:
        report_error(content)
        return

    if 'key' not in content:
        print("[!] Message: Cannot find public key\n")
        return

    public_key_string = content['key']
    shared_key = base64.b64encode(get_random_bytes(24)).decode('utf-8')
    iv = base64.b64encode(get_random_bytes(10)).decode('utf-8')

    public_key = RSA.importKey(public_key_string)
    cipher = PKCS1_OAEP.new(public_key)

    message = json.dumps({'key': shared_key, 'iv': iv}).encode('utf-8')
    encrypted_message = base64.b64encode(
        cipher.encrypt(message)
    ).decode('utf-8')

    print('[*] Sending request to get status\n')
    response = requests.request(
        'POST',
        "{}/port/status".format(host_address),
        data = { 'data': encrypted_message }
    )

    print('[*] Received response from getting status\n')
    if response.status_code != 200:
        report_error(json.loads(response.content))
        return

    cipher = AES.new(
        shared_key.encode(),
        AES.MODE_CBC,
        iv = iv.encode()
    )

    decoded_content = json.loads(
        unpad(
            cipher.decrypt(base64.b64decode(response.content)),
            AES.block_size
        )
    )

    print('\n=======================================================\n')
    print(
        "[+] Port: {}\n[+] Status: {}\n[+] Last Updated: {}\n".format(
            decoded_content['port'],
            decoded_content['status'],
            decoded_content['lastUpdated']
        )
    )

if __name__ == "__main__":
    main()
