#!/usr/bin/python3

import base64
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import oqs
import os
import requests
import subprocess
import sys
import traceback
import yaml
import time
import ThreeBears

loglevel = logging.DEBUG

logger = logging.getLogger(__name__)
logger.setLevel(loglevel)
console_log = logging.StreamHandler()
console_log.setLevel(logging.DEBUG)
logger.addHandler(console_log)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_log.setFormatter(formatter)

app_timestamp = 0

time_leeway = 60
ephem_alg = 'Kyber1024'
sigalg = 'SPHINCS+-SHAKE-128f-simple'
nonce_length = 12

ephem_kem = oqs.KeyEncapsulation(ephem_alg)
ephem_kem = ThreeBears.GrizzlyBear
ephem_kem = ThreeBears.Bear(d=6, variance=16.0 / 32, cca=False)

length_public_key = ephem_kem.details['length_public_key']
length_ciphertext = ephem_kem.details['length_ciphertext']

pqsig = oqs.Signature(sigalg)
length_signature = pqsig.details['length_signature']

x488_start = 8
x488_length = 56
x448_end = x488_start + x488_length
pq_end = x448_end + length_public_key
resp_end = x488_length + length_ciphertext


class HashalotException(Exception):
    pass


def genkey():
    pqsig = oqs.Signature(sigalg)
    sig_pub = pqsig.generate_keypair()
    sig_key = pqsig.export_secret_key()

    print('SecretKey: {}'.format(base64.b64encode(sig_key).decode()))
    print('PublicKey: {}'.format(base64.b64encode(sig_pub).decode()))


class PqKexServer(BaseHTTPRequestHandler):

    def log_request(self, *args, **kwargs):
        pass

    def log_message(self, format, *args, **kwargs):
        logger.debug(format, *args, **kwargs)

    def do_POST(self):
        global app_timestamp

        try:
            start_time = time.time()
            content_length = int(self.headers['Content-Length'])
            postdata = self.rfile.read(content_length)
            nonce = postdata[:nonce_length]
            postdata = local_aead.decrypt(postdata[nonce_length:],
                                          [b'', nonce])

            timestamp = int.from_bytes(postdata[:8], byteorder='big')
            if app_timestamp > timestamp or abs(time.time() - timestamp) > time_leeway:
                raise HashalotException(b'Illegal timestamp')
            app_timestamp = timestamp

            signature = postdata[pq_end:]
            if not remotesig.verify(postdata[:pq_end],
                                    signature, remote_sigkey):
                raise HashalotException(b'Signature check failed')

            xephem_pub = postdata[x488_start: x448_end]
            pqephem_pub = postdata[x448_end: pq_end]

            status, response = self.handle_data(xephem_pub, pqephem_pub)

            logger.debug('handle_data {:.3f} ms'.format((time.time() - start_time)
                                                        * 1000.0))
        except HashalotException as exc:
            status = 401
            response = exc.args[0]
        except Exception as exc:
            logger.warning('Exception "%s"', exc)
            status = 400
            response = b'Bad request'

        self.send_response(status)
        self.send_header('Content-type', 'application/octet-stream')
        self.end_headers()

        self.wfile.write(response)
        if status == 200:
            logger.debug('KEX "%s" %d %d -> %d', self.path,
                         status, content_length, len(response))
        else:
            logger.warning('ERR "%s" %d %s', self.path,
                           status, response.decode())

    def handle_data(self, xephem_pub, pqephem_pub):

        # rxephem_key = x448.X448PrivateKey.generate()
        rxephem_key = x448.X448PrivateKey.from_private_bytes(os.urandom(56))
        rxephem_pub = rxephem_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        xephem_key = x448.X448PublicKey.from_public_bytes(xephem_pub)
        xephem_secret = rxephem_key.exchange(xephem_key)

        ephem_ct, ephem_secret = ephem_kem.encap_secret(pqephem_pub)

        respdata = rxephem_pub + ephem_ct
        signature = localsig.sign(respdata)
        nonce = os.urandom(nonce_length)
        respdata = nonce + \
            local_aead.encrypt(respdata + signature, [b'', nonce])

        # Compose WG pre-shared secret
        wghash = hashlib.sha3_256(
            b'wgpsk' + ephem_secret + xephem_secret).digest()
        wghash = base64.b64encode(wghash).decode()

        temp_pskfile = '/tmp/wgtemps'
        with open(temp_pskfile, 'w') as wfile:
            wfile.write(wghash)

        result = subprocess.run(['wg', 'set', iface, 'peer', remote_id, 'preshared-key', temp_pskfile],
                                capture_output=True, text=True)
        os.remove(temp_pskfile)

        if result.returncode:
            logger.debug(result)
            logger.info('WG hash: ' + wghash)
        else:
            logger.info('PSK updated for ' + iface)

        return 200, respdata


def kex_request():
    timestamp = time.time()

    # Create crypto
    ephem_pq = ephem_kem.generate_keypair()

    # xephem_key = x448.X448PrivateKey.generate()
    xephem_key = x448.X448PrivateKey.from_private_bytes(os.urandom(56))
    xephem_pub = xephem_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Signature
    reqdata = int(timestamp).to_bytes(8, 'big') + xephem_pub + ephem_pq
    signature = localsig.sign(reqdata)
    nonce = os.urandom(nonce_length)
    reqdata = nonce + remote_aead.encrypt(reqdata + signature,  [b'', nonce])

    headers = {
        'Content-Type': 'application/octet-stream',
    }
    logger.debug('Prepare %.3f ms, %d bytes',
                 (time.time() - timestamp) * 1000.0,
                 len(reqdata))
    start_time = time.time()

    try:
        response = requests.post(remoteurl, data=reqdata, headers=headers)
    except requests.exceptions.ConnectionError:
        logger.error('Connection to {} refused'.format(remoteurl))
        return

    logger.debug('Remote {:.3f} ms'.format((time.time() - start_time)
                                           * 1000.0))
    start_time = time.time()

    if response.status_code != 200:
        logger.warning('request failed {}'.format(response.status_code))
        logger.debug(response.text)
        quit()

    logger.debug('  Req.: %d, Resp.: %d bytes',
                 len(reqdata), len(response.content))

    respdata = response.content
    nonce = respdata[:nonce_length]
    respdata = remote_aead.decrypt(respdata[nonce_length:], [b'', nonce])

    signature = respdata[resp_end:]
    if not remotesig.verify(respdata[:resp_end],
                            signature, remote_sigkey):
        logger.warning('Illegal response signature')
        quit()

    rxephem_pub = respdata[:x488_length]
    ephem_ct = respdata[x488_length: resp_end]
    rxpublic_key = x448.X448PublicKey.from_public_bytes(rxephem_pub)
    xephem_secret = xephem_key.exchange(rxpublic_key)
    ephem_secret = ephem_kem.decap_secret(ephem_ct)

    wghash = hashlib.sha3_256(b'wgpsk' + ephem_secret + xephem_secret).digest()
    wghash = base64.b64encode(wghash).decode()

    logger.debug('Crypto {:.3f} ms'.format(
        (time.time() - start_time) * 1000.0))
    start_time = time.time()

    temp_pskfile = '/tmp/wgtempc'
    with open(temp_pskfile, 'w') as wfile:
        wfile.write(wghash)

    result = subprocess.run(['wg', 'set', iface, 'peer', remote_id, 'preshared-key', temp_pskfile],
                            capture_output=True, text=True)
    os.remove(temp_pskfile)

    if result.returncode:
        logger.debug(result)
        logger.info('WG hash: ' + wghash)
    else:
        logger.info('PSK updated for ' + iface)

    logger.debug('Finished {:.3f} ms'.format((time.time() - start_time)
                                             * 1000.0))
    logger.debug('Total KEX time {:.3f} ms'.format((time.time() - timestamp)
                                                   * 1000.0))


if len(sys.argv) < 2:
    command = os.path.basename(sys.argv[0])
    print('Usage:', command, '<config>.yaml')
    print('      ', command, 'genkey')
    quit()

if sys.argv[1] == 'genkey':
    genkey()
    quit()

try:
    start_time = time.time()

    yamldata = yaml.safe_load(open(sys.argv[1]))
    iface = yamldata['Iface']
    local_id = yamldata['WireguardId']
    remote_id = yamldata['RemoteWireguardId']

    local_sigkey = base64.b64decode(yamldata['SecretKey'])
    localsig = oqs.Signature(sigalg, local_sigkey)
    remote_sigkey = base64.b64decode(yamldata['RemotePublicKey'])
    remotesig = oqs.Signature(sigalg)

    local_aead = AESSIV(base64.b64decode(local_id + '=='))
    remote_aead = AESSIV(base64.b64decode(remote_id + '=='))

    serverPort = yamldata.get('Port')
    remoteurl = yamldata.get('RemoteURL')

    logger.debug('Loaded %s in %.3f ms', sys.argv[1],
                 (time.time() - start_time) * 1000.0)

    if serverPort:
        webServer = HTTPServer(('0.0.0.0', serverPort), PqKexServer)
        logger.info('Server started at port {}'.format(serverPort))

        try:
            webServer.serve_forever()
        except KeyboardInterrupt:
            pass

        webServer.server_close()
        logger.info('Server stopped.')
    else:
        kex_request()

except Exception as exc:
    logger.error('Exception: {}'.format(exc.__class__.__name__))
    logger.error(exc)
    logger.debug(traceback.format_exc())
