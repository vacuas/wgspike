#!/usr/bin/python3

import base64
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives import serialization
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import oqs
import os
import requests
import subprocess
import sys
import yaml
import time

loglevel = logging.INFO
loglevel = logging.DEBUG

logger = logging.getLogger(__name__)
logger.setLevel(loglevel)
console_log = logging.StreamHandler()
console_log.setLevel(logging.DEBUG)
logger.addHandler(console_log)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_log.setFormatter(formatter)

app_timestamp = 0


def genkey():
    if len(sys.argv) == 2:
        print('Enabled KEM mechanisms:')
        for kemalg in oqs.get_enabled_KEM_mechanisms():
            with oqs.KeyEncapsulation(kemalg) as client:
                print(
                    client.details.get('claimed_nist_level'),
                    client.details.get('name'),
                    client.details.get('length_public_key'),
                    client.details.get('length_ciphertext'),
                )
        print('\nEnabled Signature mechanisms:')
        for sigalg in oqs.get_enabled_sig_mechanisms():
            with oqs.Signature(sigalg) as client:
                print(
                    client.details.get('claimed_nist_level'),
                    client.details.get('name'),
                    client.details.get('length_public_key'),
                    client.details.get('length_signature'),
                )
        quit()

    pubdict = {}
    privdict = {}

    kemalg = sys.argv[2]
    if kemalg != '-':
        pqkem = oqs.KeyEncapsulation(kemalg)

        kem_pub = base64.b64encode(pqkem.generate_keypair()).decode()
        kem_key = base64.b64encode(pqkem.export_secret_key()).decode()

        pubdict['KemAlg'] = kemalg
        pubdict['KemPublicKey'] = kem_pub
        privdict['KemAlg'] = kemalg
        privdict['KemPrivateKey'] = kem_key

    xprivate_key = x448.X448PrivateKey.generate()
    xpublic_key = xprivate_key.public_key()

    xpublic_keyb = xpublic_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    xprivate_keyb = xprivate_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pubdict['XPublicKey'] = base64.b64encode(xpublic_keyb).decode()
    privdict['XPrivateKey'] = base64.b64encode(xprivate_keyb).decode()

    if len(sys.argv) > 3:
        sigalg = sys.argv[3]
        pqsig = oqs.Signature(sigalg)

        sig_pub = base64.b64encode(pqsig.generate_keypair()).decode()
        sig_key = base64.b64encode(pqsig.export_secret_key()).decode()

        pubdict['SigAlg'] = sigalg
        pubdict['SigPublicKey'] = sig_pub
        privdict['SigAlg'] = sigalg
        privdict['SigPrivateKey'] = sig_key

    json.dump(pubdict, sys.stdout, indent=4)
    json.dump(privdict, sys.stderr, indent=4)

    quit()


class PqKexServer(BaseHTTPRequestHandler):

    def log_request(self, *args, **kwargs):
        pass

    def log_message(self, format, *args, **kwargs):
        logger.debug(format, *args, **kwargs)

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            gzpostdata = self.rfile.read(content_length)
            postdata = gzip.decompress(gzpostdata).decode()
            jsonrequest = json.loads(postdata)

            timestamp = jsonrequest.get('timestamp', 0)
            pq_recvct = base64.b64decode(jsonrequest.get('pq_recvct', ''))
            ephem_alg = jsonrequest.get('pqephem_alg', '')
            ephem_pk = base64.b64decode(jsonrequest.get('pqephem_pub', ''))
            xephem_pubb = base64.b64decode(jsonrequest.get('xephem_pub', ''))
            signature = base64.b64decode(jsonrequest.get('pq_signature', ''))

            req_len = 8 + len(pq_recvct) + len(ephem_alg) + \
                len(ephem_pk) + len(xephem_pubb) + len(signature)

            start_time = time.time()
            status, pq_initct, ephem_ct, rxephem_pubb, checkhash = self.handle_json(timestamp,
                                                                                    pq_recvct, ephem_alg, ephem_pk, xephem_pubb, signature)

            jsonresponse = {
                'pq_initct': base64.b64encode(pq_initct).decode(),
                'ephem_ct': base64.b64encode(ephem_ct).decode(),
                'rxephem_pub': base64.b64encode(rxephem_pubb).decode(),
                'wgpskhash': base64.b64encode(checkhash).decode(),
            }

            resp_len = len(pq_initct) + len(ephem_ct) + len(rxephem_pubb) + len(checkhash)

            logger.debug('handle_json {:.3f} ms'.format((time.time() - start_time)
                                                        * 1000.0))
        except Exception as exc:
            logger.warning('Exception "%s"', exc)
            status = 400
            jsonresponse = {'error': 'Bad request'}

        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-Encoding', 'gzip')
        self.end_headers()

        jsondata = json.dumps(jsonresponse)
        gzdata = gzip.compress(bytes(jsondata, 'utf-8'))
        self.wfile.write(gzdata)
        if status == 200:
            logger.debug('KEX "%s" %d %s (%s) -> %s (%s)', self.path,
                         status, content_length, req_len, len(gzdata), resp_len)
        else:
            logger.warning('ERR "%s" %d %s', self.path,
                           status, jsonresponse.get('error', '-'))

    def handle_json(self, timestamp, pq_recvct, ephem_alg, ephem_pk, xephem_pubb, signature):
        global app_timestamp

        if not remotesig:
            raise Exception('Remote signature missing')
        time_leeway = 60
        if app_timestamp > timestamp or abs(time.time() - timestamp) > time_leeway:
            return (400, {'error': 'Illegal timestamp'})

        app_timestamp = timestamp

        xephem_key = x448.X448PublicKey.from_public_bytes(xephem_pubb)

        if localkem:
            shared_secret_1 = localkem.decap_secret(pq_recvct)
        else:
            shared_secret_1 = b''
        xshared_secret = xprivate_key.exchange(xpublic_key)

        # Hash for signature validation
        msghash = '{}'.format(timestamp).encode() + ephem_pk + shared_secret_1 \
            + xshared_secret + xephem_pubb + b'pq_signature'

        # verify signature. Confirms requestor identity
        is_valid = remotesig.verify(msghash, signature, remote_sigkey)

        if not is_valid:
            return (403, {'error': 'Signature check failed'})

        # Build response
        if remotekem:
            pq_initct, shared_secret_2 = remotekem.encap_secret(
                remote_public_key)
        else:
            pq_initct = b''
            shared_secret_2 = b''

        ephem_kem = oqs.KeyEncapsulation(ephem_alg)
        ephem_ct, ephem_secret = ephem_kem.encap_secret(ephem_pk)

        rxephem_key = x448.X448PrivateKey.generate()
        rxephem_pub = rxephem_key.public_key()
        rxephem_pubb = rxephem_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        xephem_key = x448.X448PublicKey.from_public_bytes(xephem_pubb)
        xephem_secret = rxephem_key.exchange(xephem_key)

        # Hash for checking (acts like a signature on initiator KEM)
        chasher = hashlib.sha3_256()
        chasher.update(b'wgpskhash')
        chasher.update(xephem_secret)
        chasher.update(ephem_secret)
        chasher.update(xshared_secret)
        chasher.update(shared_secret_2)
        chasher.update(shared_secret_1)
        checkhash = chasher.digest()
        if localsig:
            checkhash = localsig.sign(checkhash)

        # Compose WG pre-shared secret
        hasher = hashlib.sha3_256()
        hasher.update(b'wgpsk')
        hasher.update(shared_secret_1)
        hasher.update(shared_secret_2)
        hasher.update(xshared_secret)
        hasher.update(ephem_secret)
        hasher.update(xephem_secret)
        wghash = hasher.digest()
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

        return 200, pq_initct, ephem_ct, rxephem_pubb, checkhash


def kex_request(yamldata):
    if not localsig:
        raise Exception('Local signature missing')

    timestamp = time.time()

    remote = yamldata['RemoteURL']
    ephem_alg = yamldata['EphemAlg']

    # Create crypto

    if remotekem:
        ciphertext, shared_secret_1 = remotekem.encap_secret(remote_public_key)
    else:
        ciphertext = b''
        shared_secret_1 = b''
    ephem_kem = oqs.KeyEncapsulation(ephem_alg)
    ephem_pk = ephem_kem.generate_keypair()

    xshared_secret = xprivate_key.exchange(xpublic_key)

    xephem_key = x448.X448PrivateKey.generate()
    xephem_pub = xephem_key.public_key()
    xephem_pubb = xephem_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Signature
    msghash = '{}'.format(timestamp).encode() + ephem_pk + shared_secret_1 \
        + xshared_secret + xephem_pubb + b'pq_signature'
    signature = localsig.sign(msghash)

    jsonrequest = {
        'timestamp': timestamp,
        'xephem_pub': base64.b64encode(xephem_pubb).decode(),
        'pqephem_alg': ephem_alg,
        'pqephem_pub': base64.b64encode(ephem_pk).decode(),
        'pq_recvct': base64.b64encode(ciphertext).decode(),
        'pq_signature': base64.b64encode(signature).decode(),
    }

    headers = {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip',
    }
    data = json.dumps(jsonrequest)
    gzdata = gzip.compress(data.encode())
    logger.debug('Prepare {:.3f} ms'.format((time.time() - timestamp)
                                            * 1000.0))

    start_time = time.time()

    try:
        response = requests.post(remote, data=gzdata, headers=headers)
    except requests.exceptions.ConnectionError:
        logger.error('Connection to {} refused'.format(remote))
        return

    logger.debug('Remote {:.3f} ms'.format((time.time() - start_time)
                                           * 1000.0))
    start_time = time.time()

    if response.status_code != 200:
        logger.warning('request failed {}'.format(response.status_code))
        logger.debug(response.text)
        quit()

    logger.debug('  Req.: {} gz-bytes, Resp.: {} bytes'.format(len(gzdata),
                                                               len(response.text)))

    jsonresponse = response.json()
    ciphertext = base64.b64decode(jsonresponse.get('pq_initct', ''))
    ephem_ct = base64.b64decode(jsonresponse.get('ephem_ct', ''))
    r_checkhash = base64.b64decode(jsonresponse.get('wgpskhash', ''))
    rxephem_pubb = base64.b64decode(jsonresponse.get('rxephem_pub', ''))

    rxpublic_key = x448.X448PublicKey.from_public_bytes(rxephem_pubb)
    xephem_secret = xephem_key.exchange(rxpublic_key)

    if localkem:
        shared_secret_2 = localkem.decap_secret(ciphertext)
    else:
        shared_secret_2 = b''
    ephem_secret = ephem_kem.decap_secret(ephem_ct)

    chasher = hashlib.sha3_256()
    chasher.update(b'wgpskhash')
    chasher.update(xephem_secret)
    chasher.update(ephem_secret)
    chasher.update(xshared_secret)
    chasher.update(shared_secret_2)
    chasher.update(shared_secret_1)
    checkhash = chasher.digest()

    if remotesig:
        if not remotesig.verify(checkhash, r_checkhash, remote_sigkey):
            logger.warning('Illegal response signature')
            logger.info(checkhash[:20] + '...')
            logger.info(r_checkhash[:20] + '...')
            quit()
    else:
        if checkhash != r_checkhash:
            logger.warning('Hash check failed')
            logger.info(checkhash)
            logger.info(r_checkhash)
            quit()

    hasher = hashlib.sha3_256()
    hasher.update(b'wgpsk')
    hasher.update(shared_secret_1)
    hasher.update(shared_secret_2)
    hasher.update(xshared_secret)
    hasher.update(ephem_secret)
    hasher.update(xephem_secret)
    wghash = hasher.digest()
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
    print('      ', command, 'genkey {<kex-alg>,-} [<sig-alg>]')
    quit()

if sys.argv[1] == 'genkey':
    genkey()

try:
    logger.debug('Config from: {} '.format(sys.argv[1]))
    start_time = time.time()

    yamldata = yaml.safe_load(open(sys.argv[1]))
    serverPort = yamldata.get('Port')
    iface = yamldata['Iface']

    localyaml = json.load(open(yamldata['PrivateKeyfile']))
    local_kemalg = localyaml.get('KemAlg')
    if local_kemalg:
        secret_key = base64.b64decode(localyaml['KemPrivateKey'])
        localkem = oqs.KeyEncapsulation(local_kemalg, secret_key)
    else:
        localkem = None
    local_sigalg = localyaml.get('SigAlg')
    if local_sigalg:
        local_sigkey = base64.b64decode(localyaml['SigPrivateKey'])
        localsig = oqs.Signature(local_sigalg, local_sigkey)
    else:
        localsig = None

    if not localsig and not localkem:
        raise Exception('Illegal local config')

    xprivate_bytes = base64.b64decode(localyaml['XPrivateKey'])
    xprivate_key = x448.X448PrivateKey.from_private_bytes(xprivate_bytes)

    remote_id = yamldata['RemoteWgId']
    remoteyaml = json.load(open(yamldata['RemoteKeyfile']))
    remote_kemalg = remoteyaml.get('KemAlg')
    if remote_kemalg:
        remote_public_key = base64.b64decode(remoteyaml['KemPublicKey'])
        remotekem = oqs.KeyEncapsulation(remote_kemalg)
    else:
        remotekem = None
    remote_sigalg = remoteyaml.get('SigAlg')
    if remote_sigalg:
        remote_sigkey = base64.b64decode(remoteyaml['SigPublicKey'])
        remotesig = oqs.Signature(remote_sigalg)
    else:
        remotesig = None

    if not remotesig and not remotekem:
        raise Exception('Illegal remote config')

    xpublic_bytes = base64.b64decode(remoteyaml['XPublicKey'])
    xpublic_key = x448.X448PublicKey.from_public_bytes(xpublic_bytes)

    logger.debug('Local: {} / {}, Remote: {} / {}'.format(local_kemalg, local_sigalg,
                                                          remote_kemalg, remote_sigalg))
    logger.debug('Load config {:.3f} ms'.format((time.time() - start_time)
                                                * 1000.0))

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
        kex_request(yamldata)

except Exception as exc:
    logger.error('Exception: {}'.format(exc.__class__.__name__))
    logger.error(exc)
