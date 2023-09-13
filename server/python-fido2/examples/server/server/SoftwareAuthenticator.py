"""
Module implementing software webauthn token for testing webauthn enabled
applications
"""

import json
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from struct import pack

from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecdsa      import ECDSA
import random
import hashlib
import numpy as np
from randomgen import ChaCha

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData
from fido2.utils import sha256

# DER Encoded Signature
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder
class ECDSASignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )

# Helper Functions
BIT_NUMBER = 256
def decompose_bits(number):
    bits = []
    while number > 0:
        bits.append(number & 1)
        number >>= 1
    return bits[::-1] if bits else [0]
def padto(arr):
    while (len(arr) < BIT_NUMBER ):
        arr = [0] + arr
    return arr
def commit_to_message(hiding_sign, hiding_sign_vec2,mbit_arr, order):
    # print("Commitng from %a" % hiding_sign)
    rolling_sum = 0
    for i in range(BIT_NUMBER):
        # hiding_sign[i] = hiding_sign[i] * mbit_arr[i]
        hiding_sign_cur = hiding_sign[i] * mbit_arr[i] + hiding_sign_vec2[i] * (int(not mbit_arr[i]))
        rolling_sum += (hiding_sign_cur) % order
    # print("Opened to Message Part * K_inverse %a" %hiding_sign)
    # Summing
    return rolling_sum


class SoftWebauthnDevice():
    """
    This simulates the Webauthn browser API with a authenticator device
    connected. It's primary use-case is testing, device can hold only
    one credential.
    """

    def __init__(self):
        self.credential_id = None
        self.private_key = None
        self.aaguid = b'\x00'*16
        self.rp_id = None
        self.user_handle = None
        self.sign_count = 0

    def cred_init(self, rp_id, user_handle):
        """initialize credential for rp_id under user_handle"""

        self.credential_id = os.urandom(32)
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.rp_id = rp_id
        self.user_handle = user_handle

    def cred_as_attested(self):
        """return current credential as AttestedCredentialData"""

        return AttestedCredentialData.create(
            self.aaguid,
            self.credential_id,
            ES256.from_cryptography_key(self.private_key.public_key()))

    def create(self, options, origin):
        """create credential and return PublicKeyCredential object aka attestation"""

        if {'alg': -7, 'type': 'public-key'} not in options['publicKey']['pubKeyCredParams']:
            raise ValueError('Requested pubKeyCredParams does not contain supported type')

        if ('attestation' in options['publicKey']) and (options['publicKey']['attestation'] not in [None, 'none']):
            raise ValueError('Only none attestation supported')

        # prepare new key
        self.cred_init(options['publicKey']['rp']['id'], options['publicKey']['user']['id'])

        # generate credential response
        # client_data = {
        #     'type': 'webauthn.create',
        #     'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
        #     'origin': origin
        # }
        # Challenge is already b64_url encoded
        client_data = {
            'type': 'webauthn.create',
            'challenge': options['publicKey']['challenge'],
            'origin': origin
        }

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x41'  # attested_data + user_present
        sign_count = pack('>I', self.sign_count)
        credential_id_length = pack('>H', len(self.credential_id))
        cose_key = cbor.encode(ES256.from_cryptography_key(self.private_key.public_key()))
        attestation_object = {
            'authData':
                rp_id_hash + flags + sign_count
                + self.aaguid + credential_id_length + self.credential_id + cose_key,
            'fmt': 'none',
            'attStmt': {}
        }

        # Decode all bytes data (JSON compatible) to str
        return {
            'id': urlsafe_b64encode(self.credential_id).decode("ascii"),
            'rawId': urlsafe_b64encode(self.credential_id).decode("ascii"),
            'response': {
                'clientDataJSON': urlsafe_b64encode(json.dumps(client_data).encode('utf-8')).decode("ascii"),
                'attestationObject': urlsafe_b64encode(cbor.encode(attestation_object)).decode("ascii")
            },
            'type': 'public-key'
        }

    def get(self, options, origin):
        """get authentication credential aka assertion"""

        if self.rp_id != options['publicKey']['rpId']:
            raise ValueError('Requested rpID does not match current credential')

        # Devices that does not support siganture counter
        # self.sign_count += 1

        # prepare signature
        client_data = json.dumps({
            'type': 'webauthn.get',
            'challenge': options['publicKey']['challenge'],
            'origin': origin
        }).encode('utf-8')
        client_data_hash = sha256(client_data)

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x01'
        sign_count = pack('>I', self.sign_count)
        authenticator_data = rp_id_hash + flags + sign_count

        signature = self.private_key.sign(authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

        # generate assertion
        return {
            'id': urlsafe_b64encode(self.credential_id).decode("ascii"),
            'rawId': urlsafe_b64encode(self.credential_id).decode("ascii"),
            'response': {
                'authenticatorData': urlsafe_b64encode(authenticator_data).decode("ascii"),
                'clientDataJSON': urlsafe_b64encode(client_data).decode("ascii"),
                'signature': urlsafe_b64encode(signature).decode("ascii"),
                'userHandle': self.user_handle
            },
            'type': 'public-key'
        }
    
    def get_delegated_signing_capability(self,options,origin, targetpk):
        assert(self.private_key != None)
        rand = random.SystemRandom()

        csrng = np.random.Generator(ChaCha(seed=None, rounds=20)) #Use /dev/urandom if none

        """get authentication credential aka assertion, delegated"""
        if self.rp_id != options['publicKey']['rpId']:
            raise ValueError('Requested rpID does not match current credential')

        # Device does not support siganture counter
        # self.sign_count += 1

        # prepare delegated signature prefilled guiding inputs
        client_data = json.dumps({
            'type': 'webauthn.get',
            'challenge': options['publicKey']['challenge'],
            'origin': origin
        }).encode('utf-8')

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x01'
        sign_count = pack('>I', self.sign_count)
        authenticator_data = rp_id_hash + flags + sign_count

        # Generate Delegation
        sect = self.private_key.private_numbers().private_value
        cv = Curve.get_curve('secp256r1')
        order = cv.order
        G = cv.generator
        k = rand.randint(0,cv.order-1)
        k_inverse = pow(k,-1,order)
        R = k*G
        r = R.x
        part1 = (k_inverse * r * sect)
        hiding_sign = [0] * BIT_NUMBER
        hiding_sign_vec2 = [0] * BIT_NUMBER
        randomness_arr = [0] * (BIT_NUMBER)
        randomness_arr_sum = 0

        for i in range(BIT_NUMBER):
            randomness_arr[i] = rand.randint(0, cv.order-1) 
            randomness_arr_sum =  (randomness_arr_sum - randomness_arr[i]) % order
        for i in range(BIT_NUMBER):
            hiding_sign[i] = (pow(2,i) * k_inverse + randomness_arr[i] ) % order
            hiding_sign_vec2[i] = (randomness_arr[i]) % order
        part1 = (part1 + randomness_arr_sum)  % order


        # print(targetpk)
        key_derive = lambda finalsharedsec,localsec : sha256(finalsharedsec+localsec)
        xor_otp = lambda x,y: bytes(a^b for (a,b) in zip(x,y))
        flatten = lambda mat: [item for arr in mat for item in arr]

        allornot_1 = [0x00]*BIT_NUMBER
        allornot_0 = [0x00]*BIT_NUMBER
        final_sec = [0x00]*16 
        shared_splitsec = [[0x00] *16 ]*BIT_NUMBER
        epk = b""
        for i in range(BIT_NUMBER):
            shared_splitsec[i] = bytes([csrng.integers(0, 256) for _ in range(16)]) #rand.randbytes(16) #os.urandom(16)
            final_sec = xor_otp(final_sec,shared_splitsec[i])
        for i in range(BIT_NUMBER):
            private_key = ec.generate_private_key(
                ec.SECP256R1
            )
            shared_key = private_key.exchange(
                ec.ECDH(), targetpk[i])
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            allornot_1_localsec =  bytes([csrng.integers(0, 256) for _ in range(16)]) # rand.randbytes(16)
            allornot_1[i] = shared_splitsec[i] + allornot_1_localsec
            allornot_1[i] = xor_otp(shared_key,allornot_1[i]) #shared_key_1[i]

            private_key = ec.generate_private_key(
                ec.SECP256R1
            )
            shared_key = private_key.exchange(
                ec.ECDH(), targetpk[i])
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            allornot_0_localsec = bytes([csrng.integers(0, 256) for _ in range(16)]) # rand.randbytes(16)
            allornot_0[i] = shared_splitsec[i] + allornot_0_localsec
            allornot_0[i] = xor_otp(shared_key,allornot_0[i]) #shared_key_0[i]
            hiding_sign[i] = xor_otp(hiding_sign[i].to_bytes(32,'big'),key_derive(final_sec,allornot_1_localsec))  #vec1
            hiding_sign_vec2[i] = xor_otp(hiding_sign_vec2[i].to_bytes(32,'big'),key_derive(final_sec,allornot_0_localsec)) #vec0
        
        return {
            'serverepk': urlsafe_b64encode(epk).decode("ascii"),
            'allornot_1': urlsafe_b64encode( bytes(flatten(allornot_1)) ).decode("ascii"),
            'allornot_0': urlsafe_b64encode( bytes(flatten(allornot_0)) ).decode("ascii"),
            'credential_id': urlsafe_b64encode(self.credential_id).decode("ascii"),
            'authenticator_data': urlsafe_b64encode(authenticator_data).decode("ascii"),
            'client_data': urlsafe_b64encode(client_data).decode("ascii"),
            'user_handle': self.user_handle,
            'r' : r,
            'part1' : part1,
            'hiding_sign' : urlsafe_b64encode( bytes(flatten(hiding_sign)) ).decode("ascii") ,
            'hiding_sign_vec2' :  urlsafe_b64encode( bytes(flatten(hiding_sign_vec2)) ).decode("ascii") 
        } 
    
    # wordsize == Possible Values/Arrays Size
    def get_delegated_signing_capability_wordbased(self,options,origin, targetpk, wordsize):
        assert(self.private_key != None)
        rand = random.SystemRandom()
        csrng = np.random.Generator(ChaCha(seed=None, rounds=20)) #Use /dev/urandom if none
        """get authentication credential aka assertion, delegated"""
        if self.rp_id != options['publicKey']['rpId']:
            raise ValueError('Requested rpID does not match current credential')
        # Device does not support siganture counter
        # self.sign_count += 1
        # prepare delegated signature prefilled guiding inputs
        client_data = json.dumps({
            'type': 'webauthn.get',
            'challenge': options['publicKey']['challenge'],
            'origin': origin
        }).encode('utf-8')
        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x01'
        sign_count = pack('>I', self.sign_count)
        authenticator_data = rp_id_hash + flags + sign_count

        # Generate Delegation
        sect = self.private_key.private_numbers().private_value
        cv = Curve.get_curve('secp256r1')
        order = cv.order
        G = cv.generator
        k = rand.randint(0,cv.order-1)
        k_inverse = pow(k,-1,order)
        R = k*G
        r = R.x
        part1 = (k_inverse * r * sect)

        CHUNK_NUMBER = int(256/(wordsize))
        hiding_sign_arr = [0] * CHUNK_NUMBER
        randomness_arr = [0] * CHUNK_NUMBER
        randomness_arr_sum = 0

        for i in range(CHUNK_NUMBER):
            randomness_arr[i] = rand.randint(0, cv.order-1) 
            randomness_arr_sum =  (randomness_arr_sum - randomness_arr[i]) % order
        for i in range(CHUNK_NUMBER):
            hiding_sign_subarr = [0]*pow(2,wordsize)
            for j in range( pow(2,wordsize) ):
                hiding_sign_subarr[j]  = ( ( j * pow(2,wordsize*(i)) ) * k_inverse + randomness_arr[i] ) % order
            hiding_sign_arr[i] = hiding_sign_subarr
        part1 = (part1 + randomness_arr_sum)  % order

        # print(targetpk)
        key_derive = lambda finalsharedsec,localsec : sha256(finalsharedsec+localsec)
        xor_otp = lambda x,y: bytes(a^b for (a,b) in zip(x,y))
        flatten = lambda mat: [byte for arr in mat for item in arr for byte in item]

        allornot_arr = [0]*CHUNK_NUMBER
        final_sec = [0x00]*16 
        shared_splitsec = [[0x00] *16 ]*CHUNK_NUMBER
        epk = b""
        for i in range(CHUNK_NUMBER):
            shared_splitsec[i] = bytes([csrng.integers(0, 256) for _ in range(16)]) #rand.randbytes(16) #os.urandom(16)
            final_sec = xor_otp(final_sec,shared_splitsec[i])
        for i in range(CHUNK_NUMBER):
            allornot_subarr = [0]*pow(2,wordsize)
            for j in range(pow(2,wordsize)):
                private_key = ec.generate_private_key(
                    ec.SECP256R1
                )
                shared_key = private_key.exchange(
                    ec.ECDH(), targetpk[i])
                epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
                allornot_localsec =  bytes([csrng.integers(0, 256) for _ in range(16)]) # rand.randbytes(16)
                allornot_subarr[j] = shared_splitsec[i] + allornot_localsec
                allornot_subarr[j] = xor_otp(shared_key,allornot_subarr[j]) #shared_key_0[i]
                hiding_sign_arr[i][j] = xor_otp(hiding_sign_arr[i][j].to_bytes(32,'big'),key_derive(final_sec,allornot_localsec))
            allornot_arr[i] = allornot_subarr
        
        return {
            'serverepk': urlsafe_b64encode(epk).decode("ascii"),
            'allornot_0': urlsafe_b64encode( bytes(flatten(allornot_arr)) ).decode("ascii"),
            'allornot_1': "",
            'credential_id': urlsafe_b64encode(self.credential_id).decode("ascii"),
            'authenticator_data': urlsafe_b64encode(authenticator_data).decode("ascii"),
            'client_data': urlsafe_b64encode(client_data).decode("ascii"),
            'user_handle': self.user_handle,
            'r' : r,
            'part1' : part1,
            'hiding_sign' : urlsafe_b64encode( bytes(flatten(hiding_sign_arr)) ).decode("ascii") ,
            'hiding_sign_vec2' : ""
        } 

    