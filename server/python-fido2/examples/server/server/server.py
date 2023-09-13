# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Example demo server to use a supported web browser to call the WebAuthn APIs
to register and use a credential.

See the file README.adoc in this directory for details.

Navigate to https://localhost:5000 in a supported web browser.
"""

from base64 import urlsafe_b64encode, urlsafe_b64decode
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.server import Fido2Server
from flask import Flask, session, request, redirect, abort, jsonify

import os
import random
import fido2.features
import json
import base64
import asn1
import pem
import math 
import time
from asn1crypto.core import Sequence
from pyasn1.codec.ber import decoder as pyasn1decoder
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID,ObjectIdentifier
from .SoftwareAuthenticator import SoftWebauthnDevice
from cryptography.hazmat.primitives.asymmetric import ec

fido2.features.webauthn_json_mapping.enabled = True


app = Flask(__name__, static_url_path="")
app.secret_key = os.urandom(32)  # Used for session.

# rpid = "localhost"
# origin = "https://localhost"
rpid = "fido-delegation-demo.eastus.cloudapp.azure.com"
origin = "https://fido-delegation-demo.eastus.cloudapp.azure.com"
rp = PublicKeyCredentialRpEntity(name="Demo server", id=rpid)
server = Fido2Server(rp)

# Registered credentials are stored globally, in memory only. Single user
# support, state is lost when the server terminates.
credentials = []
credentials_userprofile = {}


@app.route("/")
def index():
    return redirect("/index.html")


# authenticator_attachment="cross-platform",
@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    user_handle = b"uid"
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=user_handle,
            name="a_user",
            display_name="A. User",
        ),
        credentials,
        user_verification="discouraged",
        authenticator_attachment="platform",
    )

    session["state"] = state
    print("\n\n\n\n")
    print(options)
    print("\n\n\n\n")

    return jsonify(dict(options))


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    response = request.json
    print("RegistrationResponse:", response)
    auth_data = server.register_complete(session["state"], response)

    credentials.append(auth_data.credential_data)
    new_profile = {"userName": "User " + str(len(credentials)),"balance": random.randint(0,10000)}
    credentials_userprofile[response["id"]] = new_profile
    print("REGISTERED CREDENTIAL:", auth_data.credential_data)
    return jsonify({"status": "OK","profile":new_profile})


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    if not credentials:
        abort(404)

    options, state = server.authenticate_begin(credentials)
    session["state"] = state

    return jsonify(dict(options))


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    if not credentials:
        abort(404)
        
    print("Authentication Check Answer for Challenge")
    response = request.json
    print("AuthenticationResponse:", response)
    server.authenticate_complete(
        session.pop("state"),
        credentials,
        response,
    )
    print("ASSERTION OK")
    return jsonify({"status": "OK", "user":credentials_userprofile[(response["id"])] })
    # return jsonify({"status": "OK", "user":credentials_userprofile[urlsafe_b64decode(response["id"]).encode("ascii")] })

@app.route("/api/records", methods=["GET"])
def getcred():
    return jsonify(credentials_userprofile)


@app.route("/api/delegatedpresig", methods=["GET"])
def getpresig():
    virtual_token = SoftWebauthnDevice()
    c = app.test_client()
    regbegin_response = c.post('/api/register/begin')
    rjson = json.loads(regbegin_response.data)
    print("Reg Begin from Server:", rjson, "\n")
    reg_reply = virtual_token.create(rjson, origin)
 
    print("Replying Reg From Token: ", reg_reply)
    regcomplete_response = c.post('/api/register/complete', data=json.dumps(reg_reply), content_type = "application/json" )
    complete_json = json.loads(regcomplete_response.data)
    print(complete_json)
    print("\n")
 
    # Only to compute the message strucutre, challenge is compute at the actual time of authentication.
    authbegin_response = c.post('/api/authenticate/begin')
    ajson = json.loads(authbegin_response.data)
    # print("attestation",request.args.get('attestation'))
    # print("Attestation:", (request.args.get('attestation')))
    is_valid_att, targetpk, nusecount = verify_attestation(json.loads(request.args.get('attestation'))["att"])
    if not is_valid_att:
        return jsonify("NONE")
    targetpk = [targetpk]*nusecount
    capability = virtual_token.get_delegated_signing_capability_wordbased(ajson, origin, targetpk, int(256/nusecount) ) if nusecount!=256 else virtual_token.get_delegated_signing_capability(ajson, origin, targetpk)

    combinedreply = {**complete_json["profile"], **capability}

    # return jsonify(complete_json["profile"] | auth_reply)
    return jsonify(combinedreply)


def verify_attestation(att):
    cert_arr = []
    cert_raw_arr =[]
    for cert_b64 in att:
        cert_raw = base64.urlsafe_b64decode(cert_b64)
        temp_cert = x509.load_der_x509_certificate(cert_raw)
        cert_arr.append(temp_cert)
        cert_raw_arr.append(cert_raw)

    is_valid_chain = True
    for i in reversed(range(len(cert_arr))):
        if i==0:
            break
        signer_cert = cert_arr[i]
        issued_cert = cert_arr[i-1]
        try:
            # This method verifies that the certificate issuer name matches the issuer subject name and that the certificate is signed by the issuer’s private key. Note missing checking cert validity date or revocation list if exist
            is_signed_by = issued_cert.verify_directly_issued_by(signer_cert)
        except:
            is_valid_chain= False
            break
    has_valid_root_cert = False
    root_cert_raw_bytes= cert_raw_arr[-1]
    filename = "/home/azureuser/python-fido2/examples/server/server/rootcert.pem"
    cert_obj = pem.parse_file(filename)
    for co in cert_obj:
        rootcert = x509.load_pem_x509_certificate(co.as_bytes())     
        if root_cert_raw_bytes == rootcert.public_bytes(Encoding.DER):
            has_valid_root_cert = True
            break
    has_valid_property = False
    # See https://cs.android.com/android/platform/superproject/+/master:prebuilts/vndk/v30/arm/include/generated-headers/hardware/interfaces/keymaster/4.1/android.hardware.keymaster@4.1_genc++_headers/gen/android/hardware/keymaster/4.1/IKeymasterDevice.h?q=1.3.6.1.4.1.11129.2.1.17&ss=android%2Fplatform%2Fsuperproject
    # Check Limited N-times usage is present, exact verification depends on trust/threat model and compactability requirement
    # The check below is not complete, IE security level, and key use count should be checked according to the correct upperbound imposed by the actual functional requirement.
    # The check below is only done for convenient of benchmarking across different configurations.
    oid_string = '1.3.6.1.4.1.11129.2.1.17'
    extension_obj = cert_arr[0].extensions.get_extension_for_oid(ObjectIdentifier(oid_string))
    extension_data = extension_obj.value.value
    seq = Sequence.load(extension_data)
    asn1_sequence_obj = seq[7]
    decoder = asn1.Decoder()
    decoder.start(asn1_sequence_obj._contents)
    tag, value = decoder.read()
    keycount = 0
    while tag != None:
        if tag.nr == 405:
            value, _ = pyasn1decoder.decode(value)
            if value == 1 or value==256 or value==32:
                keycount = value 
                has_valid_property =True
        read_result = decoder.read()
        if read_result!=None:
            tag, value = read_result
        else: 
            tag=None
            value = None
    asn1_sequence_obj = seq[6]
    decoder = asn1.Decoder()
    decoder.start(asn1_sequence_obj._contents)
    tag, value = decoder.read()
    while tag != None:
        if tag.nr == 405:
            value, _ = pyasn1decoder.decode(value)
            if value == 256 or value==1 or value==32:
                keycount = value
                has_valid_property =True
        read_result = decoder.read()
        if read_result!=None:
            tag, value = read_result
        else: 
            tag=None
            value = None
    # Extract PK 
    pk = cert_arr[0].public_key()

    print("Verified:", is_valid_chain and has_valid_root_cert and has_valid_property)
    return (is_valid_chain and has_valid_root_cert and has_valid_property, pk, int(keycount) )


def run_server():
    app.run(ssl_context="adhoc", debug=False)

@app.route("/api/benchmarkdelegate", methods=["GET"])
def benchmark_delegation():
    # Create a software authenticator, register then authenticate
    num_iter  = 100
    exe_time = []

    # Registration
    virtual_token = SoftWebauthnDevice()
    c = app.test_client()
    regbegin_response = c.post('/api/register/begin')
    rjson = json.loads(regbegin_response.data)
    print("Reg Begin from Server:", rjson, "\n")
    reg_reply = virtual_token.create(rjson, origin)
 
    print("Replying Reg From Token: ", reg_reply)
    regcomplete_response = c.post('/api/register/complete', data=json.dumps(reg_reply), content_type = "application/json" )
    complete_json = json.loads(regcomplete_response.data)
    print(complete_json)
    print("\n")
 
    # Only to compute the message strucutre, challenge is compute at the actual time of authentication.
    authbegin_response = c.post('/api/authenticate/begin')
    ajson = json.loads(authbegin_response.data)
    for _ in range(num_iter):
        start = time.time()
        is_valid_att, targetpk, nusecount = verify_attestation(json.loads(request.args.get('attestation'))["att"])
        if not is_valid_att:
            return jsonify("NONE")
        targetpk = [targetpk]*nusecount
        capability = virtual_token.get_delegated_signing_capability_wordbased(ajson, origin, targetpk, int(256/nusecount) ) if nusecount!=256 else virtual_token.get_delegated_signing_capability(ajson, origin, targetpk)
        exe_time.append( time.time() - start)
    avg_execution_time = sum(exe_time) / num_iter
    variance = sum((x - avg_execution_time) ** 2 for x in exe_time) / (num_iter)
    std_deviation = math.sqrt(variance)
    print(f"Avg: {avg_execution_time:.6f} seconds")
    print(f"Std: {std_deviation:.6f} seconds")

    combinedreply = {**complete_json["profile"], **capability}

    return jsonify(combinedreply)

def main():
    print(__doc__)
    # benchmark_delegation()
    app.run(host='0.0.0.0', port=5000, ssl_context=("/home/azureuser/fullchain.pem","/home/azureuser/privkey.pem"), debug=False)
