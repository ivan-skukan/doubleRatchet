#!/usr/bin/env python3

import cryptography
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import pickle
import base64
from dataclasses import dataclass, field
import os

from cryptography.hazmat.primitives.asymmetric import ec

def gov_decrypt(gov_priv, message):

    header, ciphertext = message
    gov_pub = header.gov_pub
    gov_iv = header.gov_iv
    iv = header.iv

    k_M = gov_priv.exchange(ec.ECDH(), serialization.load_pem_public_key(gov_pub))
    k = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None, # maybe change
        info=None,
        backend=cryptography.hazmat.backends.default_backend()
    ).derive(k_M)

    aesgcm = AESGCM(k)
    mk = aesgcm.decrypt(gov_iv, header.gov_ct, None)

    plaintext = AESGCM(mk).decrypt(iv, ciphertext, None)

    return plaintext.decode()


# Možete se (ako želite) poslužiti sa sljedeće dvije strukture podataka
@dataclass
class Connection:
    dhs        : ec.EllipticCurvePrivateKey # Diffie-Hellman private key
    dhr        : ec.EllipticCurvePublicKey # Diffie-Hellman public key
    rk         : bytes = None # root key
    cks        : bytes = None # chain key sending
    ckr        : bytes = None # chain key receiving
    pn         : int = 0 # previous message number
    ns         : int = 0 # number of messages sent
    nr         : int = 0 # number of messages received
    mk_skipped : dict = field(default_factory=dict) # skipped message keys

@dataclass
class Header:
    rat_pub : bytes # ratchet public key
    iv      : bytes # initialization vector
    gov_pub : bytes # gov public key?
    gov_iv  : bytes # initialization vector for gov_ct?
    gov_ct  : bytes # ciphertext?
    n       : int = 0 # message number
    pn      : int = 0 # previous message number

# Dopusteno je mijenjati sve osim sučelja.
class Messenger:
    """ Klasa koja implementira klijenta za čavrljanje
    """

    MAX_MSG_SKIP = 10

    def __init__(self, username, ca_pub_key, gov_pub):
        """ Inicijalizacija klijenta

        Argumenti:
            username (str)      --- ime klijenta
            ca_pub_key (class)  --- javni ključ od CA (certificate authority)
            gov_pub (class) --- javni ključ od vlade

        Returns: None
        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        self.gov_pub = gov_pub
        self.conns = {}

    def generate_certificate(self):

        ec_private_key = ec.generate_private_key(ec.SECP384R1())
        ec_public_key = ec_private_key.public_key()

        self.ec_private_key = ec_private_key # is this necessary?
        #if you have multiple connections, you need to store the private key for each connection?

        return {
            "username": self.username,
            "public_key": ec_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        }

        #raise NotImplementedError()

    def receive_certificate(self, cert_data, cert_sig):

        cert_data_bytes = pickle.dumps(cert_data)

        try:
            self.ca_pub_key.verify(
                cert_sig,
                cert_data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        except cryptography.exceptions.InvalidSignature:
            raise ValueError("Certificate verification failed")
        
        
        dhs = self.ec_private_key # check
        dhr = serialization.load_pem_public_key(
            cert_data["public_key"],
            backend=cryptography.hazmat.backends.default_backend()
        )

        shared_key = dhs.exchange(ec.ECDH(), dhr)

        rk = HKDF( # might not be necessary now, as long as we have the shared key
            algorithm=hashes.SHA256(),
            length=32,
            salt=None, # maybe change
            info=None,
            backend=cryptography.hazmat.backends.default_backend()
        ).derive(shared_key)
        """
        explanation:
        Shared Key Entropy Might Not Be Uniform: The shared key g^xy may 
        not have the required uniform randomness needed for cryptographic 
        purposes. A key derivation function (KDF) like HKDF extracts and 
        expands the shared key into something suitable.

        Context Binding: The HKDF process allows incorporating additional 
        information, like a salt or context-specific info parameter. 
        This ensures the derived root key (rk) is tied to the specific session 
        or protocol.

        Forward Secrecy: Using HKDF ensures that even if the shared key is 
        compromised later, the derived key (rk) provides better security 
        by being cryptographically derived and distinct.
        """
 
        self.conns[cert_data["username"]] = Connection(
            dhr=dhr,
            dhs=dhs,
            rk=rk,
        )


    def send_message(self, username, message):

        conn = self.conns[username]

        if conn is None:
            raise ValueError("Connection not established")
            # according to docs, this shouldnt happen

        if conn.ns - conn.nr > self.MAX_MSG_SKIP:
            raise ValueError("Too many messages skipped")
            #this is just a placeholder idk how this will work yet
        
        # Diffie-Hellman ratchet
        new_dhs = ec.generate_private_key(ec.SECP384R1())
        shared_secret = new_dhs.exchange(ec.ECDH(), conn.dhr)

        #if conn.ns == 0: #not sure about this. we already performed DH exchange at certificate reception
        conn.rk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=cryptography.hazmat.backends.default_backend()
        ).derive(shared_secret)

        # Symmetric-key ratchet
        conn.cks = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=cryptography.hazmat.backends.default_backend()
        ).derive(conn.rk)

        # Message key
        mk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=cryptography.hazmat.backends.default_backend()
        ).derive(conn.cks)

        # Encrypt message
        iv = os.urandom(12)
        aesgcm = AESGCM(mk)
        ciphertext = aesgcm.encrypt(iv, message.encode(), None)

        # Encrypt message key
        eph_key = ec.generate_private_key(ec.SECP384R1())
        shared_secret_gov = eph_key.exchange(ec.ECDH(), self.gov_pub)
        k = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=cryptography.hazmat.backends.default_backend()
        ).derive(shared_secret_gov)
        
        gov_iv = os.urandom(12)

        y = AESGCM(k).encrypt(gov_iv, mk, None)

        

        gov_pub = eph_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        header = Header(
            rat_pub=new_dhs.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            iv=iv,
            gov_pub=gov_pub,
            gov_iv=gov_iv,
            gov_ct=y,
            n=conn.ns,
            pn=conn.pn
        )
        conn.ns += 1

        return (header, ciphertext)

    def receive_message(self, username, message):
        if self.conns[username] is None:
            raise ValueError("Connection not established")
        
        conn = self.conns[username]
        header, ciphertext = message
        
        if conn.nr - conn.ns > self.MAX_MSG_SKIP:
            raise ValueError("Too many messages skipped")
            #this is just a placeholder idk how this will work yet

        dhr = serialization.load_pem_public_key(
            header.rat_pub,
            backend=cryptography.hazmat.backends.default_backend()
        )

        shared_key = conn.dhs.exchange(ec.ECDH(), dhr)

        conn.rk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=cryptography.hazmat.backends.default_backend()
        ).derive(shared_key)

        conn.ckr = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=cryptography.hazmat.backends.default_backend()
        ).derive(conn.rk)

        conn.dhr = dhr

        mk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=cryptography.hazmat.backends.default_backend()
        ).derive(conn.ckr)

        plaintext = AESGCM(mk).decrypt(header.iv, ciphertext, None)

        conn.nr += 1

        return plaintext.decode()



        

