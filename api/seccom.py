import seccom, datetime, secrets, binascii, os
from cryptography import x509
from Cryptodome.Cipher import PKCS1_OAEP
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC

RANGE_LIMIT_LOW: int = 0
RSA_VALUE_KEY_PUBLIC_EXPONENT: int = 65537
RSA_VALUE_KEY_SIZE: int = 2048
RSA_VALUE_PADDING_SIZE: int = 66 # 2 * 32 + 2
RSA_VALUE_CONSTANT: int = 8
RSA_VALUE_OAEP_LABEL: str or None = None
RSA_VALUE_AOD: str or None = b'seccomAOD'
RSA_VALUE_PASSWORD: str or None = None
X509_VALUE_COUNTRY: str = "DE"
X509_VALUE_STATE_PROVINCE: str = ""
X509_VALUE_LOCALITY: str = ""
X509_VALUE_ORGANIZATION: str = ""
X509_VALUE_COMMON: str = "0.0.0.0"
X509_VALUE_ALTERNATIVE: str = "127.0.0.1"
X509_VALUE_PATH_LENGTH: int or None = None
X509_VALUE_CA_TRUE: bool = True
X509_VALUE_CA_FALSE: bool = False
X509_VALUE_CRITICAL_TRUE: bool = True
X509_VALUE_CRITICAL_FALSE: bool = False
X509_VALUE_DURATION_DAYS: int = 365
DIGEST_LENGTH: int = 32
DIGEST_SALT: str or None = None
DIGEST_INFO: str or None = None
BYTES_RANDOM_SIZE: int = 16
DICT_KEY_SHARED_SECRET: str = 'sharedSecret'
DICT_KEY_PAYLOAD: str = 'payload'
DICT_KEY_CIPHERTEXT: str = 'ciphertext'
DICT_KEY_IV: str = 'iv'
JSON_KEY_SHARED_SECRET_DIGEST: str = 'digest'
JSON_RESPONSE_KEY_PKEC: str = 'key'
JSON_KEY_RSA_PUBLIC_KEY: str = 'key'
JSON_KEY_IV: str = 'iv'
BLOCK_SIZE_DECRYPTION: int = 256
BLOCK_SIZE_ENCRYPTION: int = 190
ENCODING_UTF8: str = 'utf-8'
FORMAT_PAM_FILE_END: str = '---\n'

class Seccom(object):


    def __init__(self):
        self.ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ec_public_key = self.ec_private_key.public_key()
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=RSA_VALUE_KEY_PUBLIC_EXPONENT,
            key_size=RSA_VALUE_KEY_SIZE,
            backend=default_backend()
        )
        self.subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, X509_VALUE_COUNTRY),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, X509_VALUE_STATE_PROVINCE),
            x509.NameAttribute(NameOID.LOCALITY_NAME, X509_VALUE_LOCALITY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, X509_VALUE_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, X509_VALUE_COMMON),
        ])
        self.cert  = (
            x509.CertificateBuilder()
            .subject_name(self.subject)
            .issuer_name(self.subject)
            .public_key(self.rsa_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=X509_VALUE_DURATION_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=X509_VALUE_CA_FALSE, path_length=X509_VALUE_PATH_LENGTH), critical=X509_VALUE_CRITICAL_TRUE,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(X509_VALUE_ALTERNATIVE)]), critical=X509_VALUE_CRITICAL_FALSE,
            )
            .sign(self.rsa_private_key, hashes.SHA256(), default_backend())
        )
        self.private_key_pem = self.rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.cert_pem = self.cert.public_bytes(encoding=serialization.Encoding.PEM)
        self.associated_data = RSA_VALUE_AOD
    
    def ecdh(self, peer_ec_hex: str) -> dict or False:
        serialized_ec_public_key_peer                           =   bytes.fromhex(peer_ec_hex)
        peer_ec_public_key                                      =   serialization.load_pem_public_key(
            serialized_ec_public_key_peer,
            backend                                             =   default_backend()
        )
        # Exchanging Key:
        shared_secret                                           =   self.ec_private_key.exchange(
            ec.ECDH(), peer_ec_public_key)
        # Digesting Key:
        shared_secret_digest                                    =   ConcatKDFHMAC(
            algorithm                                           =   hashes.SHA256(),
            length                                              =   DIGEST_LENGTH,
            salt                                                =   DIGEST_SALT,
            otherinfo                                           =   DIGEST_INFO,
            backend                                             =   default_backend()
        ).derive(shared_secret)
        self.ec_public_key_hex                                  =   self.ec_public_key.public_bytes(
            encoding                                            =   serialization.Encoding.PEM,
            format                                              =   serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        result                                                  =   {}
        result[DICT_KEY_SHARED_SECRET]                          =   shared_secret.hex()
        payload: dict                                           =   {}
        payload[str(JSON_KEY_SHARED_SECRET_DIGEST)]             =   shared_secret_digest.hex()
        payload[str(JSON_RESPONSE_KEY_PKEC)]                    =   self.ec_public_key_hex
        result[DICT_KEY_PAYLOAD]                                =   payload
        return result

    def rsa(self, encrypted_rsa_pk_peer: str, iv: str, shared_secret: str) -> dict:
        # A Symmetrically Decrypts Ciphertext with the Shared Secret as Key
        result: dict                                            =   {}
        decipher                                                =   Cipher(algorithms.AES(bytes.fromhex(shared_secret)),
                                                                    modes.CBC(bytes.fromhex(iv)), backend=default_backend())
        decryptor                                               =   decipher.decryptor()
        rsa_public_key_peer                                     =   decryptor.update(bytes.fromhex(encrypted_rsa_pk_peer))
        rsa_public_key_peer                                     =   (rsa_public_key_peer.decode(ENCODING_UTF8) + FORMAT_PAM_FILE_END).encode(ENCODING_UTF8)
        enc = self.encrypt(self.cert.public_bytes(
            encoding                                            =   serialization.Encoding.PEM
        ), rsa_public_key_peer, shared_secret)
        result['payload']                                       =   enc
        result['peerRsaCrt']                                    =   rsa_public_key_peer
        return result

    def encrypt(self, text: bytes, rsa_pk_peer_pam: bytes, shared_secret: str) -> dict:
        cert_peer                                               =   x509.load_pem_x509_certificate(rsa_pk_peer_pam, default_backend())
        nonce                                                   =   secrets.token_bytes(RSA_VALUE_PADDING_SIZE)
        chunk_size                                              =   (RSA_VALUE_KEY_SIZE // RSA_VALUE_CONSTANT) - RSA_VALUE_PADDING_SIZE
        chunks                                                  =   [text[i : i + chunk_size] for i in range(RANGE_LIMIT_LOW, len(text), chunk_size)]
        ciphertext_sym_blocks                                   =   []
        ciphertext_asym_blocks                                  =   []
        result                                                  =   {}
        sym_bytes                                               =   b''
        iv_new                                                  =   os.urandom(16)
        cipher_rsa                                              =   PKCS1_OAEP.new(key=cert_peer.public_key(), hashAlgo=hashes.SHA256())
        cipher_aes                                              =   Cipher(algorithms.AES(bytes.fromhex(shared_secret)),
                                                                    modes.CBC(iv_new), backend=default_backend())
        encryptor                                               =   cipher_aes.encryptor()
        # Asymmetric Encryption of Slized Blocks
        for block in chunks:
            ciphertext_asym_blocks.append(cert_peer.public_key().encrypt(block, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=self.associated_data
            )))
        # Symmetric Encryption of Slized Blocks
        for asym_block in ciphertext_asym_blocks:
            ciphertext = encryptor.update(asym_block)
            ciphertext_sym_blocks.append(ciphertext)
        # Byte Union
        for sym_block in ciphertext_sym_blocks:
            sym_bytes = sym_bytes + sym_block
        result[DICT_KEY_IV] = iv_new.hex()
        result[DICT_KEY_CIPHERTEXT] = sym_bytes.hex()
        return result
        
    def decrypt(self, cipherText: str, iv: str, shared_secret: str) -> str:
        cipherText_bytes = bytes.fromhex(cipherText)
        chunk_size = BLOCK_SIZE_DECRYPTION
        encrypted_sym_blocks = [cipherText_bytes[i : i + chunk_size] for i in range(RANGE_LIMIT_LOW, len(cipherText_bytes), chunk_size)]
        encrypted_asym_blocks = []
        plaintext_blocks = []
        plaintextDec = b''
        decipher_aes = Cipher(algorithms.AES(bytes.fromhex(shared_secret)),
                        modes.CBC(bytes.fromhex(iv)), backend=default_backend())
        decryptor = decipher_aes.decryptor()
        # Symmetrical Decryption
        for asym_block in encrypted_sym_blocks:
            ciphertext_asym = decryptor.update(asym_block)
            encrypted_asym_blocks.append(ciphertext_asym)
        serialized_rsa_private_key = self.rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Asymmetrical Decryption
        loaded_private_key = serialization.load_pem_private_key(
            serialized_rsa_private_key,
            password=RSA_VALUE_PASSWORD,
            backend=default_backend()
        )
        decipher_rsa = PKCS1_OAEP.new(key=loaded_private_key, hashAlgo=hashes.SHA256())
        for sym_block in encrypted_asym_blocks:
            plaintext_blocks.append(loaded_private_key.decrypt(sym_block, padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=self.associated_data))
            )
        # Reassembly
        for plaintext_block in plaintext_blocks:
            plaintextDec = plaintextDec + plaintext_block
        return plaintextDec
