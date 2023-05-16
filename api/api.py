#!/bin/python3
#from PROPERTIES import *

from flask import Flask, request, make_response, Response, session
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_sslify import SSLify
from uvicorn import Server, Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from urllib.parse import quote
from asgiref.wsgi import WsgiToAsgi
import ssl
import subprocess
import logging
import random
import string
import uvicorn
import json
import hmac
import os
import secrets
from seccom import Seccom

PYTHON_LIFECYCLE_MAIN                           : str   = '__main__'
CSRF_SECRET                                     : str   = 'CSRF_SALT'
LOG_FORMAT                                      : str   = '%(asctime)s    :%(levelname)s    :%(message)s'
LOG_RESPONSE_JSON                               : str   = 'Generating response json.'
LOG_TLS_CONTEXT_CREATION_START                  : str   = 'Creating tls context.'
LOG_API_REQUEST_RSA_GET                         : str   = 'Api rsa get request.'
LOG_API_REQUEST_RSA_POST                        : str   = 'Api rsa post request.'
LOG_API_REQUEST_CREATION_CAM_BROKER_POST        : str   = 'API    : Post, Creating signed cam broker certificate.'
LOG_API_REQUEST_CREATION_CAM_CA_POST            : str   = 'API    : Post, Creating signed cam ca certificate.'
LOG_API_REQUEST_CREATION_CAM_CA_GET             : str   = 'API    : Get, Creating signed cam ca certificate.'
LOG_API_REQUEST_CREATION_API_CLIENT_POST        : str   = 'API    : Post, Creating signed api client certificate.'
LOG_API_REQUEST_CREATION_API_BROKER_POST        : str   = 'API    : Post, Creating signed api broker certificate.'
LOG_API_REQUEST_CREATION_API_CA_POST            : str   = 'API    : Post, Creating signed api ca certificate.'
LOG_API_REQUEST_CREATION_API_CA_GET             : str   = 'API    : Get, Issuing signed api ca certificate.'
LOG_API_REQUEST_DISTRIBUTION_CAM_POST           : str   = 'API    : Post, Creating signed cam client certificate.'
LOG_ISSUING_START                               : str   = 'Issuing signed certificate.'
LOG_SCRIPT_JAR_RUN_START                        : str   = 'Executing jar.'
LOG_ALS_RSA_PAIR_SERIALIZATION_START            : str   = 'Serializing rsa key pair.'
LOG_ALS_RSA_PAIR_CREATION_START                 : str   = 'Creating rsa key pair.'
LOG_ALS_KEYS_DISTRIBUTION                       : str   = 'Distributing als keys'
LOG_TLS_CONTEXT_CREATION_START                  : str   = 'Creating tls context.'
LOG_FILE_SERIALIZE                              : str   = 'Serializing file.'
ALS_KEY_PUBLIC                                  : str   = 'pubKey'
ALS_KEY_PRIVATE                                 : str   = 'privKey'
ALS_KEY_AES                                     : str   = 'aesKey'
API_IP_LOCAL                                    : str   = '0.0.0.0'
API_IP_PORT                                     : int   = 22432
PATH_HOME                                       : str   = '/home/brokerregistry/'
PATH_LOG                                        : str   = PATH_HOME + 'brokerRegistry.log'
PATH_CERTIFICATES                               : str   = PATH_HOME + 'certificates/'
PATH_DISTRIBUTION_JAR                           : str   = '/home/brokerregistry/bin/certdistributor.jar'
PATH_DISTRIBUTION_CA                            : str   = '/home/brokerregistry/bin/issueNewCaCrt.sh'
PATH_DISTRIBUTION_CRT                           : str   = '/home/brokerregistry/bin/issueSignedCrt.sh'
PATH_JAR_PROPERTIES                             : str   = '/home/brokerregistry/etc/properties.json'
PATH_JAR_ALS                                    : str   = '/home/brokerregistry/etc/als.json'
PATH_API_CRT                                    : str   = PATH_CERTIFICATES + 'api_crt.pem'
PATH_API_KEY                                    : str   = PATH_CERTIFICATES + 'api_key.pem'
PATH_API_DH                                     : str   = PATH_CERTIFICATES + 'api_dh_params.pem'
PATH_CAM_CA_CRT                                 : str   = PATH_CERTIFICATES + 'cam_ca_crt.pem'
PATH_CAM_CA_KEY                                 : str   = PATH_CERTIFICATES + 'cam_ca_key.pem'
PATH_CAM_BROKER_KEY                             : str   = '_cam_broker_key.pem'
PATH_CAM_BROKER_CRT                             : str   = '_cam_broker_crt.pem'
PATH_CAM_CLIENT_KEY                             : str   = '_cam_client_key.pem'
PATH_CAM_CLIENT_CRT                             : str   = '_cam_client_crt.pem'
PATH_API_CA_CRT                                 : str   = '/home/brokerregistry/certificates/api_ca_crt.pem'
PATH_API_CA_KEY                                 : str   = '/home/brokerregistry/certificates/api_ca_key.pem'
PATH_API_BROKER_KEY                             : str   = '_api_broker_key.pem'
PATH_API_BROKER_CRT                             : str   = '_api_broker_crt.pem'
PATH_API_CLIENT_KEY                             : str   = '_api_client_key.pem'
PATH_API_CLIENT_CRT                             : str   = '_api_client_crt.pem'
PATH_TOKEN_API                                  : str   = '/home/brokerregistry/token/api'
PATH_TOKEN_USER                                 : str   = '/home/brokerregistry/token/user'
PATH_TOKEN_CREATOR                              : str   = '/home/brokerregistry/token/creator'
HTTP_REQUEST_METHODE_POST                       : str   = 'POST'
HTTP_REQUEST_METHODE_GET                        : str   = 'GET'
HTTP_REQUEST_METHODE_DELETE                     : str   = 'DELETE'
HTTP_RESPONSE_CODE_200                          : int   = 200
HTTP_RESPONSE_CODE_400                          : int   = 400
HTTP_RESPONSE_CODE_503                          : int   = 503
PAYLOAD_KEY_REQUEST                             : str   = 'REQUEST'
PAYLOAD_VALUE_SUCCESSFULL                       : str   = 'SUCCESSFULL'
PAYLOAD_VALUE_FAILURE                           : str   = 'FAILED'
HEADER_RESPONSE_KEY_CONTENT_TYPE                : str   = 'Content-Type'
HEADER_RESPONSE_VALUE_APP_JSON                  : str   = 'application/json'
HEADER_REQUEST_VALUE_APP_JSON                   : str   = 'application/json'
COOKIE_VALUE_STRICT                             : str   = 'Strict'
COOKIE_VALUE_TRUE                               : bool  = True
URL_CERT_DISTRIBUTION_CAM                       : str   = '/distribution'
URL_CERT_CREATION_API_CA                        : str   = '/cert/api/ca'
URL_CERT_CREATION_API_BROKER                    : str   = '/cert/api/broker'
URL_CERT_CREATION_API_CLIENT                    : str   = '/cert/api/client'
URL_CERT_CREATION_CAM_CA                        : str   = '/cert/cam/ca'
URL_CERT_CREATION_CAM_BROKER                    : str   = '/cert/cam/broker'
URL_ALS_CREATION_KEYS                           : str   = '/als'
URL_API_HANDSHAKE                               : str   = '/handshake'
CMD_RUN_PARAMETER_BASH                          : str   = '/home/brokerregistry/bin/bash'
CMD_RUN_PARAMETER_JAVA                          : str   = '/home/brokerregistry/bin/java'
CMD_RUN_PARAMETER_JAR                           : str   = '-jar'
JSON_KEY_ECDH_PUBLIC                            : str   = 'ecdhPublic'
JSON_KEY_TOKEN_API                              : str   = 'apiToken'
JSON_KEY_TOKEN_USER                             : str   = 'userToken'
JSON_KEY_TOKEN_CREATOR                          : str   = 'creatorToken'
JSON_KEY_CHANNEL_NAME                           : str   = 'channelName'
JSON_KEY_RSA_PUBLIC_KEY                         : str   = 'key'
JSON_KEY_IV                                     : str   = 'iv'
JSON_RESPONSE_KEY_CA_CRT                        : str   = 'caCrt'
JSON_RESPONSE_KEY_CA_KEY                        : str   = 'caKey'
JSON_RESPONSE_KEY_ALS_PRIV                      : str   = 'alsPrivKey'
JSON_RESPONSE_KEY_ALS_PUB                       : str   = 'alsPubKey'
JSON_RESPONSE_KEY_ALS_AES                       : str   = 'alsAes'
TLS_CA_TYPE_CAM                                 : str   = 'cam'
TLS_CA_TYPE_API                                 : str   = 'api'
TLS_CRT_TYPE_CLIENT                             : str   = 'client'
TLS_CRT_TYPE_BROKER                             : str   = 'broker'
SESSION_KEY_ID                                  : str   = 'sessionId'
SESSION_KEY_CSRF                                : str   = 'X-CSRFToken'
SESSION_DATA_KEY_CSRF                           : str   = 'csrf_token'
CONTEXT_PASSWORD                                : str   = 'AWFuIITe2kOsPzEO15LFKT4DWAW6pB6zm16EmRgFWEJ6Cu2fZL'
CONTEXT_CRT                                     : str   = PATH_API_CRT
CONTEXT_KEY                                     : str   = PATH_API_KEY
CONTEXT_CA                                      : str   = PATH_API_CA_CRT
CONTEXT_CIPHERS                                 : str   = 'ECDHE-RSA-AES128-GCM-SHA256'
PERMISSION_FILE_OPEN_READ                       : str   = 'r'
INDEX_ARRAY_0                                   : int   = 0
INDEX_ARRAY_1                                   : int   = 1
INDEX_ARRAY_2                                   : int   = 2
EXIT_CODE_SUCCESS                               : int   = 0
IDENTIFIER_LENGTH                               : int   = 5
HTTP_RESPONSE_CODE_200                          : int   = 200
HTTP_RESPONSE_CODE_400                          : int   = 400
SUCCESS                                         : bool  = True
FAILURE                                         : bool  = False


class Service:

    logging.basicConfig(filename=PATH_LOG,
                        level=logging.DEBUG,
                        format=LOG_FORMAT)

    class validate:

        def token(file: str, token: str) -> bool:
            flag = FAILURE
            if isinstance(token, str) and token:
                with open(file, PERMISSION_FILE_OPEN_READ) as file:
                    for line in file:
                        if token == line:
                            flag = SUCCESS
            return flag

        def csrfToken(token: str, val: str) -> bool:
            return token == val

        def hex(hex: str) -> bool:
            return hex and len(hex) % 2 == 0
        
        def script(result: bool) -> bool:
            return result is not FAILURE

        def creation(file: str or bytes) -> bool:
            return (isinstance(file, str) or isinstance(file, bytes)) and file
        
        def als(als: dict or None):
            return (isinstance(als, dict) and als
            ) and (isinstance(als[ALS_KEY_PUBLIC], str) and als[ALS_KEY_PUBLIC]
            ) and (isinstance(als[ALS_KEY_PRIVATE], str) and als[ALS_KEY_PRIVATE]
            ) and (isinstance(als[ALS_KEY_PUBLIC], str) is str and als[ALS_KEY_AES])
    
    def response(payload: dict) -> Response:
        logging.info(LOG_RESPONSE_JSON)
        csrf                                                = secrets.token_bytes(20).hex() + generate_csrf(async_api.secret_key)
        session[str(SESSION_DATA_KEY_CSRF)]                 = csrf
        response                                            = make_response(json.dumps(payload))
        response.status_code                                = HTTP_RESPONSE_CODE_200
        response.set_cookie(SESSION_KEY_CSRF,
                            value                           = csrf,
                            secure                          = COOKIE_VALUE_TRUE,
                            httponly                        = COOKIE_VALUE_TRUE,
                            samesite                        = COOKIE_VALUE_STRICT)
        response.headers[HEADER_RESPONSE_KEY_CONTENT_TYPE]  = HEADER_RESPONSE_VALUE_APP_JSON
        return response

    def successResponse() -> Response:
        logging.info(LOG_RESPONSE_JSON)
        csrf                                                = secrets.token_bytes(20).hex() + generate_csrf(async_api.secret_key)
        session[str(SESSION_DATA_KEY_CSRF)]                 = csrf
        payload: dict                                       = {}
        payload[str(PAYLOAD_KEY_REQUEST)]                   = str(PAYLOAD_VALUE_SUCCESSFULL)
        response                                            = make_response(json.dumps(payload))
        response.status_code                                = HTTP_RESPONSE_CODE_200
        response.set_cookie(SESSION_KEY_CSRF,
                            value                           = csrf,
                            secure                          = COOKIE_VALUE_TRUE,
                            httponly                        = COOKIE_VALUE_TRUE,
                            samesite                        = COOKIE_VALUE_STRICT)
        response.headers[HEADER_RESPONSE_KEY_CONTENT_TYPE]  = HEADER_RESPONSE_VALUE_APP_JSON
        return response

    def failureResponse() -> Response:
        logging.info(LOG_RESPONSE_JSON)
        csrfToken                                           = secrets.token_bytes(20).hex() + generate_csrf(async_api.secret_key)
        payload: dict                                       = {}
        payload[str(PAYLOAD_KEY_REQUEST)]                   = str(PAYLOAD_VALUE_FAILURE)
        response                                            = make_response(json.dumps(payload))
        response.status_code                                = HTTP_RESPONSE_CODE_400
        response.set_cookie(SESSION_KEY_CSRF,
                            value                           = csrfToken,
                            secure                          = COOKIE_VALUE_TRUE,
                            httponly                        = COOKIE_VALUE_TRUE,
                            samesite                        = COOKIE_VALUE_STRICT)
        response.headers[HEADER_RESPONSE_KEY_CONTENT_TYPE]  = HEADER_RESPONSE_VALUE_APP_JSON
        return response

    def deserializeFile(path: str) -> str:
        logging.info(LOG_FILE_SERIALIZE)
        with open(path, PERMISSION_FILE_OPEN_READ) as file:
            file_contents = file.read()
        return file_contents

    def createAlsRsaKeyPair() -> bool:
        logging.info(LOG_ALS_RSA_PAIR_CREATION_START)
        return Service.successResponse()
        '''
        if not Service.validate.script(Service.runJarScript(PATH_ALS_RSA_CREATION_JAR, CMD_RUN_PARAMETER_JAR)):
            return SUCCESS
        else:
            return FAILURE
        '''
    
    def deserializeAlsRsaKeyPair() -> tuple or FAILURE:
        logging.info(LOG_ALS_RSA_PAIR_SERIALIZATION_START)
        als = dict(Service.deserializeFile(PATH_JAR_ALS))
        if Service.validate.als(als):
            return ( als[ALS_KEY_PUBLIC], als[ALS_KEY_PRIVATE], als[ALS_KEY_AES] )
        else:
            return FAILURE

    def runJarScript(identifier: str, channel_name: str) -> bool:
        #java -jar /path/to/myapp.jar
        logging.info(LOG_SCRIPT_JAR_RUN_START)
        if subprocess.run([ CMD_RUN_PARAMETER_JAVA,
                            CMD_RUN_PARAMETER_JAR,
                            PATH_DISTRIBUTION_JAR,
                            PATH_JAR_PROPERTIES,
                            PATH_JAR_ALS,
                            TLS_CA_TYPE_CAM,
                            TLS_CRT_TYPE_CLIENT,
                            identifier,
                            channel_name
                            ],
                            check=SUCCESS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == EXIT_CODE_SUCCESS:
            return SUCCESS
        else:
            return FAILURE

    def createId(length: int) -> str:
        letters     = string.ascii_lowercase
        result_str  = ''.join(random.choice(letters) for i in range(length))
        return result_str

    def issueNewCaCrt(caType: str) -> bool:
        logging.info(LOG_ISSUING_START)
        if caType == TLS_CA_TYPE_CAM:
            logging.info('cam')
            valKey: str     = PATH_CAM_CA_KEY
            valCrt: str     = PATH_CAM_CA_CRT
        elif caType == TLS_CA_TYPE_API:
            logging.info('api')
            valKey: str     = PATH_API_CA_KEY
            valCrt: str     = PATH_API_CA_CRT
        else:
            logging.info('general error 0')
            return FAILURE
        if subprocess.run([ CMD_RUN_PARAMETER_BASH,
                            PATH_DISTRIBUTION_CA,
                            caType],
                            check=SUCCESS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == EXIT_CODE_SUCCESS:
            logging.info('script 0')
            val: tuple = (  Service.deserializeFile(valCrt), Service.deserializeFile(valKey) )
            if Service.validate.creation(val[INDEX_ARRAY_0]
            ) and Service.validate.creation(val[INDEX_ARRAY_1]):
                logging.info('script validated')
                return SUCCESS
            else:
                logging.info('script not validated')
                return FAILURE
        else:
            logging.info('general error 1')
            return FAILURE

    def issueSignedCrt(caType: str, certType: str, identifier: str, keyPwd: str or None = None) -> bool:
        logging.info(LOG_ISSUING_START)
        if caType == TLS_CA_TYPE_CAM and certType == TLS_CRT_TYPE_CLIENT:
            valKey: str     = PATH_CERTIFICATES + identifier + PATH_CAM_CLIENT_KEY
            valCrt: str     = PATH_CERTIFICATES + identifier + PATH_CAM_CLIENT_CRT
        elif caType == TLS_CA_TYPE_CAM and certType == TLS_CRT_TYPE_BROKER:
            valKey: str     = PATH_CERTIFICATES + identifier + PATH_CAM_BROKER_KEY
            valCrt: str     = PATH_CERTIFICATES + identifier + PATH_CAM_BROKER_CRT
        elif caType == TLS_CA_TYPE_API and certType == TLS_CRT_TYPE_CLIENT:
            valKey: str     = PATH_CERTIFICATES + identifier + PATH_API_CLIENT_KEY
            valCrt: str     = PATH_CERTIFICATES + identifier + PATH_API_CLIENT_CRT
        elif caType == TLS_CA_TYPE_API and certType == TLS_CRT_TYPE_BROKER:
            valKey: str     = PATH_CERTIFICATES + identifier + PATH_API_BROKER_KEY
            valCrt: str     = PATH_CERTIFICATES + identifier + PATH_API_BROKER_CRT
        else:
            return FAILURE
        if keyPwd != None:
            if subprocess.run([ CMD_RUN_PARAMETER_BASH,
                                PATH_DISTRIBUTION_CRT,
                                caType,
                                certType,
                                identifier,
                                keyPwd],
                                check=SUCCESS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == EXIT_CODE_SUCCESS:
                val: tuple = ( Service.deserializeFile(valCrt), 
                                Service.deserializeFile(valKey) )
                if Service.validate.creation(val[INDEX_ARRAY_0]) and Service.validate.creation(val[INDEX_ARRAY_1]):
                    return SUCCESS
                else:
                    return FAILURE
            else:
                return FAILURE
        elif keyPwd == None:
            if subprocess.run([ CMD_RUN_PARAMETER_BASH,
                                PATH_DISTRIBUTION_CRT,
                                caType,
                                certType,
                                identifier],
                                check=SUCCESS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == EXIT_CODE_SUCCESS:
                val: tuple = ( Service.deserializeFile(valCrt),
                                Service.deserializeFile(valKey) )
                if Service.validate.creation(val[INDEX_ARRAY_0]) and Service.validate.creation(val[INDEX_ARRAY_1]):
                    return SUCCESS
                else:
                    return FAILURE
            else:
                return FAILURE
        else:
            return FAILURE
    
    def handleHttpCamDistributionPostRequest(identifier: str, channel_name: str):
        logging.info(LOG_API_REQUEST_DISTRIBUTION_CAM_POST)
        if Service.validate.script(Service.issueSignedCrt(  TLS_CA_TYPE_CAM,
                                                            TLS_CRT_TYPE_CLIENT,
                                                            identifier,
                                                            channel_name)):
            return Service.successResponse()                                                
            '''
            if Service.validate.script(Service.runJarScript(identifier, channel_name)):
                return Service.successResponse()
            else:
                print('jar')
                return Service.failureResponse()
            '''
        else:
            return Service.failureResponse()
    
    def handleHttpAlsPostRequest():
        logging.info(LOG_HTTP_POST_REQUEST)
        return Service.successResponse()

        '''
        if Service.validate.als(Service.createAlsRsaKeyPair()):
            return Service.successResponse()
        else:
            return Service.failureResponse()
        '''
    
    def handleHttpAlsGetRequest():
        logging.info(LOG_ALS_KEYS_DISTRIBUTION)
        return Service.successResponse()
        '''
        als = Service.deserializeAlsRsaKeyPair() 
        if Service.validate.als(als):
            payload: dict                               = {}
            payload[str(JSON_RESPONSE_KEY_ALS_PRIV)]    = str(als[INDEX_ARRAY_0])
            payload[str(JSON_RESPONSE_KEY_ALS_PUB)]     = str(als[INDEX_ARRAY_1])
            payload[str(JSON_RESPONSE_KEY_ALS_AES)]     = str(als[INDEX_ARRAY_2])
            return Service.response(payload, sessionId)
        else:
            return Service.failureResponse()
        '''
    
    def handleHttpCaCrtPostRequest(caType: str):
        logging.info(LOG_API_REQUEST_CREATION_API_CA_POST)
        if Service.validate.script(Service.issueNewCaCrt(caType)):
            return Service.successResponse()
        else:
            return Service.failureResponse()   

    def handleHttpCaCrtGetRequest(caCrt: str, caKey: str):
        logging.info(LOG_API_REQUEST_CREATION_API_CA_GET)
        crt_hex_string = hex(int.from_bytes(Service.deserializeFile(caCrt).encode(), 'big'))
        key_hex_string = hex(int.from_bytes(Service.deserializeFile(caKey).encode(), 'big'))
        payload: dict                               = {}
        payload[str(JSON_RESPONSE_KEY_CA_CRT)]      = seccom.encrypt(bytes.fromhex(crt_hex_string[2:]), bytes.fromhex(session.get('peerRsaCrt')), session.get('sharedSecret'))
        payload[str(JSON_RESPONSE_KEY_CA_KEY)]      = seccom.encrypt(bytes.fromhex(key_hex_string[2:]), bytes.fromhex(session.get('peerRsaCrt')), session.get('sharedSecret'))
        if payload[JSON_RESPONSE_KEY_CA_CRT]['ciphertext'] != None and payload[JSON_RESPONSE_KEY_CA_KEY]['ciphertext'] != None:
            return Service.response(payload)
        else:
            return Service.failureResponse()

    def handleHttpCrtPostRequest(identifier: str, caType: str, crtType: str, crt: str, key: str):
        logging.info(LOG_API_REQUEST_DISTRIBUTION_CAM_POST)
        if Service.validate.script(Service.issueSignedCrt(  caType,
                                                            crtType,
                                                            identifier,
                                                            None)):
            crt_hex_string = hex(int.from_bytes(Service.deserializeFile(PATH_CERTIFICATES + identifier + crt).encode(), 'big'))
            key_hex_string = hex(int.from_bytes(Service.deserializeFile(PATH_CERTIFICATES + identifier + key).encode(), 'big'))
            payload: dict                               = {}
            payload[str(JSON_RESPONSE_KEY_CA_CRT)]      = seccom.encrypt(bytes.fromhex(crt_hex_string[2:]), bytes.fromhex(session.get('peerRsaCrt')), session.get('sharedSecret'))
            payload[str(JSON_RESPONSE_KEY_CA_KEY)]      = seccom.encrypt(bytes.fromhex(key_hex_string[2:]), bytes.fromhex(session.get('peerRsaCrt')), session.get('sharedSecret'))
            if payload[JSON_RESPONSE_KEY_CA_CRT]['ciphertext'] != None and payload[JSON_RESPONSE_KEY_CA_KEY]['ciphertext'] != None:
                return Service.response(payload)
            else:
                return Service.failureResponse()
        else:
            return Service.failureResponse()

    def main():
        logging.info('starting api application.')
        try:
            logging.info('running uvicorn.')
            uvicorn.run('api:async_api_asgi',
                        host=API_IP_LOCAL,
                        port=API_IP_PORT,
                        ssl_keyfile=CONTEXT_KEY,
                        ssl_certfile=CONTEXT_CRT,
                        ssl_keyfile_password=CONTEXT_PASSWORD,
                        ssl_version=ssl.PROTOCOL_TLSv1_2,
                        ssl_ca_certs=CONTEXT_CA,
                        ssl_ciphers=CONTEXT_CIPHERS,
                        lifespan='off',
                        workers=1,
                        interface='asgi3',
                        loop='auto')
            logging.info('looping.')
        except Exception as e:
            logging.info('exception thrown.')
            logging.info(e)
        finally:
            logging.info('finally exitting python api.')

async_api = Flask(__name__)
async_api.config['SESSION_COOKIE_NAME'] = 'sessionId'
async_api.config['SESSION_TYPE'] = 'filesystem'
async_api.config['SESSION_FILE_DIR'] = '/home/brokerregistry/tmp/flask_session'
async_api.config['SESSION_COOKIE_SECURE'] = True
async_api.config['SESSION_COOKIE_HTTPONLY'] = True
async_api.secret_key = CSRF_SECRET
sslify = SSLify(app=async_api, permanent=True, subdomains=True)
csrf = CSRFProtect(async_api)
Session(async_api)
seccom = Seccom()

@async_api.route('/', subdomain='<subdomain>')
@csrf.exempt
def default_route(subdomain):
    payload: dict                                       = {}
    payload[str(PAYLOAD_KEY_REQUEST)]                   = str(PAYLOAD_VALUE_FAILURE)
    response                                            = make_response(json.dumps(payload))
    response.response_code                              = HTTP_RESPONSE_CODE_503
    response.headers[HEADER_RESPONSE_KEY_CONTENT_TYPE]  = HEADER_RESPONSE_VALUE_APP_JSON
    return response

@async_api.route(URL_API_HANDSHAKE, methods=[HTTP_REQUEST_METHODE_POST])
@csrf.exempt
def ecdhExchange() -> Response:
    api_token               = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    ec_public_key_peer_hex  = quote(str(request.get_json().get(JSON_KEY_ECDH_PUBLIC)))

    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.hex(ec_public_key_peer_hex
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    elif request.content_type == HEADER_REQUEST_VALUE_APP_JSON:
        result: dict                                 = seccom.ecdh(ec_public_key_peer_hex)
        session['sharedSecret'] = result['sharedSecret']
        return Service.response(result['payload'])
    else:
        return Service.failureResponse()

@async_api.route(URL_API_HANDSHAKE, methods=[HTTP_REQUEST_METHODE_GET])
def rsaExchange() -> Response:
    _csrf_token             = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token               = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    encrypted_rsa_pk_peer   = quote(str(request.get_json().get(JSON_KEY_RSA_PUBLIC_KEY)))
    iv                      = quote(str(request.get_json().get(JSON_KEY_IV)))

    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.hex(encrypted_rsa_pk_peer
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    elif request.content_type == HEADER_REQUEST_VALUE_APP_JSON:
        result: dict = seccom.rsa(encrypted_rsa_pk_peer, iv, session.get('sharedSecret'))      
        session['peerRsaCrt'] = result['peerRsaCrt'].hex()                 
        payload: dict = result['payload']                      
        return Service.response(payload)
    else:
        return Service.failureResponse()

@async_api.route(URL_API_HANDSHAKE, methods=[HTTP_REQUEST_METHODE_DELETE])
@csrf.exempt
def deauthenticate() -> Response:
    logging.info('deauth start')
    try:
        _csrf_token             = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
        api_token               = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
        user_token              = quote(str(request.get_json().get(JSON_KEY_TOKEN_USER)))
        if not Service.validate.token(PATH_TOKEN_API, api_token
        )   or not Service.validate.token(PATH_TOKEN_USER, user_token
        )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
        )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
            return Service.failureResponse()
        elif request.content_type == HEADER_REQUEST_VALUE_APP_JSON:
            logging.info('deauth forming response')
            payload: dict                           = {}
            payload[str(PAYLOAD_KEY_REQUEST)]       = str(PAYLOAD_VALUE_SUCCESSFULL)
            session.clear()
            response.delete_cookie(SESSION_KEY_ID)
            response.delete_cookie(SESSION_KEY_CSRF)
        else:
            return Service.failureResponse()
    except e:
        logging.info(e)
    finally:
        return 'de-authenticated'

@async_api.route(URL_CERT_DISTRIBUTION_CAM, methods=[HTTP_REQUEST_METHODE_POST])
@csrf.exempt
def cam_cert_distribution() -> Response:
    logging.info(LOG_API_REQUEST_DISTRIBUTION_CAM_POST)
    _csrf_token                                 = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token                                   = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    user_token                                  = quote(str(request.get_json().get(JSON_KEY_TOKEN_USER)))
    channel_name                                = quote(str(request.get_json().get(JSON_KEY_CHANNEL_NAME)))
    iv                                          = quote(str(request.get_json().get(JSON_KEY_IV)))
    identifier                                  = quote(Service.createId(IDENTIFIER_LENGTH))
    sharedSecret                                = quote(str(session.get('sharedSecret')))
    channelName                                 = seccom.decrypt(channel_name, iv, sharedSecret)
    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_USER, user_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
            return Service.failureResponse()
    else:
        return Service.handleHttpCamDistributionPostRequest(identifier,
                                                            channelName.decode('utf-8'))

@async_api.route(URL_CERT_CREATION_API_CA, methods=[HTTP_REQUEST_METHODE_POST])
@csrf.exempt
def api_cert_ca_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_API_CA_POST)
    _csrf_token         = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token           = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))
    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return Service.handleHttpCaCrtPostRequest(TLS_CA_TYPE_API)

@async_api.route(URL_CERT_CREATION_API_CA, methods=[HTTP_REQUEST_METHODE_GET])
def api_cert_ca_distribution() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_API_CA_GET)
    _csrf_token         = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token           = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))

    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return Service.handleHttpCaCrtGetRequest(   PATH_API_CA_CRT,
                                                    PATH_API_CA_KEY)


@async_api.route(URL_CERT_CREATION_API_BROKER, methods=[HTTP_REQUEST_METHODE_POST])
@csrf.exempt
def api_cert_broker_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_API_BROKER_POST)
    _csrf_token     = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token   = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))
    identifier      = quote(Service.createId(IDENTIFIER_LENGTH))

    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return Service.handleHttpCrtPostRequest(identifier,
                                                TLS_CA_TYPE_API,
                                                TLS_CRT_TYPE_BROKER,
                                                PATH_API_BROKER_CRT,
                                                PATH_API_BROKER_KEY)


@async_api.route(URL_CERT_CREATION_API_CLIENT, methods=[HTTP_REQUEST_METHODE_POST])
@csrf.exempt
def api_cert_client_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_API_CLIENT_POST)
    _csrf_token     = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token   = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))
    identifier      = quote(Service.createId(IDENTIFIER_LENGTH))
    
    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return Service.handleHttpCrtPostRequest(identifier,
                                                TLS_CA_TYPE_API,
                                                TLS_CRT_TYPE_CLIENT,
                                                PATH_API_CLIENT_CRT,
                                                PATH_API_CLIENT_KEY)

@async_api.route(URL_CERT_CREATION_CAM_CA, methods=[HTTP_REQUEST_METHODE_POST])
@csrf.exempt
def cam_cert_ca_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_CAM_CA_POST)
    _csrf_token         = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token           = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))
    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return Service.handleHttpCaCrtPostRequest(TLS_CA_TYPE_CAM)


@async_api.route(URL_CERT_CREATION_CAM_CA, methods=[HTTP_REQUEST_METHODE_GET])
def cam_cert_ca_distribution() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_CAM_CA_GET)
    _csrf_token         = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token           = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))

    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return  Service.handleHttpCaCrtGetRequest(  PATH_CAM_CA_CRT,
                                                    PATH_CAM_CA_KEY)

@async_api.route(URL_CERT_CREATION_CAM_BROKER, methods=[HTTP_REQUEST_METHODE_POST])
@csrf.exempt
def cam_cert_broker_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_CAM_BROKER_POST)
    _csrf_token     = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token   = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))
    identifier      = quote(Service.createId(IDENTIFIER_LENGTH))

    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return Service.handleHttpCrtPostRequest(identifier,
                                                TLS_CA_TYPE_CAM,
                                                TLS_CRT_TYPE_BROKER,
                                                PATH_CAM_BROKER_CRT,
                                                PATH_CAM_BROKER_KEY)

@async_api.route(URL_ALS_CREATION_KEYS, methods=[HTTP_REQUEST_METHODE_POST])
@csrf.exempt
def als_rsa_creation() -> Response:
    logging.info(LOG_API_REQUEST_RSA_POST)
    _csrf_token     = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token   = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))

    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return Service.createAlsRsaKeyPair()

@async_api.route(URL_ALS_CREATION_KEYS, methods=[HTTP_REQUEST_METHODE_GET])
def get_als_rsa() -> Response:
    logging.info(LOG_API_REQUEST_RSA_GET)
    _csrf_token     = quote(str(request.cookies.get(SESSION_KEY_CSRF)))
    api_token       = quote(str(request.get_json().get(JSON_KEY_TOKEN_API)))
    creator_token   = quote(str(request.get_json().get(JSON_KEY_TOKEN_CREATOR)))

    if  not Service.validate.token(PATH_TOKEN_API, api_token
    )   or not Service.validate.token(PATH_TOKEN_CREATOR, creator_token
    )   or not Service.validate.csrfToken(session.get(SESSION_DATA_KEY_CSRF), _csrf_token
    )   or request.content_type != HEADER_REQUEST_VALUE_APP_JSON:
        return Service.failureResponse()
    else:
        return Service.handleHttpAlsGetRequest()

async_api_asgi = WsgiToAsgi(async_api)
phMid = ProxyHeadersMiddleware(async_api, trusted_hosts="127.0.0.1")

if __name__ == PYTHON_LIFECYCLE_MAIN:
    Service.main()
