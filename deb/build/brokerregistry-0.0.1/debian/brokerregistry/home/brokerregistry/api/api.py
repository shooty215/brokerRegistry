#!/bin/python3
from PROPERTIES import *
from flask import Flask, request, make_response, Response, session
from flask_wtf.csrf import CSRFProtect
from flask_sslify import SSLify
from uvicorn import Server, Config
from urllib.parse import quote
from ssl import SSLContext, PROTOCOL_TLS
import ssl, subprocess, logging, random, string, uvicorn, json

class Service:

    logging.basicConfig(filename=PATH_LOG,
                        level=logging.DEBUG,
                        format=LOG_FORMAT)

    class Validate:

        def token(file: str, token: str) -> bool:
            flag = FAILURE
            if isinstance(token, str) and token:
                with open(file, PERMISSION_FILE_OPEN_READ) as file:
                    for line in file:
                        if token is line:
                            flag = SUCCESS
            return flag

        def csrfToken(token: str, val: str) -> bool:
            return token is val
        
        def context(context: SSLContext) -> bool:
            return isinstance(context, SSLContext) and context
        
        def script(result: bool) -> bool:
            return result is not FAILURE

        def creatorInput( api_token: str,
                            creator_token: str) -> bool:
            return Service.Validate.token(PATH_TOKEN_API, api_token) and Service.Validate.token(PATH_TOKEN_CREATOR, creator_token)
        
        def userInput(  api_token: str,
                        user_token: str,
                        channel_name: str) -> bool:
            return Service.Validate.token(PATH_TOKEN_API, api_token) and Service.Validate.token(PATH_TOKEN_USER, user_token) and (type(channel_name) is not None and str)
        
        def creation(file: str or bytes) -> bool:
            return (isinstance(file, str) or isinstance(file, bytes)) and file
        
        def als(als: dict or None):
            return (isinstance(als, dict) and als) and (isinstance(als[ALS_KEY_PUBLIC], str) and als[ALS_KEY_PUBLIC]) and (isinstance(als[ALS_KEY_PRIVATE], str) and als[ALS_KEY_PRIVATE]) and (isinstance(als[ALS_KEY_PUBLIC], str) is str and als[ALS_KEY_AES])
    
    def response(payload: dict,  sessionId: str) -> Response:
        logging.info(LOG_RESPONSE_JSON)
        csrfToken                                           = csrf.generate_token()
        session_data: dict                                  = {}
        session_data[SESSION_DATA_KEY_CSRF]                 = csrfToken
        sessions[sessionId]                                 = session_data
        response                                            = make_response(json.dumps(payload))
        response.response_code                              = HTTP_RESPONSE_CODE_200
        response.set_cookie(SESSION_KEY_ID,
                            value                           = sessionId,
                            secure                          = COOKIE_VALUE_TRUE,
                            httponly                        = COOKIE_VALUE_TRUE,
                            samesite                        = COOKIE_VALUE_STRICT)
        response.set_cookie(SESSION_KEY_CSRF,
                            value                           = csrfToken,
                            secure                          = COOKIE_VALUE_TRUE,
                            httponly                        = COOKIE_VALUE_TRUE,
                            samesite                        = COOKIE_VALUE_STRICT)
        response.headers[HEADER_RESPONSE_KEY_CONTENT_TYPE]  = HEADER_RESPONSE_VALUE_APP_JSON
        return response

    def successResponse(sessionId: str) -> Response:
        logging.info(LOG_RESPONSE_JSON)
        csrfToken                                           = csrf.generate_token()
        session_data: dict                                  = {}
        session_data[SESSION_DATA_KEY_CSRF]                 = csrfToken
        sessions[sessionId]                                 = session_data
        payload: dict                                       = {}
        payload[str(PAYLOAD_KEY_REQUEST)]                   = str(PAYLOAD_VALUE_SUCCESSFULL)
        response                                            = make_response(json.dumps(payload))
        response.response_code                              = HTTP_RESPONSE_CODE_200
        response.set_cookie(SESSION_KEY_ID,
                            value                           = sessionId,
                            secure                          = COOKIE_VALUE_TRUE,
                            httponly                        = COOKIE_VALUE_TRUE,
                            samesite                        = COOKIE_VALUE_STRICT)
        response.set_cookie(SESSION_KEY_CSRF,
                            value                           = csrfToken,
                            secure                          = COOKIE_VALUE_TRUE,
                            httponly                        = COOKIE_VALUE_TRUE,
                            samesite                        = COOKIE_VALUE_STRICT)
        response.headers[HEADER_RESPONSE_KEY_CONTENT_TYPE]  = HEADER_RESPONSE_VALUE_APP_JSON
        return response

    def failureResponse(sessionId: str) -> Response:
        logging.info(LOG_RESPONSE_JSON)
        csrfToken                                           = csrf.generate_token()
        session_data: dict                                  = {}
        session_data[SESSION_DATA_KEY_CSRF]                 = csrfToken
        sessions[sessionId]                                 = session_data
        payload: dict                                       = {}
        payload[str(PAYLOAD_KEY_REQUEST)]                   = str(PAYLOAD_VALUE_FAILURE)
        response                                            = make_response(json.dumps(payload))
        response.response_code                              = HTTP_RESPONSE_CODE_400
        response.set_cookie(SESSION_KEY_ID,
                            value                           =sessionId,
                            secure                          =COOKIE_VALUE_TRUE,
                            httponly                        =COOKIE_VALUE_TRUE,
                            samesite                        =COOKIE_VALUE_STRICT)
        response.set_cookie(SESSION_KEY_CSRF,
                            value                           = csrfToken,
                            secure                          = COOKIE_VALUE_TRUE,
                            httponly                        = COOKIE_VALUE_TRUE,
                            samesite                        = COOKIE_VALUE_STRICT)
        response.headers[HEADER_RESPONSE_KEY_CONTENT_TYPE]  = HEADER_RESPONSE_VALUE_APP_JSON
        return response
    
    def createTlsContext() -> SSLContext:
        logging.info(LOG_TLS_CONTEXT_CREATION_START)
        ssl_context = ssl.create_default_context(   purpose     = ssl.Purpose.SERVER_AUTH,
                                                    cafile      = CONTEXT_CA)
        ssl_context.load_cert_chain(                CONTEXT_CRT,
                                                    keyfile     = CONTEXT_KEY,
                                                    password    = CONTEXT_PASSWORD)
        ssl_context.set_ciphers(CONTEXT_CIPHERS)
        ssl_context.set_ecdh_curve(CONTEXT_EC)
        ssl_context.load_dh_params(CONTEXT_DH_PARAM)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        return ssl_context
    
    def deserializeFile(path: str) -> str:
        logging.info(LOG_FILE_SERIALIZE)
        with open(path, PERMISSION_FILE_OPEN_READ) as file:
            file_contents = file.read()
        return file_contents

    def createAlsRsaKeyPair() -> bool:
        logging.info(LOG_ALS_RSA_PAIR_CREATION_START)
        if not Service.Validate.script(Service.runJarScript(PATH_ALS_RSA_CREATION_JAR, CMD_RUN_PARAMETER_JAR)):
            return SUCCESS
        else:
            return FAILURE

    def deserializeAlsRsaKeyPair() -> tuple or FAILURE:
        logging.info(LOG_ALS_RSA_PAIR_SERIALIZATION_START)
        als = dict(Service.deserializeFile(PATH_JAR_ALS))
        if Service.Validate.als(als):
            return ( als[ALS_KEY_PUBLIC], als[ALS_KEY_PRIVATE], als[ALS_KEY_AES] )
        else:
            return FAILURE

    def runJarScript(bash_script: str) -> bool:
        logging.info(LOG_SCRIPT_JAR_RUN_START)
        if subprocess.run([ CMD_RUN_PARAMETER_JAVA,
                            PATH_ALS_RSA_CREATION_JAR,
                            CMD_RUN_PARAMETER_JAR],
                            check=SUCCESS).returncode is EXIT_CODE_SUCCESS:
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
            valKey: str     = PATH_CAM_CA_KEY
            valCert: str    = PATH_CAM_CA_CRT
        elif caType == TLS_CA_TYPE_API:
            valKey: str     = PATH_API_CA_KEY
            valCert: str    = PATH_API_CA_CRT
        else:
            return FAILURE
        if subprocess.run([ CMD_RUN_PARAMETER_BASH,
                            PATH_DISTRIBUTION_CRT,
                            caType],
                            check=SUCCESS).returncode is EXIT_CODE_SUCCESS:
            val: tuple = (  Service.deserializeFile(valCrt), Service.deserializeFile(valKey) )
            if Service.Validate.creation(val[INDEX_ARRAY_0]) and Service.Validate.creation(val[INDEX_ARRAY_1]):
                return SUCCESS
            else:
                return FAILURE
        else:
            return FAILURE

    def issueSignedCrt(caType: str, certType: str, identifier: str, keyPwd: str or None = None) -> bool:
        logging.info(LOG_ISSUING_START)
        if caType == TLS_CA_TYPE_CAM and certType == TLS_CRT_TYPE_CLIENT:
            valKey: str     = PATH_CERTIFICATES + identifier + PATH_CAM_CLIENT_KEY
            valCert: str    = PATH_CERTIFICATES + identifier + PATH_CAM_CLIENT_CRT
        elif caType == TLS_CA_TYPE_CAM and certType == TLS_CRT_TYPE_BROKER:
            valKey: str     = PATH_CERTIFICATES + identifier + PATH_CAM_BROKER_KEY
            valCert: str    = PATH_CERTIFICATES + identifier + PATH_CAM_BROKER_CRT
        elif caType == TLS_CA_TYPE_API and certType == TLS_CRT_TYPE_CLIENT:
            valKey: str     = PATH_CERTIFICATES + identifier + PATH_API_CLIENT_KEY
            valCert: str    = PATH_CERTIFICATES + identifier + PATH_API_CLIENT_CRT
        elif caType == TLS_CA_TYPE_API and certType == TLS_CRT_TYPE_BROKER:
            valKey: str     = PATH_CERTIFICATES + identifier + PATH_API_BROKER_KEY
            valCert: str    = PATH_CERTIFICATES + identifier + PATH_API_BROKER_CRT
        else:
            return FAILURE
        if isinstance(keyPwd, str) and keyPwd:
            if subprocess.run([ CMD_RUN_PARAMETER_BASH,
                                PATH_DISTRIBUTION_CRT,
                                caType,
                                certType,
                                identifier,
                                keyPwd],
                                check=SUCCESS).returncode is EXIT_CODE_SUCCESS:
                val: tuple = ( Service.deserializeFile(valCrt), 
                                Service.deserializeFile(valKey) )
                if Service.Validate.creation(val[INDEX_ARRAY_0]) and Service.Validate.creation(val[INDEX_ARRAY_1]):
                    return SUCCESS
                else:
                    return FAILURE
            else:
                return FAILURE
        elif isinstance(keyPwd, None) and not keyPwd:
            if subprocess.run([ CMD_RUN_PARAMETER_BASH,
                                PATH_DISTRIBUTION_CRT,
                                caType,
                                certType,
                                identifier],
                                check=SUCCESS).returncode is EXIT_CODE_SUCCESS:
                val: tuple = ( Service.deserializeFile(valCrt),
                                Service.deserializeFile(valKey) )
                if Service.Validate.creation(val[INDEX_ARRAY_0]) and Service.Validate.creation(val[INDEX_ARRAY_1]):
                    return SUCCESS
                else:
                    return FAILURE
            else:
                return FAILURE
        else:
            return FAILURE
    
    def handleHttpCamDistributionPostRequest(identifier, channel_name):
        logging.info(LOG_HTTP_POST_REQUEST)
        if Service.Validate.script(Service.issueSignedCrt(  TLS_CA_TYPE_CAM,
                                                            TLS_CRT_TYPE_CLIENT,
                                                            identifier,
                                                            channel_name)):
            if Service.Validate.script(Service.runJarScript(PATH_JAR_PROPERTIES,
                                                            PATH_JAR_ALS,
                                                            TLS_CA_TYPE_CAM,
                                                            TLS_CRT_TYPE_CLIENT,
                                                            identifier,
                                                            channel_name)):
                return Service.rsuccessResponse()
            else:
                return Service.failureResponse()
        else:
            return Service.failureResponse()
    
    def handleHttpAlsPostRequest():
        logging.info(LOG_HTTP_POST_REQUEST)
        if Service.Validate.als(Service.createAlsRsaKeyPair()):
            return Service.successResponse()
        else:
            return Service.failureResponse()
    
    def handleHttpAlsGetRequest(sessionId: str):
        logging.info(LOG_HTTP_GET_REQUEST)
        als = Service.deserializeAlsRsaKeyPair() 
        if Service.Validate.als(als):
            payload: dict                               = {}
            payload[str(JSON_RESPONSE_KEY_ALS_PRIV)]    = str(als[INDEX_ARRAY_0])
            payload[str(JSON_RESPONSE_KEY_ALS_PUB)]     = str(als[INDEX_ARRAY_1])
            payload[str(JSON_RESPONSE_KEY_ALS_AES)]     = str(als[INDEX_ARRAY_2])
            return Service.response(payload, sessionId)
        else:
            return Service.failureResponse()
    
    def handleHttpCaCrtPostRequest(caType: str):
        logging.info(LOG_HTTP_POST_REQUEST)
        if Service.Validate.script(Service.issueNewCaCrt(caType)):
            return Service.rsuccessResponse()
        else:
            return Service.failureResponse()   

    def handleHttpCaCrtGetRequest(sessionId: str, caCrt: str, caKey: str):
        logging.info(LOG_HTTP_GET_REQUEST)
        payload: dict                               = {}
        payload[str(JSON_RESPONSE_KEY_CA_CRT)]      = str(Service.deserializeFile(PATH_CERTIFICATES + caCrt))
        payload[str(JSON_RESPONSE_KEY_CA_KEY)]      = str(Service.deserializeFile(PATH_CERTIFICATES + caKey))
        if Service.Validate.creation(payload[JSON_RESPONSE_KEY_CA_CRT]) and Service.Validate.creation(payload[JSON_RESPONSE_KEY_CA_CRT]):
            return Service.response(payload, sessionId)
        else:
            return Service.failureResponse()

    def handleHttpCrtPostRequest(sessionId: str, identifier: str, caType: str, crtType: str, crt: str, key: str):
        logging.info(LOG_HTTP_POST_REQUEST)
        if Service.Validate.script(Service.issueSignedCrt(  caType,
                                                            crtType,
                                                            identifier)):
            payload: dict                               = {}
            payload[str(JSON_RESPONSE_KEY_CA_CRT)]      = str(Service.deserializeFile(PATH_CERTIFICATES + identifier + crt))
            payload[str(JSON_RESPONSE_KEY_CA_KEY)]      = str(Service.deserializeFile(PATH_CERTIFICATES + identifier + key))
            if Service.Validate.creation(val[INDEX_ARRAY_0]) and Service.Validate.creation(val[INDEX_ARRAY_1]):
                return Service.response(payload, sessionId)
            else:
                return Service.failureResponse()
        else:
            return Service.failureResponse()

async_api = Flask(__name__)
async_api.config[API_SECURE_KEY] = CSRF_SECRET
sslify = SSLify(app=async_api, permanent=True, keyfile=CONTEXT_KEY, certfile=CONTEXT_CRT)
csrf = CSRFProtect(async_api)

async def asgi_app(scope, receive, send):
    request = Request(scope, receive)
    response = await async_api.handle_request(request)
    await response(scope, receive, send)

@async_api.route(URL_API_AUTHENTICATION, methods=[HTTP_REQUEST_METHODE_POST])
async def authenticate() -> Response:
    if not Service.Validate.creatorInput(   apiToken,
                                            userToken):
        return Service.failureResponse()
    elif not request.cookies.get(SESSION_KEY_ID):
        session_id                                          = str(uuid.uuid4())
        session_data: dict                                  = {}
        session_data[SESSION_DATA_KEY_CSRF]                 = csrf.generate_token()
        sessions[session_id]                                = session_data
        payload: dict                                       = {}
        payload[str(HTTP_RESPONSE_AUTHENTICATION_SUCCESS)]  = str(als[INDEX_ARRAY_0])
        return Service.response(payload, session_id)
    else:
        return Service.failureResponse()

@async_api.route(URL_API_AUTHENTICATION, methods=[HTTP_REQUEST_METHODE_DELETE])
async def deauthenticate() -> Response:
    sessionId = request.cookies.get(SESSION_KEY_ID)
    _csrf_token = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        user_token      = quote(str(request.args.get(JSON_KEY_TOKEN_USER)))
        channel_name    = quote(str(request.args.get(JSON_KEY_CHANNEL_NAME)))
        identifier      = quote(str(Service.createId(IDENTIFIER_LENGTH)))
    if not Service.Validate.csrfToken(  session_data[SESSION_DATA_KEY_CSRF],
                                                _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.creatorInput( apiToken,
                                                    userToken):
        return Service.failureResponse()
    else:
        del sessions[sessionId]
        payload: dict                           = {}
        payload[str(PAYLOAD_KEY_REQUEST)]       = str(PAYLOAD_VALUE_SUCCESSFULL)
        response                                = make_response(payload)
        response.delete_cookie(SESSION_KEY_ID)
        response.delete_cookie(SESSION_KEY_CSRF)
        return response

@async_api.route(URL_CERT_DISTRIBUTION_CAM, methods=[HTTP_REQUEST_METHODE_POST])
async def cam_cert_distribution() -> Response:
    logging.info(LOG_API_REQUEST_DISTRIBUTION_CAM_POST)
    sessionId                                   = request.cookies.get(SESSION_KEY_ID)
    _csrf_token                                 = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        user_token      = quote(str(request.args.get(JSON_KEY_TOKEN_USER)))
        channel_name    = quote(str(request.args.get(JSON_KEY_CHANNEL_NAME)))
        identifier      = quote(str(Service.createId(IDENTIFIER_LENGTH)))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCamDistributionPostRequest(  identifier,
                                                                        channel_name)

@async_api.route(URL_CERT_CREATION_API_CA, methods=[HTTP_REQUEST_METHODE_POST])
async def api_cert_ca_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_API_CA_POST)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCaCrtPostRequest(TLS_CA_TYPE_API)

@async_api.route(URL_CERT_CREATION_API_CA, methods=[HTTP_REQUEST_METHODE_GET])
async def api_cert_ca_distribution() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_API_CA_GET)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCaCrtGetRequest( PATH_API_CA_CRT,
                                                        PATH_API_CA_KEY)

@async_api.route(URL_CERT_CREATION_API_BROKER, methods=[HTTP_REQUEST_METHODE_POST])
async def api_cert_broker_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_API_BROKER_POST)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
        identifier      = quote(Service.createId(IDENTIFIER_LENGTH))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCrtPostRequest(  identifier,
                                                        TLS_CA_TYPE_API,
                                                        TLS_CRT_TYPE_BROKER,
                                                        PATH_API_BROKER_CRT,
                                                        PATH_API_BROKER_KEY)

@async_api.route(URL_CERT_CREATION_API_CLIENT, methods=[HTTP_REQUEST_METHODE_POST])
async def api_cert_client_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_API_CLIENT_POST)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
        identifier      = quote(Service.createId(IDENTIFIER_LENGTH))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCrtPostRequest(  identifier,
                                                        TLS_CA_TYPE_API,
                                                        TLS_CRT_TYPE_CLIENT,
                                                        PATH_API_CLIENT_CRT,
                                                        PATH_API_CLIENT_KEY)

@async_api.route(URL_CERT_CREATION_CAM_CA, methods=[HTTP_REQUEST_METHODE_POST])
async def cam_cert_ca_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_CAM_CA_POST)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                                user_token,
                                                channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCaCrtPostRequest(TLS_CA_TYPE_CAM)

@async_api.route(URL_CERT_CREATION_CAM_CA, methods=[HTTP_REQUEST_METHODE_GET])
async def cam_cert_ca_distribution() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_CAM_CA_GET)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCaCrtGetRequest( PATH_CAM_CA_CRT,
                                                        PATH_CAM_CA_KEY)

@async_api.route(URL_CERT_CREATION_CAM_BROKER, methods=[HTTP_REQUEST_METHODE_POST])
async def cam_cert_broker_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_CAM_BROKER_POST)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
        identifier      = quote(Service.createId(IDENTIFIER_LENGTH))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCrtPostRequest(  identifier,
                                                        TLS_CA_TYPE_CAM,
                                                        TLS_CRT_TYPE_BROKER,
                                                        PATH_CAM_BROKER_CRT,
                                                        PATH_CAM_BROKER_KEY)

@async_api.route(URL_CERT_CREATION_CAM_CLIENT, methods=[HTTP_REQUEST_METHODE_POST])
async def cam_cert_client_creation() -> Response:
    logging.info(LOG_API_REQUEST_CREATION_CAM_CLIENT_POST)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
        identifier      = quote(Service.createId(IDENTIFIER_LENGTH))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpCrtPostRequest(  identifier,
                                                        TLS_CA_TYPE_CAM,
                                                        TLS_CRT_TYPE_CLIENT,
                                                        PATH_CAM_CLIENT_CRT,
                                                        PATH_CAM_CLIENT_KEY)

@async_api.route(URL_ALS_CREATION_KEYS, methods=[HTTP_REQUEST_METHODE_POST])
async def als_rsa_creation() -> Response:
    logging.info(LOG_API_REQUEST_RSA_POST)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpAlsPostRequest()

@async_api.route(URL_ALS_CREATION_KEYS, methods=[HTTP_REQUEST_METHODE_GET])
async def get_als_rsa() -> Response:
    logging.info(LOG_API_REQUEST_RSA_GET)
    sessionId           = request.cookies.get(SESSION_KEY_ID)
    _csrf_token         = request.cookies.get(SESSION_KEY_CSRF)
    if not sessionId in sessions:
        return Service.failureResponse()
    else:
        session_data    = sessions[sessionId]
        api_token       = quote(str(request.args.get(JSON_KEY_TOKEN_API)))
        creator_token   = quote(str(request.args.get(JSON_KEY_TOKEN_CREATOR)))
    if not Service.Validate.csrfToken(session_data[SESSION_DATA_KEY_CSRF], _csrf_token):
        return Service.failureResponse()
    elif not Service.Validate.userInput(api_token,
                                        user_token,
                                        channel_name):
        return Service.failureResponse()
    else:
        return await Service.handleHttpAlsGetRequest(sessionId)

#sudo -u brokerregistry /bin/python3 /home/sht/github/brokerRegistry/api/api.py
if __name__ == PYTHON_LIFECYCLE_MAIN:
    sslContext          = Service.createTlsContext()
    if Service.Validate.context(sslContext):
        uvicorn.run('api:async_api',
                    host=API_IP_LOCAL,
                    port=API_IP_PORT,
                    ssl_keyfile=CONTEXT_KEY,
                    ssl_certfile=CONTEXT_CRT,
                    ssl_keyfile_password=CONTEXT_PASSWORD,
                    ssl_version=ssl.PROTOCOL_TLSv1_2,
                    ssl_ca_certs=CONTEXT_CA,
                    ssl_ciphers=CONTEXT_CIPHERS,
                    lifespan='off',
                    workers=4,
                    interface='ASGI3',
                    loop='auto')
    else:
        print(str(1))