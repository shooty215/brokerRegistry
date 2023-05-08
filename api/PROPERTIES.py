PYTHON_LIFECYCLE_MAIN                           : str   = '__main__'
CSRF_SECRET                                     : str   = 'CSRF_SALT'
LOG_FORMAT                                      : str   = '%(asctime)s    :%(levelname)s    :%(message)s'
#LOG_CSRF_GENERATION                             : str   = 'Generating csrf token.'
#LOG_SESSION_ID_GENERATION                       : str   = 'Generating session id.'
LOG_RESPONSE_JSON                               : str   = 'Generating response json.'
LOG_TLS_CONTEXT_CREATION_START                  : str   = 'Creating tls context.'
LOG_API_REQUEST_RSA_GET                         : str   = 'Api rsa get request.'
LOG_API_REQUEST_RSA_POST                        : str   = 'Api rsa post request.'
#LOG_API_REQUEST_CREATION_CAM_CLIENT_POST        : str   = 'API    : Post, Creating signed cam client certificate.'
LOG_API_REQUEST_CREATION_CAM_BROKER_POST        : str   = 'API    : Post, Creating signed cam broker certificate.'
LOG_API_REQUEST_CREATION_CAM_CA_POST            : str   = 'API    : Post, Creating signed cam ca certificate.'
LOG_API_REQUEST_CREATION_CAM_CA_GET             : str   = 'API    : Get, Creating signed cam ca certificate.'
LOG_API_REQUEST_CREATION_API_CLIENT_POST        : str   = 'API    : Post, Creating signed api client certificate.'
LOG_API_REQUEST_CREATION_API_BROKER_POST        : str   = 'API    : Post, Creating signed api broker certificate.'
LOG_API_REQUEST_CREATION_API_CA_POST            : str   = 'API    : Post, Creating signed api ca certificate.'
LOG_API_REQUEST_CREATION_API_CA_GET             : str   = 'API    : Get, Issuing signed api ca certificate.'
LOG_API_REQUEST_DISTRIBUTION_CAM_POST           : str   = 'API    : Post, Creating signed cam client certificate.'
LOG_ISSUING_START                               : str   = 'Issuing signed certificate.'
#LOG_SCRIPT_DISTRIBUTION_RUN_START               : str   = 'Executing distribution script.'
#LOG_SCRIPT_BASH_RUN_START                       : str   = 'Executing bash script.'
LOG_SCRIPT_JAR_RUN_START                        : str   = 'Executing jar.'
LOG_ALS_RSA_PAIR_SERIALIZATION_START            : str   = 'Serializing rsa key pair.'
LOG_ALS_RSA_PAIR_CREATION_START                 : str   = 'Creating rsa key pair.'
#LOG_ALS_KEYS_CREATION                           : str   = 'Creating als keys'
LOG_ALS_KEYS_DISTRIBUTION                       : str   = 'Distributing als keys'
LOG_TLS_CONTEXT_CREATION_START                  : str   = 'Creating tls context.'
#LOG_PEM_CREATION_CREATION_START                 : str   = 'Creating pem.'
LOG_FILE_SERIALIZE                              : str   = 'Serializing file.'
ALS_KEY_PUBLIC                                  : str   = 'pubKey'
ALS_KEY_PRIVATE                                 : str   = 'privKey'
ALS_KEY_AES                                     : str   = 'aesKey'
#API_SECURE_KEY                                  : str   = 'CSRF_PARTIAL'
API_IP_LOCAL                                    : str   = '0.0.0.0'
API_IP_PORT                                     : int   = 22432
PATH_HOME                                       : str   = '/home/brokerregistry/'
PATH_LOG                                        : str   = PATH_HOME + 'brokerRegistry.log'
#PATH_CONFIG                                     : str   = PATH_HOME + 'etc/'
#PATH_BIN                                        : str   = PATH_HOME + 'bin/'
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
#HTTP_SUCCESS                                    : str   = 'Request Successfull'
#HTTP_INPUTS_VALIDATION_FAILURE                  : str   = 'Missing token or channel name'
#HTTP_RESPONSE_AUTHENTICATION_SUCCESS            : str   = 'SESSION ID AND CSRF TOKEN IN COOKIE'
#HTTP_RESPONSE_DISTRIBUTION_SUCCESS              : str   = 'Certificate distribution successful'
#HTTP_RESPONSE_DISTRIBUTION_FAILURE              : str   = 'Certificate distribution failed'
#HTTP_RESPONSE_CREATION_SUCCESS                  : str   = 'Creation Successfull.'
#HTTP_RESPONSE_CREATION_FAILURE                  : str   = 'Creation Failed.'
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
#COOKIE_KEY_OWNER                                : str   = 'dirPic'
URL_CERT_DISTRIBUTION_CAM                       : str   = '/distribution'
URL_CERT_CREATION_API_CA                        : str   = '/cert/api/ca'
URL_CERT_CREATION_API_BROKER                    : str   = '/cert/api/broker'
URL_CERT_CREATION_API_CLIENT                    : str   = '/cert/api/client'
URL_CERT_CREATION_CAM_CA                        : str   = '/cert/cam/ca'
URL_CERT_CREATION_CAM_BROKER                    : str   = '/cert/cam/broker'
#URL_CERT_CREATION_CAM_CLIENT                    : str   = '/cert/cam/client'
URL_ALS_CREATION_KEYS                           : str   = '/als'
URL_API_HANDSHAKE                               : str   = '/handshake'
#URL_API_DEAUTHENTICATION                        : str   = '/deauthentication'
CMD_RUN_PARAMETER_BASH                          : str   = '/home/brokerregistry/bin/bash'
CMD_RUN_PARAMETER_JAVA                          : str   = '/home/brokerregistry/bin/java'
CMD_RUN_PARAMETER_JAR                           : str   = '-jar'
JSON_KEY_ECDH_PUBLIC                            : str   = 'ecdhPublic'
#JSON_KEY_ECDH_PRIVATE                           : str   = 'ecdhPrivate'
JSON_KEY_TOKEN_API                              : str   = 'apiToken'
JSON_KEY_TOKEN_USER                             : str   = 'userToken'
JSON_KEY_TOKEN_CREATOR                          : str   = 'creatorToken'
#JSON_KEY_TOKEN_CSRF                             : str   = 'csrfToken'
JSON_KEY_CHANNEL_NAME                           : str   = 'channelName'
JSON_KEY_RSA_PUBLIC_KEY                         : str   = 'key'
#JSON_KEY_SESSION_ID                             : str   = 'sessionId'
JSON_KEY_IV                                     : str   = 'iv'
JSON_RESPONSE_KEY_CA_CRT                        : str   = 'caCrt'
JSON_RESPONSE_KEY_CA_KEY                        : str   = 'caKey'
#JSON_RESPONSE_KEY_CODE                          : str   = 'response_code'
#JSON_RESPONSE_KEY_PAYLOAD                       : str   = 'payload'
JSON_RESPONSE_KEY_ALS_PRIV                      : str   = 'alsPrivKey'
JSON_RESPONSE_KEY_ALS_PUB                       : str   = 'alsPubKey'
JSON_RESPONSE_KEY_ALS_AES                       : str   = 'alsAes'
#JSON_RESPONSE_KEY_SHARED_SECRET_DIGEST          : str   = 'sharedSecret'
#JSON_RESPONSE_KEY_PKEC                          : str   = 'key'
TLS_CA_TYPE_CAM                                 : str   = 'cam'
TLS_CA_TYPE_API                                 : str   = 'api'
TLS_CRT_TYPE_CLIENT                             : str   = 'client'
TLS_CRT_TYPE_BROKER                             : str   = 'broker'
SESSION_KEY_ID                                  : str   = 'sessionId'
SESSION_KEY_CSRF                                : str   = 'X-CSRFToken'
SESSION_DATA_KEY_CSRF                           : str   = 'csrf_token'
#CONTEXT_API_IDENTIFIER                          : str   = 'ACT'
CONTEXT_PASSWORD                                : str   = 'AWFuIITe2kOsPzEO15LFKT4DWAW6pB6zm16EmRgFWEJ6Cu2fZL'
CONTEXT_CRT                                     : str   = PATH_API_CRT
CONTEXT_KEY                                     : str   = PATH_API_KEY
CONTEXT_CA                                      : str   = PATH_API_CA_CRT
#CONTEXT_DH_PARAM                                : str   = PATH_API_DH
#CONTEXT_EC                                      : str   = "prime256v1"
CONTEXT_CIPHERS                                 : str   = "ECDHE-RSA-AES128-GCM-SHA256"
#CONTEXT_SIGNATURE_ALGORITHM                     : str   = "sha256_ecdsa"
PERMISSION_FILE_OPEN_READ                       : str   = 'r'
#PERMISSION_FILE_OPEN_READ_BYTE                  : str   = 'rb'
INDEX_ARRAY_0                                   : int   = 0
INDEX_ARRAY_1                                   : int   = 1
INDEX_ARRAY_2                                   : int   = 2
EXIT_CODE_SUCCESS                               : int   = 0
#EXIT_CODE_FAILURE                               : int   = 1
IDENTIFIER_LENGTH                               : int   = 5
HTTP_RESPONSE_CODE_200                          : int   = 200
HTTP_RESPONSE_CODE_400                          : int   = 400
#CMD_OPENSSL_PARAMETER_LENGTH_RSA_KEY            : int   = 4096
SUCCESS                                         : bool  = True
FAILURE                                         : bool  = False