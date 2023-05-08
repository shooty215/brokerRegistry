#!/home/brokerregistry/bash
. /home/brokerregistry/etc/certificates.conf

if [ "$1" = "api" ] && [ "$2" = "broker" ] && [ -n "$3" ]
then
    INPUT_CA_KEY_PWD=$API_CA_KEY_PWD
    INPUT_CRT_KEY_PWD=$API_BROKER_KEY_PWD
    INPUT_PATH_CA_CRT=$PATH_CERTIFICATES$PATH_API_CA_CRT
    INPUT_PATH_CA_KEY=$PATH_CERTIFICATES$PATH_API_CA_KEY
    INPUT_PATH_CRT=$PATH_CERTIFICATES$3$PATH_API_BROKER_CRT
    INPUT_PATH_CRT_KEY=$PATH_CERTIFICATES$3$PATH_API_BROKER_CRT_KEY
    INPUT_PATH_CRT_CSR=$PATH_CERTIFICATES$3$PATH_API_BROKER_CRT_CSR
    INPUT_PATH_CRT_KEY_PEM=$PATH_CERTIFICATES$3$PATH_API_BROKER_CRT_KEY_PEM
    INPUT_CRT_CONF=$PATH_CONFIG$PATH_BROKER_CONF
elif [ "$1" = "api" ] && [ "$2" = "client" ] && [ -n "$3" ]
then
    INPUT_CA_KEY_PWD=$API_CA_KEY_PWD
    INPUT_CRT_KEY_PWD=$API_BROKER_KEY_PWD
    INPUT_PATH_CA_CRT=$PATH_CERTIFICATES$PATH_API_CA_CRT
    INPUT_PATH_CA_KEY=$PATH_CERTIFICATES$PATH_API_CA_KEY
    INPUT_PATH_CRT=$PATH_CERTIFICATES$3$PATH_API_CLIENT_CRT
    INPUT_PATH_CRT_KEY=$PATH_CERTIFICATES$3$PATH_API_CLIENT_KEY
    INPUT_PATH_CRT_CSR=$PATH_CERTIFICATES$3$PATH_API_CLIENT_CRT_CSR
    INPUT_PATH_CRT_KEY_PEM=$PATH_CERTIFICATES$3$PATH_API_CLIENT_CRT_KEY_PEM
    INPUT_CRT_CONF=$PATH_CONFIG$PATH_CLIENT_CONF
elif [ "$1" = "api" ] && [ "$2" = "web" ] && [ -n "$3" ]
then
    INPUT_CA_KEY_PWD=$API_CA_KEY_PWD
    INPUT_CRT_KEY_PWD=$API_WEB_KEY_PWD
    INPUT_PATH_CA_CRT=$PATH_CERTIFICATES$PATH_API_CA_CRT
    INPUT_PATH_CA_KEY=$PATH_CERTIFICATES$PATH_API_CA_KEY
    INPUT_PATH_CRT=$PATH_CERTIFICATES$3$PATH_API_WEB_CRT
    INPUT_PATH_CRT_KEY=$PATH_CERTIFICATES$3$PATH_API_WEB_CRT_KEY
    INPUT_PATH_CRT_CSR=$PATH_CERTIFICATES$3$PATH_API_WEB_CRT_CSR
    INPUT_PATH_CRT_KEY_PEM=$PATH_CERTIFICATES$3$PATH_API_WEB_CRT_KEY_PEM
    INPUT_CRT_CONF=$PATH_CONFIG$PATH_WEB_CONF
elif [ "$1" = "cam" ] && [ "$2" = "broker" ] && [ -n "$3" ]
then
    INPUT_CA_KEY_PWD=$CAM_CA_KEY_PWD
    INPUT_CRT_KEY_PWD=$CAM_BROKER_KEY_PWD
    INPUT_PATH_CA_CRT=$PATH_CERTIFICATES$PATH_CAM_CA_CRT
    INPUT_PATH_CA_KEY=$PATH_CERTIFICATES$PATH_CAM_CA_KEY
    INPUT_PATH_CRT=$PATH_CERTIFICATES$3$PATH_CAM_BROKER_CRT
    INPUT_PATH_CRT_KEY=$PATH_CERTIFICATES$3$PATH_CAM_BROKER_CRT_KEY
    INPUT_PATH_CRT_CSR=$PATH_CERTIFICATES$3$PATH_CAM_BROKER_CRT_CSR
    INPUT_PATH_CRT_KEY_PEM=$PATH_CERTIFICATES$3$PATH_CAM_BROKER_CRT_KEY_PEM
    INPUT_CRT_CONF=$PATH_CONFIG$PATH_BROKER_CAM_CONF
elif [ "$1" = "cam" ] && [ "$2" = "client" ] && [ -n "$3" ] && [ -n "$4" ]
then
    INPUT_CA_KEY_PWD=$CAM_CA_KEY_PWD
    INPUT_CRT_KEY_PWD=$4
    INPUT_PATH_CA_CRT=$PATH_CERTIFICATES$PATH_CAM_CA_CRT
    INPUT_PATH_CA_KEY=$PATH_CERTIFICATES$PATH_CAM_CA_KEY
    INPUT_PATH_CRT=$PATH_CERTIFICATES$3$PATH_CAM_CLIENT_CRT
    INPUT_PATH_CRT_KEY=$PATH_CERTIFICATES$3$PATH_CAM_CLIENT_KEY
    INPUT_PATH_CRT_CSR=$PATH_CERTIFICATES$3$PATH_CAM_CLIENT_CRT_CSR
    INPUT_PATH_CRT_KEY_PEM=$PATH_CERTIFICATES$3$PATH_CAM_CLIENT_CRT_KEY_PEM
    INPUT_CRT_CONF=$PATH_CONFIG$PATH_CLIENT_CONF
else
    #echo " "
    #echo "Error handling inputs!"
    #echo " "
    exit 1
fi

INPUT_RSA_KEY_LENGTH=$RSA_KEY_LENGTH
INPUT_CRT_DAYS=$CRT_DAYS

#echo "Generating client private key"
#echo " "
$OPENSSL_CMD genpkey -pass pass:$INPUT_CRT_KEY_PWD -algorithm RSA -out $INPUT_PATH_CRT_KEY -pkeyopt rsa_keygen_bits:$INPUT_RSA_KEY_LENGTH -aes256
#echo " "

#echo " "
#echo "Generating certificate signing request for client"
#echo " "
$OPENSSL_CMD req -passin pass:$INPUT_CRT_KEY_PWD -new -key $INPUT_PATH_CRT_KEY -out $INPUT_PATH_CRT_CSR -config $INPUT_CRT_CONF
#echo " "

#echo " "
#echo "Generating RootCA signed broker certificate"
#echo " "
$OPENSSL_CMD x509 -req -days $INPUT_CRT_DAYS -in $INPUT_PATH_CRT_CSR -CA $INPUT_PATH_CA_CRT -CAkey $INPUT_PATH_CA_KEY -passin pass:$INPUT_CA_KEY_PWD -out $INPUT_PATH_CRT -CAcreateserial -extfile $INPUT_CRT_CONF -SHA256
#echo " "

#echo " "
#echo "Turning Keys To PEM"
$OPENSSL_CMD rsa -passin pass:$INPUT_CRT_KEY_PWD -in $INPUT_PATH_CRT_KEY -text > $INPUT_PATH_CRT_KEY_PEM
#echo " "

#echo " "
#echo "Deleting Unwanted Files"
rm -rf deployables/caCrt.srl
rm -rf $INPUT_PATH_CRT_CSR
#echo " "

exit 0
