#!/home/brokerregistry/bin/bash
. /home/brokerregistry/etc/certificates.conf

if [ "$1" = "cam" ]
then
    INPUT_CA_KEY_PWD=$CAM_CA_KEY_PWD
    INPUT_PATH_CA_CRT=$PATH_CERTIFICATES$PATH_CAM_CA_CRT
    INPUT_PATH_CA_KEY=$PATH_CERTIFICATES$PATH_CAM_CA_KEY
    INPUT_PATH_CA_KEY_PEM=$PATH_CERTIFICATES$PATH_CAM_CA_KEY_PEM
    
elif [ "$1" = "api" ]
then
    INPUT_CA_KEY_PWD=$API_CA_KEY_PWD
    INPUT_PATH_CA_CRT=$PATH_CERTIFICATES$PATH_API_CA_CRT
    INPUT_PATH_CA_KEY=$PATH_CERTIFICATES$PATH_API_CA_KEY
    INPUT_PATH_CA_KEY_PEM=$PATH_CERTIFICATES$PATH_API_CA_KEY_PEM
else
    ##echo " "
    ##echo "Error handling inputs!"
    ##echo " "
    exit 1
fi

INPUT_RSA_KEY_LENGTH=$RSA_KEY_LENGTH
INPUT_PATH_CA_CONF=$PATH_CONFIG$PATH_CA_CONF


#echo " "
#echo "Generating CA's private key"
#echo " "
$OPENSSL_CMD genpkey -algorithm RSA -out $INPUT_PATH_CA_KEY -pkeyopt rsa_keygen_bits:$INPUT_RSA_KEY_LENGTH -aes256 -pass pass:$INPUT_CA_KEY_PWD
#echo " "

#echo " "
#echo "Generating CA's certificate"
#echo " "
$OPENSSL_CMD req -new -x509 -days $CA_DAYS -key $INPUT_PATH_CA_KEY -out $INPUT_PATH_CA_CRT -config $INPUT_PATH_CA_CONF -SHA256 -passin pass:$INPUT_CA_KEY_PWD
#echo " "

#echo " "
#echo "Verify RootCA certificate"
#echo " "
$OPENSSL_CMD  x509 -noout -text -in $INPUT_PATH_CA_CRT
#echo " "

#echo " "
#echo "Turning Keys To PEM"
$OPENSSL_CMD rsa -passin pass:$INPUT_CA_KEY_PWD -in $INPUT_PATH_CA_KEY -text > $INPUT_PATH_CA_KEY_PEM
#echo " "

#echo " "
#echo "Deleting Unwanted Files"
rm -rf bin/deployables/caCrt.srl
#echo " "

exit 0
