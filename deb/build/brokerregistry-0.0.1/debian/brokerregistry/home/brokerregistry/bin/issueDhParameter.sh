#!/home/brokerregistry/bash
. /home/brokerregistry/etc/certificates.conf

echo " "
echo "Generating dh parameters"
echo " "
$OPENSSL_CMD dhparam -out $PATH_DH_PARAM $DH_PARAM_LENGTH
$CHMOD_CMD $CMOD_OCATA_DH_PARAM $PATH_DH_PARAM

exit 0
