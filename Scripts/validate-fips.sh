#!/bin/bash - 
#===============================================================================
#
#          FILE:  validate-fips.sh
# 
#         USAGE:  ./validate-fips.sh <server-ip:port>
# 
#   DESCRIPTION:  This scripts checks if the server supports only FIPS 140-2 compliant
#                 ciphers
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR: George Kola (), georgekola@gmail.com
#       COMPANY: 
#       CREATED: 03/08/2014 11:16:52 PM PST
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

if [ $# -ne 1 ] ; then
    echo "Usage: " $0  ' host:port'
    exit 1
fi


# OpenSSL requires the port number.
SERVER_PORT=$1
DELAY=1
ciphers=$(openssl ciphers 'ALL:eNULL' | sed -e 's/:/ /g')
fipsciphers=$(openssl ciphers FIPS)
fipsdetails=$(openssl ciphers FIPS -v)

SupportedCiphers=""
SupportedFIPSCiphers=""
SupportedNonFIPSCiphers=""

printf "Obtained cipher list from $(openssl version)\n\n"
printf "Testing using openssl s_client\n\n"

for cipher in ${ciphers[@]}
do
#echo -n Testing $cipher...
result=$(echo -n | openssl s_client -cipher "$cipher" -connect $SERVER_PORT 2>&1)
if [[ "$result" =~ "Cipher is ${cipher}" ]] ; then
    SupportedCiphers="$SupportedCiphers $cipher"
    if [ "${fipsciphers/$cipher}" = "$fipsciphers" ] ; then
        status="Not FIPS Compliant"
        SupportedNonFIPSCiphers="$SupportedNonFIPSCiphers $cipher"
    else
        status="FIPS Compliant"
        SupportedFIPSCiphers="$SupportedFIPSCiphers $cipher"
    fi
#  echo  YES $status

else
  if [[ "$result" =~ ":error:" ]] ; then
    error=$(echo -n $result | cut -d':' -f6)
#    echo NO \($error\)
  else
    echo UNKNOWN RESPONSE
    echo $result
  fi
fi
#sleep $DELAY
done

if [ "$SupportedNonFIPSCiphers" == "" ] ; then
    printf "SUCCESS! $SERVER_PORT is FIPS Validated!  \n\n"
    printf "Tested Ciphers: $ciphers \n\n"
    printf  "FIPS Compliant Ciphers Supported: $SupportedFIPSCiphers\n\n"
    printf  "FIPS Compliant Ciphers Supported Details: \n\n"
    for i in $SupportedFIPSCiphers ; do
        #printf $i;
        printf "$fipsdetails" | grep -w ^"$i"
    done
    printf "\n\n"
    exit 0;
else
    printf "FAILURE! $SERVER_PORT has  non FIPS compliant Ciphers"
    printf "Tested Ciphers: $ciphers\n"
    printf  "Non FIPS Compliant Ciphers Supported: " $SupportedNonFIPSCiphers
    printf  "FIPS Compliant Ciphers Supported: " $SupportedFIPSCiphers
    printf  "All Supported Ciphers: " $SupportedCiphers
    exit 1;
fi

