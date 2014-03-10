#!/bin/bash - 
#===============================================================================
#
#          FILE:  test-ciphers.sh
# 
#         USAGE:  ./test-ciphers.sh 
# 
#   DESCRIPTION:  
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR: George Kola (), georgekola@gmail.com
#       COMPANY: 
#       CREATED: 03/08/2014 10:36:42 PM PST
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

if [ $# -ne 1 ] ; then
    echo "Usage: " $0  ' host:port'
    exit 1
fi

# OpenSSL requires the port number.
SERVER_PORT=$1

ciphers=$(openssl ciphers 'ALL:eNULL' | sed -e 's/:/ /g')

echo Obtained cipher list from $(openssl version).

for cipher in ${ciphers[@]}
do
echo -n Testing $cipher...
result=$(echo -n | openssl s_client -cipher "$cipher" -connect $SERVER_PORT 2>&1)
if [[ "$result" =~ "Cipher is ${cipher}" ]] ; then
  echo YES
else
  if [[ "$result" =~ ":error:" ]] ; then
    error=$(echo -n $result | cut -d':' -f6)
    echo NO \($error\)
  else
    echo UNKNOWN RESPONSE
    echo $result
  fi
fi
done
