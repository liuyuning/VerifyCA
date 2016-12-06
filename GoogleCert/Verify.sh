#!/bin/bash

# Created by liuyuning on 2016/12/2.
# Copyright © 2016年 liuyuning. All rights reserved.


#Convert DER to PEM
openssl x509 -in 'GeoTrust Global CA.cer' -inform DER -out 'GeoTrust Global CA.pem'
openssl x509 -in 'Google Internet Authority G2.cer' -inform DER -out 'Google Internet Authority G2.pem'
openssl x509 -in '*.google.com.hk.cer' -inform DER -out '*.google.com.hk.pem'

#Verify each cert
openssl verify -CAfile 'GeoTrust Global CA.pem' 'GeoTrust Global CA.pem'
openssl verify -CAfile 'GeoTrust Global CA.pem' 'Google Internet Authority G2.pem'
openssl verify -CAfile 'GeoTrust Global CA.pem' -untrusted 'Google Internet Authority G2.pem' '*.google.com.hk.pem'

#Verify without root cert
openssl verify -untrusted 'Google Internet Authority G2.pem' '*.google.com.hk.pem'


#Get pub key from root cert "GeoTrust Global CA.cer"
#openssl x509 -in 'GeoTrust Global CA.cer' -inform DER -pubkey -noout > GeoTrust_Global_CA_pub_key.pem

#Convert pub key PEM to DER
#openssl rsa -in GeoTrust_Global_CA_pub_key.pem -pubin -outform DER -out GeoTrust_Global_CA_pub_key.der

#Display cert content
#openssl x509 -in 'Google Internet Authority G2.cer' -inform DER -text -noout
