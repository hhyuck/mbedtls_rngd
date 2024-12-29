README for RNGD
===================

BUILD
-------------

In order to build from the source code, follow the commands:

	mkdir build
    cd build
	cmake ..
	make


RUN
-------------

If you don't have the CA key, generate the key for CA:

    cd build
	programs/pkey/gen_key type=ec filename=RNGD_INTER_CA.key ec_curve=secp384r1 

In order to test rngd_cert_app, generate the key for the RNGD sample:

    cd build
	programs/pkey/gen_key type=ec filename=RNGD.key ec_curve=secp384r1 

In order to generate the RNGD cert file, enter:

    cd build
    programs/x509/rngd_cert_app

You can see the detailed information by using the following command:

    cd build
	openssl x509 -in RNGD.crt -noout -text

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: CN = RNGD INTER CA, O = FuriosaAI, C = KR
        Validity
            Not Before: Jan  1 00:00:00 2025 GMT
            Not After : Dec 31 23:59:59 2035 GMT
        Subject: CN = RNGD, O = FuriosaAI, C = KR
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:fe:bf:3c:bb:6a:c1:b9:61:73:02:86:9e:2b:e7:
                    67:04:7a:0d:23:ad:de:59:d3:66:1a:67:b1:ec:34:
                    f3:09:e6:73:25:ee:ec:d8:76:73:04:21:8f:96:27:
                    9b:88:a4:9b:6e:7f:06:01:2c:78:dc:24:25:4c:25:
                    76:f4:41:ab:4a:88:1b:93:53:0b:83:02:52:c9:bd:
                    a9:de:d9:d1:ef:2e:6f:ae:d6:a5:7f:5e:5d:04:b1:
                    8b:9f:df:c2:73:aa:d1
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Subject Key Identifier:
                9F:F5:3E:84:4C:29:85:3E:BA:AC:40:70:C7:09:03:6A:71:C1:AC:D6
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage: critical
                TLS Web Server Authentication, TLS Web Client Authentication, OCSP Signing
            X509v3 Subject Alternative Name:
                othername: 1.3.6.1.4.1.412.274.1::FuriosaAI:RNGD:00001
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:66:02:31:00:bd:a3:88:98:25:c8:2d:b8:60:31:30:02:33:
        a8:ce:f5:c4:1d:b0:21:b3:1d:83:05:17:6d:18:d7:55:90:6a:
        c4:91:4b:3e:64:d3:b1:e2:27:19:11:5c:23:58:ef:12:9b:02:
        31:00:b6:4a:9a:4b:0a:b2:94:d1:70:7e:56:8a:8e:a6:82:60:
        c0:88:1b:b4:99:bc:ef:ce:16:3d:ac:8c:04:73:b1:5c:3f:bf:
        c8:bc:77:ab:87:7d:2e:8f:7c:2a:3c:96:c1:4d
```
