### node-opcua-pki


[![Build Status](https://travis-ci.org/node-opcua/node-opcua-pki.png?branch=master)](https://travis-ci.org/node-opcua/node-opcua-pki)
[![Code Climate](https://codeclimate.com/github/node-opcua/node-opcua-pki/badges/gpa.svg)](https://codeclimate.com/github/node-opcua/node-opcua-pki)
[![Test Coverage](https://codeclimate.com/github/node-opcua/node-opcua-pki/badges/coverage.svg)](https://codeclimate.com/github/node-opcua/node-opcua-pki/coverage)



#### Create a Certificate Authority

```
    PKI\CA                   Certificate Authority

    PKI\rejected             Certificates that are rejected - regardless of validity
    PKI\trusted
    PKI\issuers
    PKI\issuers\crl
    PKI\issuers\certs
```

#### commands

|command      |Help                                           |
|-------------|-----------------------------------------------|
|demo         |create default certificate for node-opcua demos|
|createCA     |create a Certificate Authority                 |
|createPKI    |create a Public Key Infrastructure             |
|certificate  |create a new certificate                       |
|revoke       |revoke a existing certificate                  |
|dump         |display a certificate                          |
|toder        |convert a certificate to a DER format          |
|fingerprint  |print the certifcate fingerprint               |

Options:
  --help  display help

