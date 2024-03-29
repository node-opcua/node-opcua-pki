const config =
    "#.........DO NOT MODIFY BY HAND .........................\n" +
    "[ ca ]\n" +
    "default_ca               = CA_default\n" +
    "[ CA_default ]\n" +
    "dir                      = %%ROOT_FOLDER%%            # the main CA folder\n" +
    "certs                    = $dir/certs                 # where to store certificates\n" +
    "new_certs_dir            = $dir/certs                 #\n" +
    "database                 = $dir/index.txt             # the certificate database\n" +
    "serial                   = $dir/serial                # the serial number counter\n" +
    "certificate              = $dir/public/cacert.pem     # The root CA certificate\n" +
    "private_key              = $dir/private/cakey.pem     # the CA private key\n" +
    "x509_extensions          = usr_cert                   #\n" +
    "default_days             = 3650                       # default validity : 10 years\n" +
    "\n" +
    "# default_md               = sha1\n" +
    "\n" +
    "default_md                = sha256                      # The default digest algorithm\n" +
    "\n" +
    "preserve                 = no\n" +
    "policy                   = policy_match\n" +
    "# randfile                 = $dir/random.rnd\n" +
    "# default_startdate        = YYMMDDHHMMSSZ\n" +
    "# default_enddate          = YYMMDDHHMMSSZ\n" +
    "crl_dir                  = $dir/crl\n" +
    "crl_extensions           = crl_ext\n" +
    "crl                      = $dir/revocation_list.crl # the Revocation list\n" +
    "crlnumber                = $dir/crlnumber           # CRL number file\n" +
    "default_crl_days         = 30\n" +
    "default_crl_hours        = 24\n" +
    "#msie_hack\n" +
    "\n" +
    "[ policy_match ]\n" +
    "countryName              = optional\n" +
    "stateOrProvinceName      = optional\n" +
    "localityName             = optional\n" +
    "organizationName         = optional\n" +
    "organizationalUnitName   = optional\n" +
    "commonName               = optional\n" +
    "emailAddress             = optional\n" +
    "\n" +
    "[ req ]\n" +
    "default_bits             = 4096                     # Size of keys\n" +
    "default_keyfile          = key.pem                  # name of generated keys\n" +
    "distinguished_name       = req_distinguished_name\n" +
    "attributes               = req_attributes\n" +
    "x509_extensions          = v3_ca\n" +
    "#input_password\n" +
    "#output_password\n" +
    "string_mask              = nombstr                  # permitted characters\n" +
    "req_extensions           = v3_req\n" +
    "\n" +
    "[ req_distinguished_name ]\n" +
    "\n" +
    "#0 countryName             = Country Name (2 letter code)\n" +
    "# countryName_default     = FR\n" +
    "# countryName_min         = 2\n" +
    "# countryName_max         = 2\n" +
    "# stateOrProvinceName     = State or Province Name (full name)\n" +
    "# stateOrProvinceName_default = Ile de France\n" +
    "# localityName            = Locality Name (city, district)\n" +
    "# localityName_default    = Paris\n" +
    "organizationName          = Organization Name (company)\n" +
    "organizationName_default  = NodeOPCUA\n" +
    "# organizationalUnitName  = Organizational Unit Name (department, division)\n" +
    "# organizationalUnitName_default = R&D\n" +
    "commonName                = Common Name (hostname, FQDN, IP, or your name)\n" +
    "commonName_max            = 256\n" +
    "commonName_default        = NodeOPCUA\n" +
    "# emailAddress            = Email Address\n" +
    "# emailAddress_max        = 40\n" +
    "# emailAddress_default    = node-opcua (at) node-opcua (dot) com\n" +
    "\n" +
    "[ req_attributes ]\n" +
    "#challengePassword        = A challenge password\n" +
    "#challengePassword_min    = 4\n" +
    "#challengePassword_max    = 20\n" +
    "#unstructuredName         = An optional company name\n" +
    "[ usr_cert ]\n" +
    "basicConstraints          = critical, CA:FALSE\n" +
    "subjectKeyIdentifier      = hash\n" +
    "authorityKeyIdentifier    = keyid,issuer:always\n" +
    "#authorityKeyIdentifier    = keyid\n" +
    "subjectAltName            = $ENV::ALTNAME\n" +
    "# issuerAltName            = issuer:copy\n" +
    "nsComment                 = ''OpenSSL Generated Certificate''\n" +
    "#nsCertType               = client, email, objsign for ''everything including object signing''\n" +
    "#nsCaRevocationUrl        = http://www.domain.dom/ca-crl.pem\n" +
    "#nsBaseUrl                =\n" +
    "#nsRenewalUrl             =\n" +
    "#nsCaPolicyUrl            =\n" +
    "#nsSslServerName          =\n" +
    "keyUsage                  = critical, digitalSignature, nonRepudiation," +
    " keyEncipherment, dataEncipherment, keyAgreement, keyCertSign\n" +
    "extendedKeyUsage          = critical,serverAuth ,clientAuth\n" +
    "\n" +
    "[ v3_req ]\n" +
    "basicConstraints          = critical, CA:FALSE\n" +
    "keyUsage                  = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement\n" +
    "extendedKeyUsage          = critical,serverAuth ,clientAuth\n" +
    "subjectAltName            = $ENV::ALTNAME\n" +
    "nsComment                 = \"CA Generated by Node-OPCUA Certificate utility using openssl\"\n" +
    "[ v3_ca ]\n" +
    "subjectKeyIdentifier      = hash\n" +
    "authorityKeyIdentifier    = keyid:always,issuer:always\n" +
    "# authorityKeyIdentifier    = keyid\n" +
    "basicConstraints          = CA:TRUE\n" +
    "keyUsage                  = critical, cRLSign, keyCertSign\n" +
    "nsComment                 = \"CA Certificate generated by Node-OPCUA Certificate utility using openssl\"\n" +
    "#nsCertType                 = sslCA, emailCA\n" +
    "#subjectAltName             = email:copy\n" +
    "#issuerAltName              = issuer:copy\n" +
    "#obj                        = DER:02:03\n" +
    "crlDistributionPoints     = @crl_info\n" +
    "[ crl_info ]\n" +
    "URI.0                     = http://localhost:8900/crl.pem\n" +
    "[ v3_selfsigned]\n" +
    "basicConstraints          = critical, CA:FALSE\n" +
    "keyUsage                  = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement\n" +
    "extendedKeyUsage          = critical,serverAuth ,clientAuth\n" +
    "nsComment                 = \"Self-signed certificate, generated by NodeOPCUA\"\n" +
    "subjectAltName            = $ENV::ALTNAME\n" +
    "\n" +
    "[ crl_ext ]\n" +
    "#issuerAltName            = issuer:copy\n" +
    "authorityKeyIdentifier    = keyid:always,issuer:always\n" +
    "#authorityInfoAccess       = @issuer_info";

export default config;
