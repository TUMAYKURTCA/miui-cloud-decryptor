# Xiaomi gallery hidden files decryptor (.lsa/.lsav)
## How does it work?
MIUI gallery app uses AES for encrypting its photos/videos in CTR mode using the IV `byte[] sAesIv = {17, 19, 33, 35, 49, 51, 65, 67, 81, 83, 97, 102, 103, 104, 113, 114};` and the first 16 bytes of the gallery apk's certificate as the key
## Usage
First, install requirements
```
pip install -r requirements.txt
```
And then
```
python ./miui-cloud-decrypt.py <one single file .lsa or .lsav / directory of .lsa and .lsav files>
```
## Important note
The encrypted file must have the following name: `<file name>.<md5 of key>.lsa` and if the md5 of the key is `3e751332435bfad27569ca4efed1b602` it probably will be 100% decrypted but if not it probably won't decrypt the file correctly. You'll have to change `secretKey` to the first 16 bytes of the gallery apk's certificate:
```
keytool.exe -printcert -rfc -jarfile com.miui.gallery.apk
```
Outputs:
```
Certificate #1:
Certificate owner: EMAILADDRESS=miui@xiaomi.com, CN=MIUI, OU=MIUI, O=Xiaomi, L=Beijing, ST=Beijing, C=CN

-----BEGIN CERTIFICATE-----
MIIEbDCCA1SgAwIBAgIJAOVSqOy5ARt8MA0GCSqGSIb3DQEBBQUAMIGAMQswCQYD
VQQGEwJDTjEQMA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzEPMA0G
A1UEChMGWGlhb21pMQ0wCwYDVQQLEwRNSVVJMQ0wCwYDVQQDEwRNSVVJMR4wHAYJ
KoZIhvcNAQkBFg9taXVpQHhpYW9taS5jb20wHhcNMTExMjA2MDMyNjI2WhcNMzkw
NDIzMDMyNjI2WjCBgDELMAkGA1UEBhMCQ04xEDAOBgNVBAgTB0JlaWppbmcxEDAO
BgNVBAcTB0JlaWppbmcxDzANBgNVBAoTBlhpYW9taTENMAsGA1UECxMETUlVSTEN
MAsGA1UEAxMETUlVSTEeMBwGCSqGSIb3DQEJARYPbWl1aUB4aWFvbWkuY29tMIIB
IDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAx4ZWipr/JTrXTF0+b7/6Ev7U
TNMkTxiWDsVRG7VR5BMRUZcjSEURLMPfm7rNPg9LNSjNh+05fVd9yQCOnLxqJfwG
ZNOj9EAkN4bbiyUNQPbxSMmjzW+8LdjSQDm9aolyob3uKMMIeYv6m7O1SYd7EPmO
Jl8RjAXyZFN9leKTORV7nSoxSF4MgjUhzKbQtyGoQyYAB21mniCsQ6pYi1LBHCpR
8ExrsxrWroVzmRr+jklX1UlZH8uD7GLR2jWxcn3GtjABpe84e1pxhsHmjaEyV3K1
MHsbxznvI2ue/gbVLcrx4ydo40A+VePsVgKM9WgM+zOXHM94cFcrxH0+Ov+jhQIB
A6OB6DCB5TAdBgNVHQ4EFgQUka4vjHLjBfkqqfdFLioxYLhBoVwwgbUGA1UdIwSB
rTCBqoAUka4vjHLjBfkqqfdFLioxYLhBoVyhgYakgYMwgYAxCzAJBgNVBAYTAkNO
MRAwDgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMQ8wDQYDVQQKEwZY
aWFvbWkxDTALBgNVBAsTBE1JVUkxDTALBgNVBAMTBE1JVUkxHjAcBgkqhkiG9w0B
CQEWD21pdWlAeGlhb21pLmNvbYIJAOVSqOy5ARt8MAwGA1UdEwQFMAMBAf8wDQYJ
KoZIhvcNAQEFBQADggEBADs6aZzrSXMA8quGy9QcUTRAv2CqXEOYTrHaFA7zBUTZ
+7s3M98ksm8nA9f/xkW/WYpeYCNZapR+kXMVQvLCadCBamnJLfm/6LHJvDxUxGwS
NVu0Yp/mAgyp0V+NYVXcVYb1YW24BuzqLQa9g+MrXxP1oE/j5apRTwXfPVVVJsY9
PWKs8Are6JS5I8JpjcVxvFLHVv+noiIdg00Qy3F1yGTDCHL+IXwxRC3/AECmei+x
yLpj6sLVuj2OdrT/Kkmw24oz70rg3QqEDdKocUy1UxpWt4aBnsnrEFHZGyP94GvZ
0HCPFQxPnv5qQWykpeDCOpUq+TGtNXn7SosZ3pj2S9k=
-----END CERTIFICATE-----
```
And after converting from base 64 to hex: `3082046c30820354a003020102020900.....`. Now use it in python:
```py
secretKey = bytes.fromhex('3082046c30820354a003020102020900')
```

Thank you for reading <3
