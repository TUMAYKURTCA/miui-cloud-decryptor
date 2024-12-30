# Xiaomi gallery hidden files decrypter (.lsa/.lsav)
## How does it work?
MIUI gallery app uses AES for encrypting its photos/videos in CTR mode using the IV `byte[] sAesIv = {17, 19, 33, 35, 49, 51, 65, 67, 81, 83, 97, 102, 103, 104, 113, 114};` and the first 16 bytes of the gallery apk's RSA signature as the key. This tool can decrypt files using the same values
## Usage
First, install requirements
```
pip install -r requirements
```
And then
```
python ./miui-cloud-decrypt.py <one single file .lsa or .lsav / directory of .lsa and .lsav files>
```
## Important note
The encrypted file must have the following name: `<file name>.<md5 of key>.lsa` and if the md5 of the key is `3e751332435bfad27569ca4efed1b602` it probably will be 100% decrypted but if not it probably won't decrypt the file correctly. You'll have to change `secretKey` to the first 16 bytes of the gallery apk's RSA signature (META-INF/CERT.RSA or META-INF
