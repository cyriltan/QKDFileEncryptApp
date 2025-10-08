# QKDFileEncryptApp
This code seeks to demonstrate how one can pull QKD keys from the Toshiba KMS emulator using ETSI GS QKD 014 interface and using the keys to encrypt a file. It further demonstrates how one can generate a digital signature on the encrypted file using PQC algorithm ML-DSA.

To run this code, you need to install the open quantum safe library that runs the PQC algorithms. You need to install the following:
https://github.com/open-quantum-safe/liboqs-python

Follow the instructions to liboqs. Run the following to use in standalone applications.
```bash
export PYTHONPATH=$PYTHONPATH:/path/to/liboqs-python
```

Next, modify the FileEncryptApp to point the ETSI GS QKD 014 API call to where the certificates are stored on your machine. You have to modify the enc_url as well as the URL inside the DecodeQKDkey function.

Run the FileEncryptApp.


For troubleshooting, you can run the following command in your linux terminal to make sure you can do a key pull.
```bash
curl https://ec2-3-113-86-199.ap-northeast-1.compute.amazonaws.com/api/v1/keys/SA00000006/enc_keys --cacert /home/certificates/KMSEmulator/cacert.crt --cert /home/certificates/KMSEmulator/SA00000007.crt --key /home/certificates/KMSEmulator/SA00000007.key 
```

```bash
curl https://ec2-52-197-156-199.ap-northeast-1.compute.amazonaws.com/api/v1/keys/SA00000007/dec_keys?key_ID=xxx  --cacert /home/certificates/KMSEmulator/cacert.crt --cert /home/certificates/KMSEmulator/SA00000006.crt --key /home/certificates/KMSEmulator/SA00000006.key 
```

Note: Please change the locations of the certificates above accordingly. For getting the decryption key, you also need to provide the correct key index specified inside key_ID. 
