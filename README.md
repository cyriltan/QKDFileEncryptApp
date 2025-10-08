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
