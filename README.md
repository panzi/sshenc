sshenc
======

Encrypt/decrypt files using an SSH RSA key.

Inspired by: https://yurichev.com/n/SSH_encrypt/

Usage
-----

```
usage: sshenc.py encrypt [-h] [-o FILE] pubkey file

positional arguments:
  pubkey
  file

options:
  -h, --help            show this help message and exit
  -o FILE, --output FILE
                        Write output to FILE instead of stdout.
```

```
usage: sshenc.py decrypt [-h] [-p | -P PASSWORD | --passfile FILE | --passenv NAME] [-o FILE] privkey file

positional arguments:
  privkey
  file

options:
  -h, --help            show this help message and exit
  -p, --passprompt      Prompt for password.
  -P PASSWORD, --password PASSWORD
                        Pass password as argument.
  --passfile FILE       Read password from FILE.
  --passenv NAME        Use environment variable NAME as password.
  -o FILE, --output FILE
                        Write output to FILE instead of stdout.
```
