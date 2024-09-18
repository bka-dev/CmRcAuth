# CmRcAuth

CmRcAuth checks login credentials against the "Configuration Manager Remote Control" service (CmRcService.exe) that is used in MECM/SCCM deployments and by default running on TCP port 2701.

## Requirements

The Python ntlm-auth library utilizes Hashlib for performing the necessary steps for NTLMSSP authentication.
Therefore it requires MD4, which in current versions of OpenSSL is disabled.

A workaround is to enable legacy ciphers in /etc/ssl/openssl.cnf, however this seem to have negative side effects on other services of the operating system.

A recommendation would be to enable legacy ciphers, execute the tool and disable legacy ciphers afterwards.

## Installation

```bash
git clone https://github.com/bka-dev/CmRcAuth.git
cd CmRcAuth`
pip3 install -r requirements.txt
```

## Usage

Check authentication against a single host:

`CmRcAuth.py -u <USERNAME> -d <DOMAIN> -f <IP>`

Check authentication against multiple hosts read from an input file:

`CmRcAuth.py -u <USERNAME> -d <DOMAIN> -f <FILE>`
