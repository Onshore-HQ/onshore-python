# Onshore SDK for Python

The Onshore server SDK for Python 3.9+. It stores sensitive values in your in-country vault and gives you tokens back, reveals them as your access rules allow, and covers records, lookups, data subject requests, resident checks, detection, flow checks, client tokens, cloaking for AI and webhook signatures. Reveals fail closed.

## Install

```sh
pip install "onshore @ git+https://github.com/Onshore-HQ/onshore-python@v0.1.0"
```

```python
import os
from onshore import VaultClient

vault = VaultClient(
    base_url=os.environ["ONSHORE_URL"],
    service_account_id=os.environ["ONSHORE_SA_ID"],
    key_id=os.environ["ONSHORE_KEY_ID"],
    private_key=os.environ["ONSHORE_PRIVATE_KEY"],
)
```

## Documentation

Full reference, with every method, parameter, return value and error: https://docs.onshorevault.com/developers/sdks/python/
