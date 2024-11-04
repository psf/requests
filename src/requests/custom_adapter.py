from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter

class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            cert_reqs='CERT_REQUIRED',
            ca_certs='/path/to/your/ca-certificates.crt'  # Update this path to your CA certificates file
        )
