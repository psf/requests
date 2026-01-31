import requests

def test_ipv6_zone_identifier_is_not_percent_encoded():
    session = requests.Session()
    url = "https://[fe80::1%eth0]/redfish/v1"
    req = requests.Request("GET", url)
    prepared = session.prepare_request(req)
    assert "%eth0" in prepared.url
    assert "%25eth0" not in prepared.url
