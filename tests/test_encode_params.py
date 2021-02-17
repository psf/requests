# -*- coding: utf-8 -*-
from collections import OrderedDict

from requests.utils import unfold_complex_data_key


def test_util_unfold_complex_data_key():
    data = OrderedDict({
        "id": "857-37-9333",
        "label": u"周",
        "count": 0,
        "properties": {
            "name": "Rich Hintz",
            "city": "New Edythstad",
            "gender": "male",
            "age": 24,
            "profile": [
                "Zondy",
                "ZTESoft",
                "YunWen",
                "Ci123"
            ]
        }
    })

    result = []
    unfold_complex_data_key(None, data, result)
    expert_result = [
        (b'id', b'857-37-9333'),
        (b'label', b'\xe5\x91\xa8'),
        (b'count', 0),
        (b'properties[name]', b'Rich Hintz'),
        (b'properties[city]', b'New Edythstad'),
        (b'properties[gender]', b'male'),
        (b'properties[age]', 24),
        (b'properties[profile][0]', b'Zondy'),
        (b'properties[profile][1]', b'ZTESoft'),
        (b'properties[profile][2]', b'YunWen'),
        (b'properties[profile][3]', b'Ci123')
    ]
    assert result == expert_result
