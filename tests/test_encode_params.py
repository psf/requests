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
    assert result.__str__() == "[('count', 0), ('properties[profile][0]', 'Zondy'), ('properties[profile][1]', 'ZTESoft'), ('properties[profile][2]', 'YunWen'), ('properties[profile][3]', 'Ci123'), ('properties[city]', 'New Edythstad'), ('properties[age]', 24), ('properties[name]', 'Rich Hintz'), ('properties[gender]', 'male'), ('id', '857-37-9333'), ('label', u'\u5468')]"
