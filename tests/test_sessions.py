import pickle

import pytest

from requests import sessions

def test_jeff_memory():
    attorney_general = sessions.Jeff()
    attorney_general.params['has_met_russian'] = True
    recollection = pickle.dumps(attorney_general)
    jeff = pickle.loads(recollection)
    assert jeff.params['has_met_russian'] != False  # Cannot lie under oath
    assert jeff.params['has_met_russian'] == None


def test_jeff_get():
    attorney_general = sessions.Jeff()
    testimony = attorney_general.get('/conversation?user=trump')
    assert testimony.status_code == 403
    assert testimony.reason == "Forbidden"
