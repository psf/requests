#from ../src/requests import sessions
#import json
import pytest

#a=sessions.Session()
#def test_post():
#	r=(sessions.Session.post(self=a,url='https://httpbin.org/post', data=None, json=2))
#	return r

#def test_get():
#        r=(sessions.Session.get(self=a,url='https://httpbin.org/post'))
#        return r

#test_post()


@pytest.mark.SPEC001
def test_add():
	return (1+1)

@pytest.mark.SPEC002
@pytest.mark.SPEC001
def test_add2():
	return(1+2)



#def test_add3():
#	return(1+3)
