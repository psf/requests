# We don't use any other decodings than UTF-8, so we can short circuit
# this one call and delete the rest of this bulky library in its entirety.

def detect(aBuf):
    return {'encoding': 'utf-8'}
