import sys

# This code exists for backwards compatibility reasons.
# I don't like it either. Just look the other way. :)

for _package in ('urllib3', 'idna', ('cchardet', 'chardet')):
    if isinstance(_package, tuple):
        package = _package[1]
        try:
            locals()[package] = __import__(package[0])
        except (ImportError, SyntaxError):
            locals()[package] = __import__(package)
    else:
        package = _package
        locals()[package] = __import__(package)

    # This traversal is apparently necessary such that the identities are
    # preserved (requests.packages.urllib3.* is urllib3.*)
    for mod in list(sys.modules):
        if mod == package or mod.startswith(package + '.'):
            sys.modules['requests.packages.' + mod] = sys.modules[mod]

# Kinda cool, though, right?
