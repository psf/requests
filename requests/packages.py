import sys

# This code exists for backwards compatibility reasons.
# I don't like it either. Just look the other way. :)

for package, alias in (('urllib3', 'urllib3'), ('idna', 'idna'), ('charset_normalizer', 'chardet')):
    locals()[package] = __import__(package)
    locals()[alias] = locals()[package]
    # This traversal is apparently necessary such that the identities are
    # preserved (requests.packages.urllib3.* is urllib3.*)
    for mod in list(sys.modules):
        if mod == package or mod.startswith(package + '.'):
            sys.modules['requests.packages.' + mod.replace(package, alias)] = sys.modules[mod]

# Kinda cool, though, right?
