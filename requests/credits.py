from base64 import b64decode
import sys
import zlib

DATA = ("eJyFl1lywyAMht99FRgOoBkNz76Uzl4tSIjFqZo2rp18/rWCn25WulspBWrjH"
        "7aWrdqvvNiKGaK+6ff08JF3lD+9GBSp6teqvhai4eywQgL2BOzZ+GRVE6ARWt"
        "1EzuPqwN4XhRmIzWgteD+sVroB+4iGnAPXV0+Hr0S4Aac+ClRdHKztk03kLs4"
        "YBrLUaRZ45+wJTyLhG6jVol8NYkrqJ5E2l6fHFOLG3zaVfgD18kfZFATIQA9n"
        "8L4lOmAAPQTOq8EI9g+PhYim0HpmAEviLamZgr8zXa3mHDgFrkjIUo+eWQy0c"
        "U9gPYAtBeDbZ830DbgwQVmU6d92AzJuZsVVxSm++O1xa+Xict1iSFzmfmIMM3"
        "Pvwq0HUIeq6AlphOE7EMGQ7wnfTOpmA6K7bF8hZIEMNRQjEfk4uDv1ApQ+mTw"
        "g0FALxoEgk4XAci+nqEQ14RnDgjRurnOTfZdPkbSjeExM5OE7IhZ5AoVrTlag"
        "Jj3CpCXOQL6HeE5iKMYVDDpVJSgkwdW7S++tCnVp8NnQrNdrk3N6RXh6RxGN6"
        "q+6zC9Z/ECrcAfyv/wJJZb+CrFZaM30HSw0TVFm3HPUbkBheqH0V0yJtk4Onk"
        "qX+7bBK6ycqpb1FkNbpNgL6TQwoCAtVZYRn6JopURhI8lnUnhFVonwTqDfS8P"
        "p9TVZUqcMrIfCGA/sAdT3zcjJ0zMjSZMIYzL4wM5AjjUXSbg8NUoENVNvD4HM"
        "1XRJWXwAZdXjdZuuwIJdi00KE6MwFQhkLl+BfA3fdyfOHVaXLGUeGS8rTDsJG"
        "Ti9nMDApQAGEMsJ9Exap/QN2DMPcQGOJroB9W6257rzXu95nMTJK92bai70Bc"
        "c4OXicY4mepMarL3gOLAdQC0eBfQ2hDJ2ZbrI5OyYulcOeGWBpP1WYmq/nJhk"
        "q3OPkcAZuq3GdLken9EhJip4e9wsQQWchjPVCYzgk9tdjMfVRaLwLHEAvKp3Y"
        "qm1mJeW6IGbeJYIMlEXDRjDUmWVt3IOIJeOoXDzmOoQqNckN5Yviu6tbFFIgY"
        "5HfgJXnIC/Lc4d+BcYci+mfdw68zng8Hz83Nz65qheHZ/wg41Z7fAzFmf5miV"
        "Y2a0J0/fwE2mdLPEBg31yeMBw7idXfG5BtPOrwY0ffianpfAH95onLUqHNd4U"
        "C7HtSTGRaS34Ba3pq0r1b773vSV4T/Mvj9thF3yfJHDkqxokB/LU9HmXjO1UJ"
        "efmP90tge/4AipGf6g==")

sys.stdout.write(zlib.decompress(b64decode(DATA)))
