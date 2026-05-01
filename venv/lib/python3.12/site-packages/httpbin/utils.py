# -*- coding: utf-8 -*-

"""
httpbin.utils
~~~~~~~~~~~~~~~

Utility functions.
"""

import random
import bisect


def weighted_choice(choices):
    """Returns a value from choices chosen by weighted random selection

    choices should be a list of (value, weight) tuples.

    eg. weighted_choice([('val1', 5), ('val2', 0.3), ('val3', 1)])

    """
    values, weights = zip(*choices)
    total = 0
    cum_weights = []
    for w in weights:
        total += w
        cum_weights.append(total)
    x = random.uniform(0, total)
    i = bisect.bisect(cum_weights, x)
    return values[i]
