# -*- coding: utf-8 -*-
"""

"""

from concurrent.futures import ThreadPoolExecutor
from .sessions import Session

class FuturesSession(Session):

    def __init__(self, executor=None, *args, **kwargs):
        """
        NOTE: ProcessPoolExecutor is not supported b/c response objects are not
        picklable
        """
        super(FuturesSession, self).__init__(*args, **kwargs)
        if executor is None:
            executor = ThreadPoolExecutor(max_workers=2)
        self.executor = executor

    def request(self, *args, **kwargs):
        """
        background_callback param allows you to do some processing on the
        response in the background, e.g. call resp.json() so that json parsing
        happens in the background thread.
        """
        sup = super(FuturesSession, self).request

        if 'background_callback' in kwargs:
            def wrap(*args_, **kwargs_):
                background_callback = kwargs_['background_callback']
                del kwargs_['background_callback']
                resp = sup(*args_, **kwargs_)
                background_callback(self, resp)
                return resp

            return self.executor.submit(wrap, *args, **kwargs)

        return self.executor.submit(sup, *args, **kwargs)
