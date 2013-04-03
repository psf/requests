Requests: HTTP for Humans (now with source_address support)
===========================================================

Fork of Kenneth Reitz's fantastic Requests library with source_address support (and a forked version of the included urllib3 that's included with requests).

This means that this fork is only compatible with Python 2.7, when HTTPConnection added source_address support (and I have not yet tested it on 3.3). This first draft is a little specific to my Python 2.7 needs and I'll wait for feedback before I clean things up.

Find the real documentation here: https://github.com/kennethreitz/requests

I've removed the docs from this fork because I haven't had time to update all of them and no docs is better than docs that are wrong.

source_address is a kwarg on request building methods (get/post/put/etc)

session objects have a source_address attribute that can be set on the session (and overridden on an individual request like all the other request related session object attributes).

If you pass in 0 for the port then the underlying HTTPConnection object falls back to "default behaviour" which, as far as I can tell, is the normal "any available port" behaviour.

Perhaps the source_address should accept an ip string *or* a tuple so that you don't need to specify the 0 (and the subtlety of free source ports and the magic 0 argument don't need to be understood by the users)

.. code-block:: pycon

    >>> r = requests.get('https://api.github.com', auth=('user', 'pass'), source_address=('127.0.0.1', 54444))
    >>> r = requests.get('https://api.github.com', auth=('user', 'pass'), source_address=('127.0.0.1', 0))
    >>> sess = requests.session()
    >>> sess.source_address = ('127.0.0.1', 54444)
    >>> sess.auth = ('user', 'pass')
    >>> r = sess.get('https://api.github.com')

I don't have good test coverage yet (and none at all checked in at the moment because I was using netcat to set up a fake server). I will work out a reasonable way to test this and then hopefully get this merged into requests.

I'm definitely open to suggestions of more elegant ways to thread the source_address parameter through the session, adapter, connectionpool and connection objects that are in between the requests api and the underlying HTTPConnection. It's not bad right now but I have a feeling that someone with a better mental model of how Requests works might see a nicer way to thread this argument through the class hierarchy.
