Requests: The Simple (e.g. usable) HTTP Module
==============================================

::

	:::::::::  ::::::::::  ::::::::   :::    ::: ::::::::::  ::::::::  :::::::::::  ::::::::  
	:+:    :+: :+:        :+:    :+:  :+:    :+: :+:        :+:    :+:     :+:     :+:    :+: 
	+:+    +:+ +:+        +:+    +:+  +:+    +:+ +:+        +:+            +:+     +:+        
	+#++:++#:  +#++:++#   +#+    +:+  +#+    +:+ +#++:++#   +#++:++#++     +#+     +#++:++#++ 
	+#+    +#+ +#+        +#+  # +#+  +#+    +#+ +#+               +#+     +#+            +#+ 
	#+#    #+# #+#        #+#   +#+   #+#    #+# #+#        #+#    #+#     #+#     #+#    #+# 
	###    ### ##########  ###### ###  ########  ##########  ########      ###      ########  

                                                              


Overview
--------

Existing Python modules for dealing HTTP requests are insane. I have to look up *everything* that I want to do. Most of my worst Python experiences (yes, even worse than Logging) are a result of the various built-in HTTP libraries. 

But this one's different. This one's going to be awesome. And simple.

Really simple.

Usage
-----

Let's do this. ::


	>>> import requests
	>>> request.get(url, params={}, headers={} auth=None)
	>>> request.put(url, params={}, headers={}, auth=None)
	>>> request.post(url, params={}, headers={}, auth=None)
	>>> request.delete(url, params={}, headers={}, auth=None)
	
	
	>>> r = request.Request()
	
	>>> r.url = 'httep://someurl.com/'
	>>> r.add_header(('key', 'value'))
	
	>>> r.method = 'GET'
	
	>>> r.send()
	True

	>>> dict(r)
	{
		'headers': {
			'key': 'value',
		}, 
		'method': 'GET',
		'response': {
			'status_code': 200,
			'headers': {
				'x-runtime': '210ms',
				'server': 'Apache 2.1',
				'Content-Type': 'text/html; charset=utf-8'
			}
		}
	}
	
Access stuff. ::

	>>> r = request.get('https://github.com')
	>>> r.status_code()

HTTP Authentication. ::

	>>> whoiam = AuthObject('xxx-username', 'xxx-pass')
	>>> request.get(url, params{}, auth=whoiam)

"Opener" System. ::

	# all containing given url will automatically auth with given AuthObject
	>>> requests.add_autoauth(url, auth)
	


Installation
------------

To install tablib, simply: ::

	$ pip install requests
	
Or, if you absolutely must: ::

	$ easy_install requests

But, you really shouldn't do that.
   
Contribute
----------

If you'd like to contribute, simply fork `the repository`_, commit your changes to the **develop** branch (or branch off of it), and send a pull request. Make sure you add yourself to AUTHORS_.


Roadmap
-------
- Documentation
- Write it!
- Test it!
- Fo shizzle

.. _`the repository`: http://github.com/kennethreitz/requests
.. _AUTHORS: http://github.com/kennethreitz/requests/blob/master/AUTHORS
