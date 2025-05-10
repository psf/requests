.. _advanced_features:

Advanced Features
===============

This document describes the advanced features added to the requests library.

Middleware System
--------------

The middleware system allows you to add custom processing logic to requests and responses. This is useful for logging, authentication, request/response transformation, and more.

Basic Usage
~~~~~~~~~~

.. code-block:: python

    import requests
    
    # Create a session with middleware
    session = requests.Session()
    
    # Add logging middleware
    session.middleware.add(requests.LoggingMiddleware())
    
    # Make a request that will be processed by the middleware
    response = session.get('https://api.example.com/endpoint')

Built-in Middleware
~~~~~~~~~~~~~~~~

Requests comes with several built-in middleware classes:

- ``LoggingMiddleware``: Logs requests and responses
- ``TimingMiddleware``: Measures and logs request duration
- ``HeadersMiddleware``: Adds custom headers to requests
- ``UserAgentMiddleware``: Sets a custom User-Agent header
- ``AuthMiddleware``: Adds authentication to requests
- ``RetryContextMiddleware``: Tracks retry attempts

Example with multiple middleware:

.. code-block:: python

    import requests
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a session
    session = requests.Session()
    
    # Add multiple middleware
    session.middleware.add(requests.LoggingMiddleware())
    session.middleware.add(requests.TimingMiddleware())
    session.middleware.add(requests.HeadersMiddleware({
        'X-Custom-Header': 'CustomValue',
        'X-API-Key': 'your-api-key'
    }))
    
    # Make a request
    response = session.get('https://api.example.com/endpoint')
    
    # Access timing information added by middleware
    print(f"Request took {response.request_duration} seconds")

Custom Middleware
~~~~~~~~~~~~~~

You can create your own middleware by subclassing ``Middleware`` and implementing the ``process_request`` and/or ``process_response`` methods:

.. code-block:: python

    import requests
    
    class CustomMiddleware(requests.Middleware):
        def process_request(self, request, context):
            # Modify the request
            request.headers['X-Custom-Header'] = 'CustomValue'
            return request
        
        def process_response(self, response, context):
            # Modify the response
            response.__dict__['custom_attribute'] = 'custom_value'
            return response
    
    # Create a session
    session = requests.Session()
    
    # Add custom middleware
    session.middleware.add(CustomMiddleware())
    
    # Make a request
    response = session.get('https://api.example.com/endpoint')
    
    # Access custom attribute added by middleware
    print(response.custom_attribute)  # Outputs: custom_value

Enhanced Timeout Controls
---------------------

The enhanced timeout controls provide more granular control over different phases of the request lifecycle.

Basic Usage
~~~~~~~~~~

.. code-block:: python

    import requests
    
    # Create a session
    session = requests.Session()
    
    # Configure granular timeout
    session.default_timeout = requests.Timeout(
        connect=0.5,  # Connection timeout
        read=2.0,     # Read timeout
        write=1.0     # Write timeout
    )
    
    # Make a request with the configured timeout
    response = session.get('https://api.example.com/endpoint')

Timeout Strategies
~~~~~~~~~~~~~~

Requests provides several timeout strategies for use with retries:

- ``ConstantTimeout``: Uses the same timeout for all retry attempts
- ``LinearTimeout``: Increases the timeout linearly with each retry
- ``ExponentialTimeout``: Increases the timeout exponentially with each retry

Example with timeout strategy:

.. code-block:: python

    import requests
    
    # Create a session
    session = requests.Session()
    
    # Configure base timeout
    base_timeout = requests.Timeout(
        connect=1.0,
        read=2.0
    )
    
    # Configure timeout strategy
    session.timeout_strategy = requests.ExponentialTimeout(
        base_timeout=base_timeout,
        factor=2.0,        # Double the timeout with each retry
        max_timeout=30.0   # Maximum timeout of 30 seconds
    )
    
    # Configure retries
    session.max_retries = 3
    
    # Make a request
    response = session.get('https://api.example.com/endpoint')

Per-Request Timeout
~~~~~~~~~~~~~~~

You can also specify a timeout for individual requests:

.. code-block:: python

    import requests
    
    # Create a session
    session = requests.Session()
    
    # Make a request with a specific timeout
    response = session.get(
        'https://api.example.com/endpoint',
        timeout=requests.Timeout(
            connect=0.5,
            read=5.0
        )
    )

Combining Features
--------------

The real power comes from combining these features:

.. code-block:: python

    import requests
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a session
    session = requests.Session()
    
    # Configure middleware
    session.middleware.add(requests.LoggingMiddleware())
    session.middleware.add(requests.TimingMiddleware())
    session.middleware.add(requests.RetryContextMiddleware())
    
    # Configure timeout
    session.default_timeout = requests.Timeout(
        connect=1.0,
        read=2.0
    )
    
    # Configure timeout strategy
    session.timeout_strategy = requests.LinearTimeout(
        base_timeout=session.default_timeout,
        increment=1.0,
        max_timeout=10.0
    )
    
    # Configure retry
    session.max_retries = 3
    session.retry_strategy = requests.ExponentialRetryWithJitter(
        backoff_factor=0.5,
        max_backoff=10.0,
        jitter_factor=0.1
    )
    session.retry_status_forcelist = {429, 500, 502, 503, 504}
    session.retry_on_timeout = True
    
    try:
        # Make a request
        response = session.get('https://api.example.com/endpoint')
        
        # Process the response
        print(f"Status: {response.status_code}")
        print(f"Body: {response.text}")
        print(f"Duration: {response.request_duration} seconds")
        print(f"Retry count: {response.retry_count}")
        
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

This example combines middleware, enhanced timeout controls, and retry functionality to create a robust request handling system.
