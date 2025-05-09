.. _advanced_retries:

Advanced Retry Functionality
===========================

Requests now includes a powerful and flexible retry system that allows you to automatically retry failed requests with configurable backoff strategies.

Basic Usage
----------

The simplest way to use the retry functionality is to set the ``max_retries`` attribute on a session:

.. code-block:: python

    import requests
    
    # Create a session with retry
    session = requests.Session()
    session.max_retries = 3  # Maximum number of retries
    
    # Make a request that will automatically retry up to 3 times if it fails
    response = session.get('https://api.example.com/endpoint')

By default, retries will only be triggered for certain HTTP methods (GET, HEAD, PUT, DELETE, OPTIONS, TRACE) and certain status codes (413, 429, 500, 502, 503, 504).

Configuring Retry Behavior
-------------------------

You can customize the retry behavior by configuring additional attributes on the session:

.. code-block:: python

    import requests
    
    session = requests.Session()
    
    # Configure retry settings
    session.max_retries = 3  # Maximum number of retries
    session.retry_status_forcelist = {500, 502, 503, 504}  # Status codes that trigger a retry
    session.retry_allowed_methods = {'GET', 'HEAD'}  # HTTP methods that should be retried
    session.retry_on_timeout = True  # Whether to retry on timeout errors
    session.retry_on_connection_error = True  # Whether to retry on connection errors

Retry Strategies
--------------

Requests provides several built-in retry strategies that determine how long to wait between retry attempts:

1. ``ConstantRetry``: Uses a constant delay between retry attempts
2. ``ExponentialRetry``: Uses an exponential backoff strategy (delay increases exponentially with each retry)
3. ``ExponentialRetryWithJitter``: Uses exponential backoff with added jitter to prevent the "thundering herd" problem

You can configure the retry strategy on a session:

.. code-block:: python

    import requests
    
    session = requests.Session()
    session.max_retries = 3
    
    # Use exponential backoff with jitter
    session.retry_strategy = requests.ExponentialRetryWithJitter(
        backoff_factor=0.5,  # Start with 0.5 second delay
        max_backoff=60,      # Maximum backoff of 60 seconds
        jitter_factor=0.1    # Add 10% jitter
    )
    
    # Make a request with the configured retry strategy
    response = session.get('https://api.example.com/endpoint')

Custom Retry Strategies
---------------------

You can create your own retry strategy by subclassing ``RetryStrategy`` and implementing the ``get_backoff_time`` method:

.. code-block:: python

    import requests
    import random
    
    class CustomRetryStrategy(requests.RetryStrategy):
        def __init__(self, base_delay=1.0):
            self.base_delay = base_delay
        
        def get_backoff_time(self, retry_number):
            # Custom logic to determine backoff time
            return self.base_delay * (retry_number + 1) * random.uniform(0.8, 1.2)
    
    # Use the custom strategy
    session = requests.Session()
    session.max_retries = 3
    session.retry_strategy = CustomRetryStrategy(base_delay=2.0)

Respecting Retry-After Headers
----------------------------

By default, the retry system will respect ``Retry-After`` headers sent by servers, which indicate how long the client should wait before making another request. This behavior can be controlled with the ``respect_retry_after_header`` parameter:

.. code-block:: python

    import requests
    from requests.retry import Retry
    
    # Create a custom retry configuration
    retry = Retry(
        total=3,
        respect_retry_after_header=True,  # Default is True
        # Other parameters...
    )
    
    # Apply it directly to an adapter
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)

Complete Example
--------------

Here's a complete example showing how to use the retry functionality with a custom configuration:

.. code-block:: python

    import requests
    
    # Create a session with retry
    session = requests.Session()
    
    # Configure retry settings
    session.max_retries = 5
    session.retry_status_forcelist = {429, 500, 502, 503, 504}
    session.retry_allowed_methods = {'GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'}
    session.retry_on_timeout = True
    session.retry_on_connection_error = True
    
    # Use exponential backoff with jitter
    session.retry_strategy = requests.ExponentialRetryWithJitter(
        backoff_factor=1.0,
        max_backoff=60,
        jitter_factor=0.2
    )
    
    try:
        # Make a request that will automatically retry if it fails
        response = session.get('https://api.example.com/endpoint', timeout=10)
        response.raise_for_status()
        
        # Process the successful response
        print(f"Success: {response.status_code}")
        print(response.json())
        
    except requests.exceptions.RetryError as e:
        # This exception is raised when all retries have failed
        print(f"All retries failed: {e}")
        
    except requests.exceptions.RequestException as e:
        # Handle other request exceptions
        print(f"Request failed: {e}")
