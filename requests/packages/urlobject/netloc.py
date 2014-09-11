from .compat import urlparse
from .six import text_type, u


class Netloc(text_type):

    """
    A netloc string (``username:password@hostname:port``).

    Contains methods for accessing and (non-destructively) modifying those four
    components of the netloc. All methods return new instances.
    """

    def __repr__(self):
        return u('Netloc(%r)') % (text_type(self),)

    @classmethod
    def __unsplit(cls, username, password, hostname, port):
        """Put together a :class:`Netloc` from its constituent parts."""
        auth_string = ''
        if username:
            auth_string = username
            if password:
                auth_string += ':' + password
            auth_string += '@'
        port_string = ''
        if port is not None:
            port_string = ':%d' % port
        return cls(auth_string + hostname + port_string)

    @property
    def username(self):
        """The username portion of this netloc, or ``None``."""
        return self.__urlsplit.username

    def with_username(self, username):
        """Replace or add a username to this netloc."""
        return self.__replace(username=username)

    def without_username(self):
        """Remove any username (and password) from this netloc."""
        return self.without_password().with_username('')

    @property
    def password(self):
        """The password portion of this netloc, or ``None``."""
        return self.__urlsplit.password

    def with_password(self, password):

        """
        Replace or add a password to this netloc.

        Raises a ``ValueError`` if you attempt to add a password to a netloc
        with no username.
        """

        if password and not self.username:
            raise ValueError("Can't set a password on a netloc with no username")
        return self.__replace(password=password)

    def without_password(self):
        """Remove any password from this netloc."""
        return self.with_password('')

    @property
    def auth(self):
        """The username and password of this netloc as a 2-tuple."""
        return (self.username, self.password)

    def with_auth(self, username, *password):
        """Replace or add a username and password in one method call."""
        netloc = self.without_auth()
        if password:
            return netloc.with_username(username).with_password(*password)
        return netloc.with_username(username)

    def without_auth(self):
        return self.without_password().without_username()

    @property
    def hostname(self):
        """The hostname portion of this netloc."""
        return self.__urlsplit.hostname

    def with_hostname(self, hostname):
        """Replace the hostname on this netloc."""
        return self.__replace(hostname=hostname)

    @property
    def port(self):
        """The port number on this netloc (as an ``int``), or ``None``."""
        return self.__urlsplit.port

    def with_port(self, port):
        """Replace or add a port number to this netloc."""
        return self.__replace(port=port)

    def without_port(self):
        """Remove any port number from this netloc."""
        return self.__replace(port=None)

    @property
    def __urlsplit(self):
        return urlparse.SplitResult('', self, '', '', '')

    def __replace(self, **params):
        """Replace any number of components on this netloc."""
        unsplit_args = {'username': self.username,
                        'password': self.password,
                        'hostname': self.hostname,
                        'port': self.port}
        unsplit_args.update(params)
        return self.__unsplit(**unsplit_args)
