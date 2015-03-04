"""
Copyright (c) Donald Stufft, pip, and individual contributors

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
from __future__ import absolute_import

import sys


class VendorAlias(object):

    def __init__(self, package_names):
        self._package_names = package_names
        self._vendor_name = __name__
        self._vendor_pkg = self._vendor_name + "."
        self._vendor_pkgs = [
            self._vendor_pkg + name for name in self._package_names
        ]

    def find_module(self, fullname, path=None):
        if fullname.startswith(self._vendor_pkg):
            return self

    def load_module(self, name):
        # Ensure that this only works for the vendored name
        if not name.startswith(self._vendor_pkg):
            raise ImportError(
                "Cannot import %s, must be a subpackage of '%s'." % (
                    name, self._vendor_name,
                )
            )

        if not (name == self._vendor_name or
                any(name.startswith(pkg) for pkg in self._vendor_pkgs)):
            raise ImportError(
                "Cannot import %s, must be one of %s." % (
                    name, self._vendor_pkgs
                )
            )

        # Check to see if we already have this item in sys.modules, if we do
        # then simply return that.
        if name in sys.modules:
            return sys.modules[name]

        # Check to see if we can import the vendor name
        try:
            # We do this dance here because we want to try and import this
            # module without hitting a recursion error because of a bunch of
            # VendorAlias instances on sys.meta_path
            real_meta_path = sys.meta_path[:]
            try:
                sys.meta_path = [
                    m for m in sys.meta_path
                    if not isinstance(m, VendorAlias)
                ]
                __import__(name)
                module = sys.modules[name]
            finally:
                # Re-add any additions to sys.meta_path that were made while
                # during the import we just did, otherwise things like
                # requests.packages.urllib3.poolmanager will fail.
                for m in sys.meta_path:
                    if m not in real_meta_path:
                        real_meta_path.append(m)

                # Restore sys.meta_path with any new items.
                sys.meta_path = real_meta_path
        except ImportError:
            # We can't import the vendor name, so we'll try to import the
            # "real" name.
            real_name = name[len(self._vendor_pkg):]
            try:
                __import__(real_name)
                module = sys.modules[real_name]
            except ImportError:
                raise ImportError("No module named '%s'" % (name,))

        # If we've gotten here we've found the module we're looking for, either
        # as part of our vendored package, or as the real name, so we'll add
        # it to sys.modules as the vendored name so that we don't have to do
        # the lookup again.
        sys.modules[name] = module

        # Finally, return the loaded module
        return module


sys.meta_path.append(VendorAlias(["urllib3", "chardet"]))
