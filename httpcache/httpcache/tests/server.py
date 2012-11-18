from __future__ import print_function
import cherrypy


class CacheTestingServer(object):

    def index(self):
        return 'foo'
    index.exposed = True

    def max_age(self, value=None):
        age = 'max-age=%s' % (value or 300)
        cherrypy.response.headers['Cache-Control'] = age
        return 'max age'
    max_age.exposed = True

    def no_cache(self):
        cherrypy.response.headers['Cache-Control'] = 'no-cache'
        return 'no cache'
    no_cache.exposed = True

    def must_revalidate(self):
        cherrypy.response.headers['Cache-Control'] = 'must-revalidate'
        return 'must revalidate'
    must_revalidate.exposed = True

    def no_store(self):
        cherrypy.response.headers['Cache-Control'] = 'no-store'
        return 'no store'
    no_store.exposed = True


if __name__ == '__main__':
    cherrypy.tree.mount(CacheTestingServer(), '/')
    cherrypy.engine.start()
    cherrypy.engine.block()
