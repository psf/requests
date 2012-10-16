import setuptools

setup_params = dict(
    name='HTTPCache',
    version='0.5',
    author="Eric Larson",
    author_email="eric@ionrock.org",
    url="https://bitbucket.org/elarson/httpcache",
    packages=setuptools.find_packages(),
    tests_requires=[
        'py.test',
        'cherrypy',
    ],
)


if __name__ == '__main__':
    setuptools.setup(**setup_params)
