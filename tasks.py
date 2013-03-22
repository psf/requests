# -*- coding: utf-8 -*-

import requests
from invoke import run, task

@task
def test():
    run('py.test', pty=True)

@task
def deps():
    print('Vendoring urllib3...')

    run('rm -fr requests/packages/urllib3')
    run('git clone https://github.com/shazow/urllib3.git')
    run('mv urllib3/urllib3 requests/packages/')
    run('rm -fr urllib3')

    print('Vendoring Charade...')

    run('rm -fr requests/packages/charade')
    run('git clone https://github.com/sigmavirus24/charade.git')
    run('mv charade/charade requests/packages/')
    run('rm -fr charade')

@task
def certs():
    print('Grabbing latest CA Bundle...')
    r = requests.get('https://raw.github.com/kennethreitz/certifi/master/certifi/cacert.pem')

    with open('requests/cacert.pem', 'w') as f:
        f.write(r.content)
