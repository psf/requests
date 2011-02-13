#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import requests

print requests.get('http://kennethreitz.com').headers


r = requests.Request()