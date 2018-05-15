#!/usr/bin/env python

# Copyright (C) 2018:
#     Sonia Bogos, sonia.bogos@elca.ch
#

import pytest
import logging
import re
import json

import helpers.requests as req
from helpers.logging import prepared_request_to_json

from bs4 import BeautifulSoup
from requests import Request, Session

author = "Sonia Bogos"
maintainer = "Sonia Bogos"
version = "0.0.1"

# Logging
# Default to Debug
##################

logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger('test_create_env')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('import_realm')
class Test_test_create_env():

    def test_create_env(self, import_realm):

        #response = export_realm

        #assert response.status_code == 200

        response = import_realm

        assert response.status_code == 201

        #response = delete_realm
        #
        #print(response.text)
        #
        #assert response.status_code == 204