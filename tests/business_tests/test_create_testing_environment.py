#!/usr/bin/env python

# Copyright (C) 2018:
#     Sonia Bogos, sonia.bogos@elca.ch
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

import pytest
import logging

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
logger = logging.getLogger('acceptance-tool.tests.business_tests.test_create_testing_environment')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('export_realm')
class Test_create_testing_environment():
    """
       Class to prepare the testing environment and test that the setup has succeeded.
       Before launching the business tests, we need the JSON file that contains the Keycloak testing environment.
       !!This test should be run only once, before launching the tests.!!
       For all the tests we setup the testing environment as follows:
       - we configure manually Keycloak with the realm test that contains all the
       clients, users, roles, policies needed for the tests.
       - we run once test_create_testing_environment to export to a JSON file the configuration of the realm test;
       this file will be later on used by the 'import_realm' fixture
       """
    def test_create_testing_environment(self, export_realm):

        response = export_realm

        assert response.status_code == 200

        #response = import_realm
        #assert response.status_code == 201

        #response = delete_realm
        #assert response.status_code == 204