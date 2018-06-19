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
import re
import urllib.parse as urlparse
from urllib.parse import urlencode

import helpers.requests as req
from helpers.logging import log_request

from bs4 import BeautifulSoup
from requests import Request, Session
from http import HTTPStatus

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
logger = logging.getLogger('acceptance-tool.tests.business_tests.test_CT_TC_SAML_BROKER_SIMPLE')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'import_realm', 'login_broker_sso_form', 'import_realm_external')
class Test_CT_TC_SAML_SSO_BROKER_LOGOUT_SIMPLE():
    """
    Class to test the CT_TC_SAML_SSO_BROKER_LOGOUT_SIMPLE use case:
    As a resource owner I need the solution to ensure that all access tokens/sessions are invalidated
    and not usable anymore after the a user of company B, who authenticated on company B IDP,
    has proceeded to a logout on the target application.
    Company A applications are protected by Cloudtrust which acts as a broker.
    """
    # This code test contains a bit of magic as with the current Keycloak version the logout does not actually works

    def test_CT_TC_SAML_SSO_BROKER_LOGOUT_SIMPLE(self, settings, login_broker_sso_form):
        """
        #TODO:update the description and the comments
        Test the CT_TC_SAML_SSO_FORM_SIMPLE use case with the SP-initiated flow, i.e. the user accesses the application
        , which is a service provider (SP), that redirects him to the keycloak, the identity provider (IDP).
        The user has to login to keycloak which will give him the SAML token. The token will give him access to the
        application.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp = settings["sps_saml"][0]
        sp_ip = sp["ip"]
        sp_port = sp["port"]
        sp_scheme = sp["http_scheme"]
        sp_path = sp["path"]
        sp_message = sp["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp_external"]["test_realm"]["username"]
        idp_password = settings["idp_external"]["test_realm"]["password"]

        idp2_ip = settings["idp_external"]["ip"]
        idp2_port = settings["idp_external"]["port"]
        idp2_scheme = settings["idp_external"]["http_scheme"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        sp_cookie, keycloak_cookie = login_broker_sso_form

        # header_sp_reload_page = {
        #     **header,
        #     'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
        #     'Referer': "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port)
        # }
        #
        # req_get_sp_login_reload_page = Request(
        #     method='GET',
        #     url="{scheme}://{ip}:{port}/{path}".format(
        #         scheme=sp_scheme,
        #         port=sp_port,
        #         ip=sp_ip,
        #         path=sp_path
        #     ),
        #     headers=header_sp_reload_page,
        #     cookies={**sp_cookie}
        # )
        #
        # prepared_request = req_get_sp_login_reload_page.prepare()
        #
        # req.log_request(logger, req_get_sp_login_reload_page)
        #
        # response = s.send(prepared_request, verify=False, allow_redirects=False)
        #
        # logger.debug(response.status_code)
        #
        # print(response.text)
        # # the user is logged in and refreshing the page will return an OK
        # #assert response.status_code == 200