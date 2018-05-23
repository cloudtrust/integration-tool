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

import helpers.requests as req

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
logger = logging.getLogger('acceptance-tool.tests.business_tests.test_CT_TC_WS_FED_SSO_FORM_SIMPLE')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'import_realm')
class Test_CT_TC_WS_FED_SSO_FORM_SIMPLE():
    """
    Class to test the CT_TC_WS_FED_SSO_FORM_SIMPLE use case:
    As a user I can access the CRM application from any device with the WS-FED token delivered by the KEYCLOAK
    IDP after a successful form authentication.
    """

    def test_CT_TC_WS_FED_SSO_FORM_SIMPLE_SP_initiated(self, settings):
        """
        Test the CT_TC_SAML_SSO_FORM_SIMPLE use case with the SP-initiated flow, i.e. the user accesses the application
        , which is a service provider (SP), that redirects him to the keycloak, the identity provider (IDP).
        The user has to login to keycloak which will give him the WSFED token. The token will give him access to the
        application.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp = settings["sps_wsfed"][0]
        sp_ip = sp["ip"]
        sp_port = sp["port"]
        sp_scheme = sp["http_scheme"]
        sp_path = sp["path"]
        sp_message = sp["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        idp_username = settings["idp"]["test_realm"]["username"]
        idp_password = settings["idp"]["test_realm"]["password"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = {
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            'Accept-Encoding': "gzip, deflate",
            'Accept-Language': "en-US,en;q=0.5",
            'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
            'Connection': "keep-alive",
            'Upgrade-Insecure-Requests': "1",
        }

        response = req.access_sp_ws_fed(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path)

        session_cookie = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, session_cookie)

        keycloak_cookie = response.cookies

        soup = BeautifulSoup(response.content, 'html.parser')

        form = soup.find("form", {"id": keycloak_login_form_id})

        assert form is not None

        url_form = form.get('action')
        method_form = form.get('method')

        inputs = form.find_all('input')

        input_name = []
        for input in inputs:
            input_name.append(input.get('name'))

        assert "username" in input_name
        assert "password" in input_name

        # Simulate the login to the identity provider by providing the credentials
        credentials_data = {}
        credentials_data["username"] = idp_username
        credentials_data["password"] = idp_password

        response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data,
                                               keycloak_cookie, method_form)

        assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND #or response.status_code == 303 or response.status_code == 307

        keycloak_cookie_2 = response.cookies

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the token from the identity provider
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme, idp_ip,
                                                         idp_port, method_form, url_form, token, session_cookie,
                                                         keycloak_cookie_2, )

        assert response.status_code == HTTPStatus.OK

        # assert that we are logged in
        assert re.search(sp_message, response.text) is not None

    def test_CT_TC_WS_FED_SSO_FORM_SIMPLE_IDP_initiated(self, settings):
        """
        Test the CT_TC_SAML_SSO_FORM_SIMPLE use case with the IDP-initiated flow, i.e. the user logs in keycloak,
        the identity provider (IDP), and then accesses the application, which is a service provider (SP).
        The application redirect towards keycloak to obtain the WSFED token.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp = settings["sps_wsfed"][0]
        sp_ip = sp["ip"]
        sp_port = sp["port"]
        sp_scheme = sp["http_scheme"]
        sp_path = sp["path"]
        sp_message = sp["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]
        idp_test_realm = settings["idp"]["test_realm"]["name"]
        idp_path = "auth/realms/{realm}/account".format(realm=idp_test_realm)
        idp_message = settings["idp"]["logged_in_message"]

        idp_username = settings["idp"]["test_realm"]["username"]
        idp_password = settings["idp"]["test_realm"]["password"]

        # Common header for all the requests
        header = {
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            'Accept-Encoding': "gzip, deflate",
            'Accept-Language': "en-US,en;q=0.5",
            'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
            'Connection': "keep-alive",
            'Upgrade-Insecure-Requests': "1",
        }

        (oath_cookie, keycloak_cookie, keycloak_cookie2, response) = req.login_idp(logger, s, header, idp_ip, idp_port,
                                                                                   idp_scheme, idp_path, idp_username,
                                                                                   idp_password)

        assert response.status_code == HTTPStatus.OK

        # Assert we are logged in
        assert re.search(idp_message, response.text) is not None

        response = req.access_sp_ws_fed(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path)

        # store the cookie received from keycloak
        session_cookie = response.cookies

        assert response.status_code == HTTPStatus.FOUND

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, {**keycloak_cookie2})

        assert response.status_code == HTTPStatus.OK

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the saml response from the identity provider
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme, idp_ip,
                                                         idp_port, method_form, url_form, token, session_cookie,
                                                         keycloak_cookie2, )

        assert response.status_code == HTTPStatus.OK

        assert re.search(sp_message, response.text) is not None


