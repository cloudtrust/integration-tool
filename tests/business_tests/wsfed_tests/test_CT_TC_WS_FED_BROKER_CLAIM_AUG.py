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
logger = logging.getLogger('acceptance-tool.tests.business_tests.test_CT_TC_WS_FED_BROKER_SIMPLE')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'import_realm', 'import_realm_external')
class Test_CT_TC_WS_FED_BROKER_SIMPLE():
    """
    Class to test the CT_TC_SAML_SSO_BROKER_SIMPLE use case:
    As a user of company B I need the solution to allow me to access applications of company A
    after an authentication on company B IDP.
    Company A applications are protected by Cloudtrust which acts as a broker.
    """

    def test_CT_TC_WS_FED_BROKER_SIMPLE_SP_initiated(self, settings):
        """
        Test the CT_TC_WS_FED_BROKER_SIMPLE use case with the SP-initiated flow, i.e. the user accesses the application
        , which is a service provider (SP), that redirects him to the keycloak, the identity provider (IDP).
        The user has to login to keycloak which will give him the SAML token. The token will give him access to the
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

        idp_username = settings["idp_external"]["test_realm"]["username"]
        idp_password = settings["idp_external"]["test_realm"]["password"]

        idp2_ip = settings["idp_external"]["ip"]
        idp2_port = settings["idp_external"]["port"]
        idp2_scheme = settings["idp_external"]["http_scheme"]

        idp_attr_name = settings["idp"]["test_realm"]["attr_name"]
        idp_attr_name_external = settings["idp"]["test_realm"]["external_attr_name"]
        idp_attr_tag = settings["idp"]["test_realm"]["attr_xml_elem"]

        idp_attr_name_broker = settings["idp_external"]["test_realm"]["attr_name"]
        idp_attr_tag_broker = settings["idp_external"]["test_realm"]["attr_xml_elem"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        # We check that login works for both types of identity provider
        idp_brokers = [settings["idp"]["saml_broker"], settings["idp"]["wsfed_broker"]]

        for idp_broker in idp_brokers:

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

            # In the login page we can choose to login with the external IDP
            soup = BeautifulSoup(response.content, 'html.parser')

            div = soup.find("div", {"id": "kc-social-providers"})

            assert div is not None

            # we can have several idp external; choose the one needed for the test
            all_li = div.find_all('li')
            for li in all_li:
                if li.span.text == idp_broker:
                    external_idp_url = "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port) + li.a[
                        'href']

            assert external_idp_url is not None

            # Select to login with the external IDP
            req_choose_external_idp = Request(
                method='GET',
                url="{url}".format(url=external_idp_url),
                headers=header,
                cookies=keycloak_cookie
            )

            prepared_request = req_choose_external_idp.prepare()

            log_request(logger, req_choose_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

            # get the HTTP binding response with the url to the external IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            params = {}
            for input in inputs:
                params[input.get('name')] = input.get('value')

            header_redirect_external_idp = {
                **header,
                'Host': "{ip}:{port}".format(ip=idp2_ip, port=idp2_port),
                'Referer': "{ip}:{port}".format(ip=idp_ip, port=idp_port)
            }

            # Redirect to external IDP
            if idp_broker == "cloudtrust_saml":
                req_redirect_external_idp = Request(
                    method=method_form,
                    url="{url}".format(url=url_form),
                    data=params,
                    headers=header_redirect_external_idp
                )
            else:
                req_redirect_external_idp = Request(
                    method=method_form,
                    url="{url}".format(url=url_form),
                    params=params,
                    headers=header_redirect_external_idp
                )

            referer_url = url_form

            prepared_request = req_redirect_external_idp.prepare()

            log_request(logger, req_redirect_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            # if we have an identity provider saml, we do an extra redirect
            if idp_broker == "cloudtrust_saml":
                redirect_url = response.headers['Location']
                keycloak_cookie2 = response.cookies
                response = req.redirect_to_idp(logger, s, redirect_url, header, keycloak_cookie2)
            else:
                keycloak_cookie2 = response.cookies


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

            credentials_data = {}
            credentials_data["username"] = idp_username
            credentials_data["password"] = idp_password

            # Authenticate to the external IDP
            response = req.send_credentials_to_idp(logger, s, header, idp2_ip, idp2_port, referer_url, url_form,
                                                   credentials_data, {**keycloak_cookie2, **session_cookie}, method_form)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

            # get the HTTP binding response with the url to the broker IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            req_token_from_external_idp = Request(
                method=method_form,
                url="{url}".format(url=url_form),
                data=token,
                cookies=keycloak_cookie,
                headers=header
            )

            prepared_request = req_token_from_external_idp.prepare()

            log_request(logger, req_token_from_external_idp)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            # Get the token from the broker IDP
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            val = idp_attr_tag + "=\"{v}\"".format(v=idp_attr_name)
            # assert that the IDP added the location attribute in the token
            assert re.search(val, token['wresult']) is not None

            # assert that the external claim is also in the token
            val = idp_attr_tag + "=\"{v}\"".format(v=idp_attr_name_external)
            assert re.search(val, token['wresult']) is not None


            # assert that the claims that come from the external IDP are well in the token
            val = idp_attr_tag_broker + "=\"{v}\"".format(v=idp_attr_name_broker)
            # assert that the IDP added the location attribute in the token
            assert re.search(val, token['wresult']) is not None

            # Access SP with the token
            (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                             idp_ip, idp_port, method_form, url_form, token, session_cookie,
                                                             keycloak_cookie2)

            assert response.status_code == HTTPStatus.OK

            # assert that we are logged in
            assert re.search(sp_message, response.text) is not None

    def test_CT_TC_WS_FED_BROKER_SIMPLE_IDP_initiated(self, settings):
        """
        Test the CT_TC_WS_FED_BROKER_SIMPLE use case with the IDP-initiated flow, i.e. the user logs in keycloak,
        the identity provider (IDP), and then accesses the application, which is a service provider (SP).
        The application redirect towards keycloak to obtain the SAML token.
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
        idp_broker = settings["idp"]["saml_broker"]

        idp_username = settings["idp_external"]["test_realm"]["username"]
        idp_password = settings["idp_external"]["test_realm"]["password"]

        idp2_ip = settings["idp_external"]["ip"]
        idp2_port = settings["idp_external"]["port"]
        idp2_scheme = settings["idp_external"]["http_scheme"]

        idp2_external_test_realm = settings["idp_external"]["test_realm"]["name"]
        idp2_path = "auth/realms/{realm}/account".format(realm=idp2_external_test_realm)
        idp2_message = settings["idp"]["logged_in_message"]

        idp_attr_name = settings["idp"]["test_realm"]["attr_name"]
        idp_attr_name_external = settings["idp"]["test_realm"]["external_attr_name"]
        idp_attr_tag = settings["idp"]["test_realm"]["attr_xml_elem"]

        idp_attr_name_broker = settings["idp_external"]["test_realm"]["attr_name"]
        idp_attr_tag_broker = settings["idp_external"]["test_realm"]["attr_xml_elem"]

        keycloak_login_form_id = settings["idp"]["login_form_id"]

        # Common header for all the requests
        header = req.get_header()

        # We check that login works for both types of identity provider
        idp_brokers = [settings["idp"]["saml_broker"], settings["idp"]["wsfed_broker"]]

        for idp_broker in idp_brokers:
            # Login to the external IDP
            (oath_cookie, keycloak_cookie3, keycloak_cookie4, response) = req.login_external_idp(logger, s,
                                                                                                 header, idp_ip, idp_port,
                                                                                                 idp_scheme, idp_path,
                                                                                                 idp_username, idp_password,
                                                                                                 idp2_ip, idp2_port, idp_broker)

            assert response.status_code == HTTPStatus.OK

            # Assert we are logged in
            assert re.search(idp_message, response.text) is not None

            response = req.access_sp_ws_fed(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path)

            # store the cookie received from keycloak
            keycloak_cookie5 = response.cookies

            assert response.status_code == HTTPStatus.FOUND

            redirect_url = response.headers['Location']

            header_redirect_idp = {
                **header,
                'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
                'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
            }

            response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp,
                                           {**keycloak_cookie5, **keycloak_cookie3})

            assert response.status_code == HTTPStatus.OK

            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            # Get the token (SAML response) from the broker identity provider
            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            val = idp_attr_tag + "=\"{v}\"".format(v=idp_attr_name)
            # assert that the IDP added the location attribute in the token
            assert re.search(val, token['wresult']) is not None

            # assert that the external claim is also in the token
            val = idp_attr_tag + "=\"{v}\"".format(v=idp_attr_name_external)
            assert re.search(val, token['wresult']) is not None


            # assert that the claims that come from the external IDP are well in the token
            val = idp_attr_tag_broker + "=\"{v}\"".format(v=idp_attr_name_broker)
            # assert that the IDP added the location attribute in the token
            assert re.search(val, token['wresult']) is not None

            (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                             idp_ip, idp_port, method_form, url_form, token, keycloak_cookie5,
                                                             keycloak_cookie5)

            assert response.status_code == HTTPStatus.OK

            assert re.search(sp_message, response.text) is not None
