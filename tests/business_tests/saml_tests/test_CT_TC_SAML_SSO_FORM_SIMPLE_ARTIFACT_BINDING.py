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
import time
import urlparse

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
logger = logging.getLogger('acceptance-tool.tests.business_tests.test_CT_TC_SAML_SSO_FORM_SIMPLE_ARTIFACT_BINDING')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'import_realm')
class Test_CT_TC_SAML_SSO_FORM_SIMPLE_ARTIFACT_BINDING():
    """
    Class to test the CT_TC_SAML_SSO_FORM_SIMPLE_ARTIFACT_BINDING use case:
    As a user I can access an application from any device with the SAML token delivered by the KEYCLOAK IDP after a
    successful form authentication. For the SAML response we use the astifact binding where the SP and IDP discuss directly
    in order to obtain the SAML token.
    """

    # These tests check if the login succeeds for the following client:
    # one where the Artifact Binding is ON
    # TBD: do we need a new client

    def test_CT_TC_SAML_SSO_FORM_SIMPLE__ARTIFACT_BINDING_SP_initiated(self, settings):
        """
        Test the CT_TC_SAML_SSO_FORM_SIMPLE use case with the SP-initiated flow, i.e. the user accesses the application
        , which is a service provider (SP), that redirects him to the keycloak, the identity provider (IDP).
        The user has to login to keycloak.
        The IDP sends an artifact encoded in SAMLart and then IDP and SP discuss directly (not passing through the browser)
        in order to obtain the SAML token. The token will give to the user the access to the
        application.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sps = [settings["sps_saml"][0]]
        for sp in sps:
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
            header = req.get_header()

            (session_cookie, response) = req.access_sp_saml(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                                            idp_ip, idp_port)

            assert response.status_code == HTTPStatus.FOUND

            # store the cookie received from keycloak
            keycloak_cookie = response.cookies

            redirect_url = response.headers['Location']

            header_redirect_idp = {
                **header,
                'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
                'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
            }

            response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, keycloak_cookie)

            if response.status_code == HTTPStatus.UNAUTHORIZED and response.headers['WWW-Authenticate'] == 'Negotiate':
                response = req.kerberos_form_fallback(logger, s, response, header,
                                                      {**keycloak_cookie, **session_cookie})

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

            response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data, keycloak_cookie, method_form)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND #or response.status_code == 303 or response.status_code == 307



            # While normally at this stage we would get the token (SAML response) from the identity provider,
            # for this use case, we get the artifact encoded in the parameter SAMLart

            assert response.status_code == HTTPStatus.FOUND  # HTTPStatus.OK
            redirect_url = response.headers['Location']

            # extract the SAMLart
            parsed = urlparse.urlparse(redirect_url)
            artifact = urlparse.parse_qs(parsed.query)['SAMLart']

            # assert we received the artifact in encoded in the SAMLart parameter
            assert artifact is not None

            req_get_artifact = Request(
                method='GET',
                url="{url}".format(url=redirect_url),
                cookies={**session_cookie, **keycloak_cookie},
                headers=header
            )

            prepared_request = req_get_artifact.prepare()

            log_request(logger, req_get_artifact)

            response = s.send(prepared_request, verify=False)

            logger.debug(response.status_code)


            # wait for IDP to send the SAML token to SP
            time.sleep(2)

            # assert that we are logged in
            assert re.search(sp_message, response.text) is not None

            ## Check the logs of Keycloak to verifiy the communication between IDP and SP
            ## ssh using paramiko
            ##client = SSHClient()
            ##client.load_system_host_keys()
            ##client.connect(hostname, port=port, username=username, password=password)
            ##stdin, stdout, stderr = client.exec_command('ls -l')

     ## The IDP-initatited is not yet implemented: there is the need to clarify the details of this use case


    def test_CT_TC_SAML_SSO_FORM_SIMPLE_ARTIFACT_BINDING_IDP_initiated_keycloak_endpoint(self, settings):
        """
        Test the CT_TC_SAML_SSO_FORM_SIMPLE use case with the IDP-initiated flow, where we set up an endpoint
        on Keycloak with IDP Initiated SSO URL Name.
        Thus, the user accesses
        http[s]://host:port/auth/realms/{RealmName}/protocol/saml/clients/{IDP Initiated SSO URL Name}
        to authenticate to Keycloak and obtain the token (SAML response) and gets redirected
        to the SP that he can access
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sps = [settings["sps_saml"][0], settings["sps_saml"][1]]
        for sp in sps:
            sp_ip = sp["ip"]
            sp_port = sp["port"]
            sp_scheme = sp["http_scheme"]
            sp_path = sp["path"]
            sp_message = sp["logged_in_message"]
            sp_sso_url_name = sp["sso_url_name"]

            # Identity provider settings
            idp_ip = settings["idp"]["ip"]
            idp_port = settings["idp"]["port"]
            idp_scheme = settings["idp"]["http_scheme"]
            idp_test_realm = settings["idp"]["test_realm"]["name"]
            idp_login_endpoint = "auth/realms/{realm}/protocol/saml/clients/{name}".format(realm=idp_test_realm, name=sp_sso_url_name)

            idp_username = settings["idp"]["test_realm"]["username"]
            idp_password = settings["idp"]["test_realm"]["password"]

            keycloak_login_form_id = settings["idp"]["login_form_id"]

            # Common header for all the requests
            header = req.get_header()

            # Idp endpoint for client
            url_endpoint= "{scheme}://{ip}:{port}/{path}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port, path=idp_login_endpoint)

            req_access_idp_endpoint = Request(
                method='GET',
                url=url_endpoint,
                headers=header,
            )

            prepared_request = req_access_idp_endpoint.prepare()

            log_request(logger, req_access_idp_endpoint)

            response = s.send(prepared_request, verify=False, allow_redirects=False)

            logger.debug(response.status_code)

            keycloak_cookie = response.cookies

            if response.status_code == HTTPStatus.UNAUTHORIZED and response.headers['WWW-Authenticate'] == 'Negotiate':
                response = req.kerberos_form_fallback(logger, s, response, header,
                                                      {**keycloak_cookie})

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

            # Provide the credentials
            credentials_data = {}
            credentials_data["username"] = idp_username
            credentials_data["password"] = idp_password

            response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, url_endpoint, url_form,
                                                   credentials_data, keycloak_cookie, method_form)

            assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND

            keycloak_cookie_2 = response.cookies

            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.body.form

            url_form = form.get('action')
            inputs = form.find_all('input')
            method_form = form.get('method')

            # Get the token (SAML response) from the identity provider
            token = {}
            for input in inputs:
                token[input.get('name')] = input.get('value')

            (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                             idp_ip, idp_port, method_form, url_form, token,
                                                             keycloak_cookie_2, keycloak_cookie_2)

            assert response.status_code == HTTPStatus.OK

            #  Access the secure page of the SP
            header_sp_page = {
                **header,
                'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
                'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
            }

            req_get_sp_page = Request(
                method='GET',
                url="{scheme}://{ip}:{port}/{path}".format(
                    scheme=sp_scheme,
                    port=sp_port,
                    ip=sp_ip,
                    path=sp_path
                ),
                headers=header_sp_page,
                cookies=sp_cookie
            )

            prepared_request = req_get_sp_page.prepare()

            log_request(logger, req_get_sp_page)

            response = s.send(prepared_request, verify=False)

            logger.debug(response.status_code)

            assert response.status_code == HTTPStatus.OK

            assert re.search(sp_message, response.text) is not None

