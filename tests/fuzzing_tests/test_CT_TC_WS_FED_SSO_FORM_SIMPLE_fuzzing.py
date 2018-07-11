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
import sh
import os

import helpers.requests as req

import urllib.parse as url
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
logger = logging.getLogger('acceptance-tool.tests.business_tests.Test_fuzzing_wsfed_parameters')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'import_realm')
class Test_fuzzing_wsfed_parameters():
    """

    """

    def test_security_fuzzing_wa_wsfed_parameter(self, settings):
        """
        :param settings:
        :return:
        """

        s = Session()

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]
        idp_test_realm = settings["idp"]["test_realm"]["name"]


        wa_value = "wsignin1.0"
        no_fuzzed_values = 4

        # Common header for all the requests
        header = req.get_header()

        # a WSFED query
        query = "wa=wsignin1.0&" \
                "wreply=http%3A%2F%2F127.0.0.1%3A7000%2Fj_spring_fediz_security_check&" \
                "wtrealm=sp_wsfed1&" \
                "wct=2018-07-10T14%3A43%3A45.921Z&" \
                "wctx=48022b8c-9b80-4446-8487-f94b24439f44"

        redirect_url = "{scheme}://{ip}:{port}/auth/realms/{realm}/protocol/wsfed?{query}".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
            realm=idp_test_realm,
            query=query
        )

        # split the url in parts
        url_parts = list(url.urlparse(redirect_url))

        # fetch the query part with the wsfed parameters
        query = dict(url.parse_qsl(url_parts[4]))

        # update the wa wsfed parameter
        fuzzing = sh.radamsa(sh.echo(query['wa']), "-n", no_fuzzed_values)
        logger.debug("echo {param} | radamsa -n {count}".format(param=query['wa'], count=no_fuzzed_values))
        logger.debug(fuzzing)

        fuzz_params = fuzzing.split('\n')
        for param in fuzz_params:
            # modify the wa wsfed parameter with the fuzzed version
            query['wa'] = ''.join([i if ord(i) < 128 else '' for i in param])

            if query['wa'] != wa_value:
                # recreate the url
                url_parts[4] = url.urlencode(query)
                redirect_url = url.urlunparse(url_parts)

                logger.debug("Sending a wsfed login request with the fuzzed value {val} for the parameter wa".format(val=query['wa']))
                req_get_keycloak = Request(
                    method='GET',
                    url="{url}".format(url=redirect_url),
                    headers=header
                )

                prepared_request = req_get_keycloak.prepare()
                req.log_request(logger, req_get_keycloak)
                response = s.send(prepared_request, verify=False)
                logger.debug(response.status_code)

                assert response.status_code == HTTPStatus.BAD_REQUEST

                # check that Keycloak is up there running and able to answer to requests
                # run the wsfed login test
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
                header = req.get_header()

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

                response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form,
                                                       credentials_data,
                                                       keycloak_cookie, method_form)

                assert response.status_code == HTTPStatus.OK or response.status_code == HTTPStatus.FOUND  # or response.status_code == 303 or response.status_code == 307

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

                (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme,
                                                                 idp_scheme, idp_ip,
                                                                 idp_port, method_form, url_form, token,
                                                                 session_cookie,
                                                                 keycloak_cookie_2, )

                assert response.status_code == HTTPStatus.OK

                # assert that we are logged in
                assert re.search(sp_message, response.text) is not None







