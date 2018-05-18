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
logger = logging.getLogger('acceptance-tool.tests.business_tests.test_CT_TC_WS_FED_IDP_LOGOUT_PERIMETRIC')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'login_sso_form', 'import_realm')
class Test_test_CT_TC_WS_FED_IDP_LOGOUT_PERIMETRIC():
    """
    Class to test the test_CT_TC_WS_FED_IDP_LOGOUT_PERIMETRIC use case:
    As a compliance manager I need the solution to ensure that all access tokens/sessions for all applications
    are invalidated and not usable anymore after the user has proceeded to a logout on the target application.
    """

    def test_CT_TC_WS_FED_IDP_LOGOUT_PERIMETRIC(self, settings, login_sso_form):
        """
        Scenario: user is logged in on several SPs.
        The user logs out of one SP. Access to all the other SPs should require a new log in.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp1 = settings["sps_wsfed"][0]
        sp_ip = sp1["ip"]
        sp_port = sp1["port"]
        sp_scheme = sp1["http_scheme"]
        sp_path = sp1["path"]
        sp_logout_path = sp1["logout_path"]
        sp_message = sp1["logged_out_message"]

        sp2 = settings["sps_wsfed"][1]
        sp2_ip = sp2["ip"]
        sp2_port = sp2["port"]
        sp2_scheme = sp2["http_scheme"]
        sp2_path = sp2["path"]

        # Identity provider settings
        idp_ip = settings["idp"]["ip"]
        idp_port = settings["idp"]["port"]
        idp_scheme = settings["idp"]["http_scheme"]

        # Common header for all the requests
        header = {
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            'Accept-Encoding': "gzip, deflate",
            'Accept-Language': "en-US,en;q=0.5",
            'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
            'Connection': "keep-alive",
            'Upgrade-Insecure-Requests': "1",
        }

        # Perform login using the fixture login_sso_form
        sp_cookie, keycloak_cookie = login_sso_form

        # User is logged in on SP1

        # Perform login on SP2

        response = req.access_sp_ws_fed(logger, s, header, sp2_ip, sp2_port, sp2_scheme, sp2_path)

        session_cookie = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port)
        }

        response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, {**keycloak_cookie})

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, sp2_cookie) = req.access_sp_with_token(logger, s, header, sp2_ip, sp2_port, idp_scheme, idp_ip, idp_port,
                                                         method_form, url_form, token, session_cookie,
                                                         keycloak_cookie)

        # req_get_sp_login_reload_page = Request(
        #     method='GET',
        #     url="{scheme}://{ip}:{port}/{path}".format(
        #         scheme=sp2_scheme,
        #         port=sp2_port,
        #         ip=sp2_ip,
        #         path=sp2_path
        #     ),
        #     headers=header_sp2_reload_page,
        #     cookies={**session_cookie}
        # )
        #
        # prepared_request = req_get_sp_login_reload_page.prepare()
        #
        # logger.debug(
        #     json.dumps(
        #         prepared_request_to_json(req_get_sp_login_reload_page),
        #         sort_keys=True,
        #         indent=4,
        #         separators=(',', ': ')
        #     )
        # )
        #
        # response = s.send(prepared_request, verify=False, allow_redirects=False)
        #
        # logger.debug(response.status_code)
        #
        # # the user is logged in and refreshing the page will return an OK
        # assert response.status_code == 200

        # User is now logged in on both applications: SP1 and SP2

        # Logout from the first applications
        header_sp_logout_page = {
            **header,
            'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
            'Referer': "{scheme}://{ip}:{port}".format(scheme=sp_scheme, ip=sp_ip, port=sp_port)
        }

        req_get_sp_logout_page = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/{path}".format(
                scheme=sp_scheme,
                port=sp_port,
                ip=sp_ip,
                path=sp_logout_path
            ),
            headers=header_sp_logout_page,
            cookies={**sp_cookie}
        )

        prepared_request = req_get_sp_logout_page.prepare()

        log_request(logger, req_get_sp_logout_page)

        response = s.send(prepared_request, verify=False, allow_redirects=False)

        logger.debug(response.status_code)

        # new session cookie
        session_cookie2 = response.cookies

        redirect_url = response.headers['Location']

        req_sp_logout_redirect = Request(
            method='GET',
            url= redirect_url,
            headers=header_sp_logout_page,
            cookies={**sp_cookie}
        )

        prepared_request = req_sp_logout_redirect.prepare()

        log_request(logger, req_sp_logout_redirect)

        response = s.send(prepared_request, verify=False, allow_redirects=False)

        logger.debug(response.status_code)

        redirect_url = response.headers['Location']

        response = req.redirect_to_idp(logger, s, redirect_url, header, sp_cookie)

        assert response.status_code == HTTPStatus.OK

        soup = BeautifulSoup(response.content, 'html.parser')

        form = soup.body.form
        url_form = form.get('action')
        method_form = form.get('method')
        inputs = form.find_all('input')

        # Send ws fed response
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port,
                                                      method_form, url_form, token, sp_cookie, sp_cookie)

        assert response.status_code == HTTPStatus.OK

        assert re.search(sp_message, response.text) is not None

        # Check that when the user accesses the secured page of SP1 with the old session cookie,
        # he is redirected to log in

        req_get_sp_login_reload_page = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/{path}".format(
                scheme=sp_scheme,
                port=sp_port,
                ip=sp_ip,
                path=sp_path
            ),
            headers=header,
            cookies={**session_cookie}
        )

        prepared_request = req_get_sp_login_reload_page.prepare()

        log_request(logger, req_get_sp_login_reload_page)

        response = s.send(prepared_request, verify=False, allow_redirects=False)

        logger.debug(response.status_code)

        # Assert that the refresh page gives a 302 which signals that the user is logged out of SP
        assert response.status_code == HTTPStatus.FOUND

        # Check if the user is logged out from SP2: perform a refresh of the page; we expect to get a redirect

        header_sp2_reload_page = {
            **header,
            'Host': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port),
        }

        req_get_sp_login_reload_page = Request(
            method='GET',
            url="{scheme}://{ip}:{port}/{path}".format(
                scheme=sp2_scheme,
                port=sp2_port,
                ip=sp2_ip,
                path=sp2_path
            ),
            headers=header_sp2_reload_page,
            cookies={**session_cookie}
        )

        prepared_request = req_get_sp_login_reload_page.prepare()

        log_request(logger, req_get_sp_login_reload_page)

        response = s.send(prepared_request, verify=False, allow_redirects=False)

        logger.debug(response.status_code)

        # Assert that the refresh page gives a 302 which signals that the user is logged out of SP2
        assert response.status_code == HTTPStatus.FOUND
        # the assert will fail as the single logout does not work for wsfed