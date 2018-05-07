#!/usr/bin/env python

# Copyright (C) 2018:
#     Sonia Bogos, sonia.bogos@elca.ch
#

import pytest
import logging
import re
import time
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
logger = logging.getLogger('test_CT_TC_WS_FED_IDP_LOGOUT_PERIMETRIC')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'login_sso_form', scope='class')
class Test_test_CT_TC_WS_FED_IDP_LOGOUT_PERIMETRIC():
    """
    #todo: update!!
    Class to test the test_CT_TC_WS_FED_IDP_LOGOUT_PERIMETRIC use case:
    As a resource owner I need the solution to ensure that all access tokens/sessions are invalidated and not usable
    anymore after the user has proceeded to a logout on the target application.
    """

    def test_CT_TC_WS_FED_IDP_LOGOUT_PERIMETRIC(self, settings, login_sso_form):
        """
        #todo: update
        Test the CT_TC_WS_FED_IDP_LOGOUT_SIMPLE use case with the SP-initiated flow, i.e. the user that accessed the SP
        asks to be logged out. This will trigger the logout to be performed on the IDP side and the user will
        be able to see the "You're logged out" page.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp_ip = settings["service_provider"]["ip"]
        sp_port = settings["service_provider"]["port"]
        sp_scheme = settings["service_provider"]["http_scheme"]
        sp_logout_path = settings["service_provider"]["logout_path"]
        sp_message = settings["service_provider"]["logged_out_message"]

        # Service provider settings
        sp2_ip = settings["service_provider2"]["ip"]
        sp2_port = settings["service_provider2"]["port"]
        sp2_scheme = settings["service_provider2"]["http_scheme"]
        sp2_logout_path = settings["service_provider2"]["logout_path"]
        sp2_path = settings["service_provider2"]["path"]
        sp2_message = settings["service_provider2"]["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["identity_provider"]["ip"]
        idp_port = settings["identity_provider"]["port"]
        idp_scheme = settings["identity_provider"]["http_scheme"]

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

        # User is logged in for the first SP

        # Perform login on the second SP

        response = req.access_sp_ws_fed(s, header, sp2_ip, sp2_port, sp2_scheme, sp2_path)

        session_cookie = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port)
        }

        response = req.redirect_to_idp(s, redirect_url, header_redirect_idp, {**keycloak_cookie})

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the ws fed response from the identity provider
        ws_fed_response = {}
        for input in inputs:
            ws_fed_response[input.get('name')] = input.get('value')

        (response, sp2_cookie) = req.access_sp_with_token(s, header, sp2_ip, sp2_port, idp_scheme, idp_ip, idp_port,
                                                         method_form, url_form, ws_fed_response, session_cookie,
                                                         keycloak_cookie)

        header_sp2_reload_page = {
                 **header,
                 'Host': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port),
                 'Referer': "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port) # why the referer is the IDP?
             }

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

        # User is now logged in on both applications

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

        logger.debug(
            json.dumps(
                prepared_request_to_json(req_get_sp_logout_page),
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )
        )

        response = s.send(prepared_request, verify=False, allow_redirects=False)

        logger.debug(response.status_code)

        # new session cookie
        session_cookie = response.cookies

        redirect_url = response.headers['Location']

        req_sp_logout_redirect = Request(
            method='GET',
            url= redirect_url,
            headers=header_sp_logout_page,
            cookies={**sp_cookie}
        )

        prepared_request = req_sp_logout_redirect.prepare()

        logger.debug(
            json.dumps(
                prepared_request_to_json(req_sp_logout_redirect),
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )
        )

        response = s.send(prepared_request, verify=False, allow_redirects=False)

        logger.debug(response.status_code)

        redirect_url = response.headers['Location']

        response = req.redirect_to_idp(s, redirect_url, header, sp_cookie)

        assert response.status_code == 200

        soup = BeautifulSoup(response.content, 'html.parser')

        form = soup.body.form
        url_form = form.get('action')
        method_form = form.get('method')
        inputs = form.find_all('input')

        # Send ws fed response
        token = {}
        for input in inputs:
            token[input.get('name')] = input.get('value')

        (response, cookie) = req.access_sp_with_token(s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port,
                                                      method_form, url_form, token, sp_cookie, sp_cookie)

        assert response.status_code == 200

        assert re.search(sp_message, response.text) is not None

        #Check if the user is logged out from the second applicaton: perform a refresh of the page; we expect to get a redirect

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

        # todo: ask about the session cookie!!

        prepared_request = req_get_sp_login_reload_page.prepare()

        logger.debug(
            json.dumps(
                prepared_request_to_json(req_get_sp_login_reload_page),
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )
        )

        response = s.send(prepared_request, verify=False, allow_redirects=False)

        logger.debug(response.status_code)

        assert response.status_code == 302
