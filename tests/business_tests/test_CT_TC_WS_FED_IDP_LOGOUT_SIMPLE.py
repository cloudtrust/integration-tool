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
from helpers.logging import log_request

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
logger = logging.getLogger('acceptance-tool.tests.business_tests.test_CT_TC_SAML_IDP_LOGOUT_SIMPLE')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'login_sso_form', scope='class')
class Test_test_CT_TC_WS_FED_IDP_LOGOUT_SIMPLE():
    """
    Class to test the CT_TC_WS_FED_IDP_LOGOUT_SIMPLE use case:
    As a resource owner I need the solution to ensure that all access tokens/sessions are invalidated and not usable
    anymore after the user has proceeded to a logout on the target application.
    """

    def test_CT_TC_WS_FED_IDP_LOGOUT_SIMPLE(self, settings, login_sso_form):
        """
        Test the CT_TC_WS_FED_IDP_LOGOUT_SIMPLE use case with the SP-initiated flow, i.e. the user that accessed the SP
        asks to be logged out. This will trigger the logout to be performed on the IDP side and the user will
        be able to see the "You're logged out" page.
        :param settings:
        :return:
        """

        s = Session()


        # Service provider settings
        sp = settings["sps_wsfed"][0]
        sp_ip = sp["ip"]
        sp_port = sp["port"]
        sp_scheme = sp["http_scheme"]
        sp_logout_path = sp["logout_path"]
        sp_message = sp["logged_out_message"]

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

        # User is logged in

        # Access to the SP logout page
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
            cookies=sp_cookie
        )

        prepared_request = req_get_sp_logout_page.prepare()

        log_request(logger, req_get_sp_logout_page)

        response = s.send(prepared_request, verify=False, allow_redirects=False)

        logger.debug(response.status_code)

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

        (response, cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port,
                                                      method_form, url_form, token, sp_cookie, sp_cookie)

        assert response.status_code == 200

        assert re.search(sp_message, response.text) is not None
