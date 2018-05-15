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
logger = logging.getLogger('test_CT_TC_SAML_IDP_ACCESS_CONTROL_RBAC_KO')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', 'login_sso_form', scope='class')
class Test_test_CT_TC_SAML_IDP_ACCESS_CONTROL_RBAC_KO():
    """
    Class to test the test_CT_TC_SAML_IDP_ACCESS_CONTROL_RBAC_KO use case:
    As a resource owner, i need the solution to prevent end users switching between applications in a timeframe smaller
    than the allowed single sign on time span, to access applications they are not entitled to access.
    """

    def test_CT_TC_SAML_IDP_ACCESS_CONTROL_RBAC_KO_SP_initiated(self, settings, login_sso_form):
        """
        Scenario: User logs in to SP1 where he has the appropriate role.
        Same user tries to log in to SP2, SP that he is not authorized to access. He should receive an
        error message saying he has not the authorization to access SP2.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp_ip = settings["service_provider"]["ip"]
        sp_port = settings["service_provider"]["port"]
        sp_scheme = settings["service_provider"]["http_scheme"]
        sp_message = settings["service_provider"]["logged_in_message"]
        sp_path = settings["service_provider"]["path"]

        # Service provider 2 settings
        sp2_ip = settings["service_provider2"]["ip"]
        sp2_port = settings["service_provider2"]["port"]
        sp2_scheme = settings["service_provider2"]["http_scheme"]
        sp2_path = settings["service_provider2"]["path"]
        sp2_message = settings["service_provider2"]["unauthorized_message"]

        # Identity provider settings
        idp_ip = settings["identity_provider"]["ip"]
        idp_port = settings["identity_provider"]["port"]
        idp_scheme = settings["identity_provider"]["http_scheme"]

        idp_username = settings["identity_provider"]["username"]
        idp_password = settings["identity_provider"]["password"]

        keycloak_login_form_id = settings["identity_provider"]["login_form_id"]

        # Common header for all the requests
        header = {
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            'Accept-Encoding': "gzip, deflate",
            'Accept-Language': "en-US,en;q=0.5",
            'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
            'Connection': "keep-alive",
            'Upgrade-Insecure-Requests': "1",
        }

        # Perform login to SP1

        (session_cookie, response) = req.access_sp_saml(s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                        idp_ip, idp_port)

        assert response.status_code == 302

        # store the cookie received from keycloak
        keycloak_cookie = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
        }

        response = req.redirect_to_idp(s, redirect_url, header_redirect_idp, keycloak_cookie)

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

        response = req.send_credentials_to_idp(s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data,
                                               keycloak_cookie, method_form)

        assert response.status_code == 200 or response.status_code == 302 or response.status_code == 303 or response.status_code == 307

        keycloak_cookie_2 = response.cookies

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the SAML response from the identity provider
        saml_response = {}
        for input in inputs:
            saml_response[input.get('name')] = input.get('value')

        (response, sp_cookie) = req.access_sp_with_token(s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port,
                                                         method_form, url_form, saml_response, session_cookie,
                                                         keycloak_cookie_2)

        assert response.status_code == 200

        # assert that we are logged in
        assert re.search(sp_message, response.text) is not None

        # User is logged in on SP1

        # Attempt to perform login on SP2

        (session_cookie, response) = req.access_sp_saml(s, header, sp2_ip, sp2_port, sp2_scheme, sp2_path, idp_ip,
                                                        idp_port)

        session_cookie2 = response.cookies

        redirect_url = response.headers['Location']

        header_redirect_idp = {
            **header,
            'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
            'Referer': "{ip}:{port}".format(ip=sp2_ip, port=sp2_port)
        }

        response = req.redirect_to_idp(s, redirect_url, header_redirect_idp, {**session_cookie2, **keycloak_cookie_2})

        # Assert that the client is not authorized to access SP2
        assert response.status_code == 403

        assert re.search(sp2_message, response.text) is not None

