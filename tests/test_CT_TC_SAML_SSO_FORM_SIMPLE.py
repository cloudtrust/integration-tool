#!/usr/bin/env python

# Copyright (C) 2018:
#     Sonia Bogos, sonia.bogos@elca.ch
#

import pytest
import logging
import re

import helpers.requests as req

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
logger = logging.getLogger('test_CT_TC_SAML_SSO_FORM_SIMPLE')
logger.setLevel(logging.DEBUG)


@pytest.mark.usefixtures('settings', scope='class')
class Test_CT_TC_SAML_SSO_FORM_SIMPLE():
    """
    Class to test the CT_TC_SAML_SSO_FORM_SIMPLE use case:
    As a user I can access an application from any device with the SAML token delivered by the KEYCLOAK IDP after a
    successful form authentication.
    """

    def test_CT_TC_SAML_SSO_FORM_SIMPLE_SP_initiated(self, settings):
        """
        Test the CT_TC_SAML_SSO_FORM_SIMPLE use case with the SP-initiated flow, i.e. the user accesses the application
        , which is a service provider (SP), that redirects him to the keycloak, the identity provider (IDP).
        The user has to login to keycloak which will give him the SAML token. The token will give him access to the
        application.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp_ip = settings["service_provider"]["ip"]
        sp_port = settings["service_provider"]["port"]
        sp_scheme = settings["service_provider"]["http_scheme"]
        sp_path = settings["service_provider"]["path"]
        sp_message = settings["service_provider"]["logged_in_message"]

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

        (session_cookie, header_idp_saml_request, response) = req.access_sp(s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                                        idp_ip, idp_port)

        assert response.status_code == 302

        # store the cookie received from keycloak
        keycloak_cookie = response.cookies

        redirect_url = response.headers['Location']

        response = req.redirect_to_idp(s, redirect_url, header_idp_saml_request, keycloak_cookie)

        soup = BeautifulSoup(response.content, 'html.parser')

        form = soup.find("form",{"id": keycloak_login_form_id})

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

        response = req.send_credentials_to_idp(s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data, keycloak_cookie, method_form)

        #print(response.text)

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

        (response, sp_cookie) = req.access_sp_with_saml_token(s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port,
                                                          method_form, url_form, saml_response, session_cookie,
                                                          keycloak_cookie_2)

        assert response.status_code == 200

        # assert that we are logged in
        assert re.search(sp_message, response.text) is not None



    def test_CT_TC_SAML_SSO_FORM_SIMPLE_IDP_initiated(self, settings):
        """
        Test the CT_TC_SAML_SSO_FORM_SIMPLE use case with the IDP-initiated flow, i.e. the user logs in keycloak,
        the identity provider (IDP), and then accesses the application, which is a service provider (SP).
        The application redirect towards keycloak to obtain the SAML token.
        :param settings:
        :return:
        """

        s = Session()

        # Service provider settings
        sp_ip = settings["service_provider"]["ip"]
        sp_port = settings["service_provider"]["port"]
        sp_scheme = settings["service_provider"]["http_scheme"]
        sp_path = settings["service_provider"]["path"]
        sp_message = settings["service_provider"]["logged_in_message"]

        # Identity provider settings
        idp_ip = settings["identity_provider"]["ip"]
        idp_port = settings["identity_provider"]["port"]
        idp_scheme = settings["identity_provider"]["http_scheme"]
        idp_path = settings["identity_provider"]["path"]
        idp_message = settings["identity_provider"]["logged_in_message"]

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

        (oath_cookie, keycloak_cookie, keycloak_cookie2, response) = req.login_idp(s, header, idp_ip, idp_port, idp_scheme,
                                                                                idp_path, idp_username, idp_password)

        assert response.status_code == 200

        # Assert we are logged in
        assert re.search(idp_message, response.text) is not None

        (session_cookie, header_idp_saml_request, response) = req.access_sp(s, header, sp_ip, sp_port, sp_scheme, sp_path, idp_ip, idp_port)

        # store the cookie received from keycloak
        keycloak_cookie3 = response.cookies

        assert response.status_code == 302

        redirect_url = response.headers['Location']

        response = req.redirect_to_idp(s, redirect_url, header_idp_saml_request, {**keycloak_cookie3, **keycloak_cookie2})

        assert response.status_code == 200

        soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.body.form

        url_form = form.get('action')
        inputs = form.find_all('input')
        method_form = form.get('method')

        # Get the saml response from the identity provider
        saml_response = {}
        for input in inputs:
            saml_response[input.get('name')] = input.get('value')

        (response, sp_cookie) = req.access_sp_with_saml_token(s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port,
                                                          method_form, url_form, saml_response, session_cookie,
                                                          keycloak_cookie2)

        assert response.status_code == 200

        assert re.search(sp_message, response.text) is not None

