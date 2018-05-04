#!/usr/bin/env python
# Copyright (C) 2018:
#     Sonia Bogos, sonia.bogos@elca.ch
#

import pytest
import json

import helpers.requests as req

from bs4 import BeautifulSoup
from requests import Request, Session


def pytest_addoption(parser):
    parser.addoption("--config-file", action="store", help="Json configuration file ", dest="config_file")
    parser.addoption("--standard", action="store", help="Oasis standard ", dest="standard")


@pytest.fixture()
def settings(pytestconfig):
    try:
        with open(pytestconfig.getoption('config_file')) as json_data:
            config = json.load(json_data)

    except IOError as e:
        raise IOError("Config file {path} not found".format(path=pytestconfig.getoption('config_file')))

    return config


@pytest.fixture()
def login_sso_form(settings, pytestconfig):

    standard = pytestconfig.getoption('standard')

    s = Session()

    # Service provider settings
    sp_ip = settings["service_provider"]["ip"]
    sp_port = settings["service_provider"]["port"]
    sp_scheme = settings["service_provider"]["http_scheme"]
    sp_path = settings["service_provider"]["path"]

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

    # Perform login
    if standard == "WSFED":
        response = req.access_sp_ws_fed(s, header, sp_ip, sp_port, sp_scheme, sp_path)
    elif standard == "SAML":
        (cookie1, response) = req.access_sp_saml(s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                                        idp_ip, idp_port)

    session_cookie = response.cookies

    redirect_url = response.headers['Location']

    header_redirect_idp = {
        **header,
        'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
        'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
    }

    response = req.redirect_to_idp(s, redirect_url, header_redirect_idp, session_cookie)

    keycloak_cookie = response.cookies

    soup = BeautifulSoup(response.content, 'html.parser')

    form = soup.find("form", {"id": keycloak_login_form_id})

    url_form = form.get('action')
    method_form = form.get('method')

    inputs = form.find_all('input')

    input_name = []
    for input in inputs:
        input_name.append(input.get('name'))

    # Simulate the login to the identity provider by providing the credentials
    credentials_data = {}
    credentials_data["username"] = idp_username
    credentials_data["password"] = idp_password

    if standard == "WSFED":
        response = req.send_credentials_to_idp(s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data,
                                               keycloak_cookie, method_form)
    elif standard == "SAML":
        response = req.send_credentials_to_idp(s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data,
                                               session_cookie, method_form)

    keycloak_cookie_2 = response.cookies

    soup = BeautifulSoup(response.content, 'html.parser')
    form = soup.body.form

    url_form = form.get('action')
    inputs = form.find_all('input')
    method_form = form.get('method')

    # Get the token from the IDP
    token = {}
    for input in inputs:
        token[input.get('name')] = input.get('value')

    if standard == "WSFED":
        (response, sp_cookie) = req.access_sp_with_token(s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port,
                                                         method_form, url_form, token, session_cookie, keycloak_cookie_2)
    elif standard == "SAML":
        (response, sp_cookie) = req.access_sp_with_token(s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port,
                                                         method_form, url_form, token, cookie1, keycloak_cookie_2)

    return sp_cookie
