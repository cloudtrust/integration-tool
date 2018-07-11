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
import json
import logging

import helpers.requests as req
from helpers.logging import log_request

from bs4 import BeautifulSoup
from requests import Request, Session
from http import HTTPStatus


logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger('conftest')
logger.setLevel(logging.DEBUG)


def pytest_addoption(parser):
    parser.addoption("--config-file", action="store", help="Json configuration file ", dest="config_file")


@pytest.fixture(scope='session')
def settings(pytestconfig):
    try:
        with open(pytestconfig.getoption('config_file')) as json_data:
            config = json.load(json_data)

    except IOError as e:
        raise IOError("Config file {path} not found".format(path=pytestconfig.getoption('config_file')))

    return config


@pytest.fixture()
def login_sso_form(settings, pytestconfig):
    """
    Fixture to perform the log in
    :param settings: settings of the IDP and SP
    :param pytestconfig: fixture that provides the standard used for log in: WSFED or SAML
    :return:
    """
    standard = pytestconfig.getoption('standard')

    s = Session()

    # Standard
    if standard == "WSFED":
        client = "sps_wsfed"
    elif standard == "SAML":
        client = "sps_saml"

    # Service provider settings
    sp = settings[client][0]
    sp_ip = sp["ip"]
    sp_port = sp["port"]
    sp_scheme = sp["http_scheme"]
    sp_path = sp["path"]

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

    # Perform login
    if standard == "WSFED":
        response = req.access_sp_ws_fed(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path)
    elif standard == "SAML":
        (cookie1, response) = req.access_sp_saml(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                                        idp_ip, idp_port)

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
        response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data,
                                               keycloak_cookie, method_form)
    elif standard == "SAML":
        response = req.send_credentials_to_idp(logger, s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data,
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
        (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme, idp_ip,
                                                         idp_port, method_form, url_form, token, session_cookie,
                                                         keycloak_cookie_2)
    elif standard == "SAML":
        (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme, idp_ip,
                                                         idp_port, method_form, url_form, token, cookie1,
                                                         keycloak_cookie_2)

    return sp_cookie, keycloak_cookie_2


@pytest.fixture()
def login_broker_sso_form(settings, pytestconfig):
    """
    Fixture to perform the log in when we have a broker and an external IDP
    :param settings: settings of the IDP and SP
    :param pytestconfig: fixture that provides the standard used for log in: WSFED or SAML
    :return:
    """
    standard = pytestconfig.getoption('standard')

    s = Session()

    # Standard
    if standard == "WSFED":
        client = "sps_wsfed"
        idp_broker = settings["idp"]["saml_broker"]
    elif standard == "SAML":
        client = "sps_saml"
        idp_broker = settings["idp"]["wsfed_broker"]

    # Service provider settings
    sp = settings[client][0]
    sp_ip = sp["ip"]
    sp_port = sp["port"]
    sp_scheme = sp["http_scheme"]
    sp_path = sp["path"]

    # Identity provider settings
    idp_ip = settings["idp"]["ip"]
    idp_port = settings["idp"]["port"]
    idp_scheme = settings["idp"]["http_scheme"]

    idp2_ip = settings["idp_external"]["ip"]
    idp2_port = settings["idp_external"]["port"]
    idp2_scheme = settings["idp_external"]["http_scheme"]

    idp_username = settings["idp_external"]["test_realm"]["username"]
    idp_password = settings["idp_external"]["test_realm"]["password"]

    keycloak_login_form_id = settings["idp"]["login_form_id"]

    # Common header for all the requests
    header = req.get_header()

    (session_cookie, response) = req.access_sp_saml(logger, s, header, sp_ip, sp_port, sp_scheme, sp_path,
                                                    idp_ip, idp_port)


    # store the cookie received from keycloak
    keycloak_cookie = response.cookies

    redirect_url = response.headers['Location']

    header_redirect_idp = {
        **header,
        'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
        'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
    }

    response = req.redirect_to_idp(logger, s, redirect_url, header_redirect_idp, keycloak_cookie)

    # In the login page we can choose to login with the external IDP
    soup = BeautifulSoup(response.content, 'html.parser')

    div = soup.find("div", {"id": "kc-social-providers"})

    # we can have several idp external; choose the one needed for the test
    all_li = div.find_all('li')
    for li in all_li:
        if li.span.text == idp_broker:
            external_idp_url = "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port) + li.a[
                'href']

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

    url_form = form.get('action')
    method_form = form.get('method')
    inputs = form.find_all('input')

    input_name = []
    for input in inputs:
        input_name.append(input.get('name'))

    credentials_data = {}
    credentials_data["username"] = idp_username
    credentials_data["password"] = idp_password

    # Authenticate to the external IDP
    response = req.send_credentials_to_idp(logger, s, header, idp2_ip, idp2_port, referer_url, url_form,
                                           credentials_data, {**keycloak_cookie2, **session_cookie}, method_form)

    keycloak_cookie3 = response.cookies

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

    if response.status_code == HTTPStatus.FOUND: # user logs in for the first time and has to fill in a form
        response = req.broker_fill_in_form(logger, s, response, header, keycloak_cookie, idp_broker, settings)

    # Get the token (SAML response) from the broker IDP
    soup = BeautifulSoup(response.content, 'html.parser')
    form = soup.body.form

    url_form = form.get('action')
    inputs = form.find_all('input')
    method_form = form.get('method')

    token = {}
    for input in inputs:
        token[input.get('name')] = input.get('value')

    # Access SP with the token
    (response, sp_cookie) = req.access_sp_with_token(logger, s, header, sp_ip, sp_port, sp_scheme, idp_scheme,
                                                     idp_ip, idp_port, method_form, url_form, token, session_cookie,
                                                     keycloak_cookie)

    return sp_cookie, keycloak_cookie3, response.status_code


@pytest.fixture(scope='session')
def export_realm(settings):
    """
    Fixture to perform the export of a realm to a JSON file
    :param settings:
    :return:
    """

    # Identity provider settings
    idp_ip = settings["idp"]["ip"]
    idp_port = settings["idp"]["port"]
    idp_scheme = settings["idp"]["http_scheme"]

    idp_username = settings["idp"]["master_realm"]["username"]
    idp_password = settings["idp"]["master_realm"]["password"]
    idp_client_id = settings["idp"]["master_realm"]["client_id"]

    idp_realm_id = settings["idp"]["master_realm"]["name"]

    idp_realm_test = settings["idp"]["test_realm"]["name"]

    filename = settings["idp"]["test_realm"]["json_file"]

    s = Session()

    access_token_data={
        "client_id": idp_client_id,
        "username": idp_username,
        "password": idp_password,
        "grant_type": "password"
    }

    access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)

    header = {
        'Accept': "application/json,text/plain, */*",
        'Accept-Encoding': "gzip, deflate",
        'Accept-Language': "en-US,en;q=0.5",
        'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
        'Connection': "keep-alive",
        'Content-Type': "application/json",
        'Referer': "{scheme}://{ip}:{port}/auth/admin/master/console/".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port
        ),
        'Host': "{ip}:{port}".format(
            ip=idp_ip,
            port=idp_port
        ),
        "DNT": "1",
        "Keep-Alive": "timeout=15, max=3",
        'Authorization': 'Bearer ' + access_token

    }

    req_export_realm = Request(
        method='GET',
        url="{scheme}://{ip}:{port}/auth/realms/{realm}/export/realm".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
            realm=idp_realm_test
        ),
        headers=header
    )

    prepared_request = req_export_realm.prepare()

    log_request(logger, req_export_realm)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    with open(filename, "w") as f:
        f.write(response.text)

    return response


@pytest.fixture(scope='session')
def import_realm(settings):
    """
    Fixture to perform the import of a realm from a JSON file
    :param settings:
    :return:
    """

    # Identity provider settings
    idp_ip = settings["idp"]["ip"]
    idp_port = settings["idp"]["port"]
    idp_scheme = settings["idp"]["http_scheme"]

    idp_username = settings["idp"]["master_realm"]["username"]
    idp_password = settings["idp"]["master_realm"]["password"]
    idp_client_id = settings["idp"]["master_realm"]["client_id"]

    idp_realm_id = settings["idp"]["master_realm"]["name"]

    filename = settings["idp"]["test_realm"]["json_file"]

    s = Session()

    access_token_data={
        "client_id": idp_client_id,
        "username": idp_username,
        "password": idp_password,
        "grant_type": "password"
    }

    access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)

    header = {
        'Accept': "application/json,text/plain, */*",
        'Accept-Encoding': "gzip, deflate",
        'Accept-Language': "en-US,en;q=0.5",
        'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
        'Connection': "keep-alive",
        'Content-Type': "application/json",
        'Referer': "{scheme}://{ip}:{port}/auth/admin/master/console/".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port
        ),
        'Host': "{ip}:{port}".format(
            ip=idp_ip,
            port=idp_port
        ),
        "DNT": "1",
        "Keep-Alive": "timeout=15, max=3",
        'Authorization': 'Bearer ' + access_token

    }

    with open(filename, "r") as f:
        realm_representation = f.read()

    req_import_realm = Request(
        method='POST',
        url="{scheme}://{ip}:{port}/auth/admin/realms".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
        ),
        headers=header,
        data=realm_representation
    )

    prepared_request = req_import_realm.prepare()

    log_request(logger, req_import_realm)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    return response


@pytest.fixture(scope='session')
def import_realm_external(settings):
    """
    Fixture to perform the import of the external realm from a JSON file
    :param settings:
    :return:
    """

    # Identity provider settings
    idp_ip = settings["idp_external"]["ip"]
    idp_port = settings["idp_external"]["port"]
    idp_scheme = settings["idp_external"]["http_scheme"]

    idp_username = settings["idp_external"]["master_realm"]["username"]
    idp_password = settings["idp_external"]["master_realm"]["password"]
    idp_client_id = settings["idp_external"]["master_realm"]["client_id"]

    idp_realm_id = settings["idp_external"]["master_realm"]["name"]

    filename = settings["idp_external"]["test_realm"]["json_file"]

    s = Session()

    access_token_data={
        "client_id": idp_client_id,
        "username": idp_username,
        "password": idp_password,
        "grant_type": "password"
    }

    access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)

    header = {
        'Accept': "application/json,text/plain, */*",
        'Accept-Encoding': "gzip, deflate",
        'Accept-Language': "en-US,en;q=0.5",
        'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
        'Connection': "keep-alive",
        'Content-Type': "application/json",
        'Referer': "{scheme}://{ip}:{port}/auth/admin/master/console/".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port
        ),
        'Host': "{ip}:{port}".format(
            ip=idp_ip,
            port=idp_port
        ),
        "DNT": "1",
        "Keep-Alive": "timeout=15, max=3",
        'Authorization': 'Bearer ' + access_token

    }

    with open(filename, "r") as f:
        realm_representation = f.read()

    req_import_realm = Request(
        method='POST',
        url="{scheme}://{ip}:{port}/auth/admin/realms".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
        ),
        headers=header,
        data=realm_representation
    )

    prepared_request = req_import_realm.prepare()

    log_request(logger, req_import_realm)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    return response



@pytest.fixture(scope='session')
def delete_realm(settings):
    """
    Fixture to perform the deletion of a realm from Keycloak
    :param settings:
    :return:
    """
    # Identity provider settings
    idp_ip = settings["idp"]["ip"]
    idp_port = settings["idp"]["port"]
    idp_scheme = settings["idp"]["http_scheme"]

    idp_username = settings["idp"]["master_realm"]["username"]
    idp_password = settings["idp"]["master_realm"]["password"]
    idp_client_id = settings["idp"]["master_realm"]["client_id"]

    idp_realm_id = settings["idp"]["master_realm"]["name"]

    idp_realm_test = settings["idp"]["test_realm"]["name"]

    s = Session()

    access_token_data={
        "client_id": idp_client_id,
        "username": idp_username,
        "password": idp_password,
        "grant_type": "password"
    }

    access_token = req.get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)

    header = {
        'Accept': "application/json,text/plain, */*",
        'Accept-Encoding': "gzip, deflate",
        'Accept-Language': "en-US,en;q=0.5",
        'User-Agent': "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
        'Connection': "keep-alive",
        'Content-Type': "application/json",
        'Referer': "{scheme}://{ip}:{port}/auth/admin/master/console/".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port
        ),
        'Host': "{ip}:{port}".format(
            ip=idp_ip,
            port=idp_port
        ),
        "DNT": "1",
        "Keep-Alive": "timeout=15, max=3",
        'Authorization': 'Bearer ' + access_token

    }

    req_delete_realm = Request(
        method='DELETE',
        url="{scheme}://{ip}:{port}/auth/admin/realms/{realm}".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
            realm=idp_realm_test
        ),
        headers=header,
    )

    prepared_request = req_delete_realm.prepare()

    log_request(logger, req_delete_realm)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    return response
