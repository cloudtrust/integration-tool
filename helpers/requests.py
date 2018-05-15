import json
import logging

from helpers.logging import prepared_request_to_json
from helpers.logging import log_request

from bs4 import BeautifulSoup
from requests import Request

logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger('requests')
logger.setLevel(logging.DEBUG)


def access_sp_ws_fed(s, header, sp_ip, sp_port, sp_scheme, sp_path):
    # Access to the SP
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
    )

    prepared_request = req_get_sp_page.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_get_sp_page),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    return response


def access_sp_saml(s, header, sp_ip, sp_port, sp_scheme, sp_path, idp_ip, idp_port):

    # Access to the SP
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
    )

    prepared_request = req_get_sp_page.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_get_sp_page),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    # store the session cookie
    session_cookie = response.cookies

    # Response returns a form that requests a post with RelayState and SAMLRequest as input
    soup = BeautifulSoup(response.content, 'html.parser')

    form = soup.body.form
    url_form = form.get('action')
    method_form = form.get('method')
    inputs = form.find_all('input')

    # Do a SAML request to the identity provider
    saml_request = {}
    for input in inputs:
        saml_request[input.get('name')] = input.get('value')

    header_redirect_idp = {
        **header,
        'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
        'Referer': "{ip}:{port}".format(ip=sp_ip, port=sp_port)
    }

    req_idp_saml_request = Request(
        method=method_form,
        url="{url}".format(url=url_form),
        data=saml_request,
        headers=header_redirect_idp
    )

    prepared_request = req_idp_saml_request.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_idp_saml_request),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    return session_cookie, response


def access_sp_with_token(s, header, sp_ip, sp_port, idp_scheme, idp_ip, idp_port, method, url, token, session_cookie, keycloak_cookie):
    # Perform a callback
    header_callback = {
        **header,
        'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
        'Referer': "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port),
    }

    req_sp_with_response = Request(
        method=method,
        url="{url}".format(url=url),
        data=token,
        cookies=session_cookie,
        headers=header_callback
    )

    prepared_request = req_sp_with_response.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_sp_with_response),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    sp_cookie = response.cookies

    url_sp = response.headers['Location']

    # Browse to the service provider with the saml response
    header_login_sp = {
        **header,
        'Host': "{ip}:{port}".format(ip=sp_ip, port=sp_port),
        'Referer': "{scheme}://{ip}:{port}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port),
    }

    req_get_sp_page_final = Request(
        method='GET',
        url="{url}".format(url=url_sp),
        cookies={**session_cookie, **keycloak_cookie, **response.cookies},
        headers=header_login_sp
    )

    prepared_request = req_get_sp_page_final.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_get_sp_page_final),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    return response, sp_cookie


def redirect_to_idp(s, redirect_url, header, cookie):
    # Perform the redirect request of the identity provider

    req_get_keycloak = Request(
        method='GET',
        url="{url}".format(url=redirect_url),
        cookies=cookie,
        headers=header
    )

    prepared_request = req_get_keycloak.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_get_keycloak),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    return response


def send_credentials_to_idp(s, header, idp_ip, idp_port, redirect_url, url_form, credentials_data, cookie, method):

    header_login_keycloak = {
        **header,
        'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port),
        'Referer': "{host}".format(host=redirect_url),
    }

    req_login_idp = Request(
        method=method,
        url="{url}".format(url=url_form),
        data=credentials_data,
        cookies=cookie,
        headers=header_login_keycloak
    )
    prepared_request = req_login_idp.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_login_idp),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    return response


def login_idp(s, header, idp_ip, idp_port, idp_scheme, idp_path, idp_username, idp_password):

    # Requests access to the SP
    header_idp_page = {
        **header,
        'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port)
    }

    req_get_idp_page = Request(
        method='GET',
        url="{scheme}://{ip}:{port}/{path}".format(scheme=idp_scheme, ip=idp_ip, port=idp_port, path=idp_path),
        headers=header_idp_page,
    )

    prepared_request = req_get_idp_page.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_get_idp_page),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    oath_cookie = response.cookies

    url_redirect = response.headers['Location']

    req_idp_redirect = Request(
        method='GET',
        url="{url}".format(url=url_redirect),
        headers=header_idp_page
    )

    prepared_request = req_idp_redirect.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_idp_redirect),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    keycloak_cookie = response.cookies

    soup = BeautifulSoup(response.content, 'html.parser')

    form = soup.body.form

    url_form = form.get('action')
    method_form = form.get('method')

    credentials_data = {}
    credentials_data["username"] = idp_username
    credentials_data["password"] = idp_password

    header_login_keycloak = {
        **header,
        'Host': "{ip}:{port}".format(ip=idp_ip, port=idp_port)
    }

    req_login_idp = Request(
        method=method_form,
        url="{url}".format(url=url_form),
        data=credentials_data,
        cookies=keycloak_cookie,
        headers=header_login_keycloak
    )
    prepared_request = req_login_idp.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_login_idp),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    keycloak_cookie2 = response.cookies

    url_redirect = response.headers['Location']

    req_idp_redirect = Request(
        method='GET',
        url="{url}".format(url=url_redirect),
        headers=header_login_keycloak,
        cookies=keycloak_cookie2
    )

    prepared_request = req_idp_redirect.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_idp_redirect),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    keycloak_cookie3 = response.cookies

    url_redirect = response.headers['Location']

    req_idp_redirect = Request(
        method='GET',
        url="{url}".format(url=url_redirect),
        headers=header_login_keycloak,
        cookies=keycloak_cookie3
    )

    prepared_request = req_idp_redirect.prepare()

    logger.debug(
        json.dumps(
            prepared_request_to_json(req_idp_redirect),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )

    response = s.send(prepared_request, verify=False, allow_redirects=False)

    logger.debug(response.status_code)

    return oath_cookie, keycloak_cookie, keycloak_cookie2, response


def get_access_token(s, data, idp_scheme, idp_port, idp_ip, realm_id):

    req_get_access_token = Request(
        method='POST',
        url="{scheme}://{ip}:{port}/auth/realms/{realm}/protocol/openid-connect/token".format(
            scheme=idp_scheme,
            ip=idp_ip,
            port=idp_port,
            realm=realm_id
        ),
        data=data
    )

    prepared_request = req_get_access_token.prepare()

    log_request(logger, req_get_access_token)

    response = s.send(prepared_request, verify=False)

    logger.debug(response.status_code)

    access_token = json.loads(response.text)['access_token']

    return access_token



