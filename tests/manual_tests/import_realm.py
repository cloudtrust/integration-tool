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

import sys
import json
import logging
import argparse

from http import HTTPStatus
from requests import Request, Session

logging.basicConfig(
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p'
)
logger = logging.getLogger('manual_tests.import_realm')
logger.setLevel(logging.DEBUG)

version="1.0"
prog_name = sys.argv[0]
usage = """{pn} [options]
Import a realm (found in a Json file) to the Keycloak
""".format(
    pn=prog_name
)
parser = argparse.ArgumentParser(prog="{pn} {v}".format(pn=prog_name, v=version), usage=usage)

parser.add_argument(
    '--config-file',
    dest="config",
    help='Path to the config file: Ex : ../config/config.json',
    required=True
)


def prepared_request_to_json(req):
    """
    Helper dedicated to translate python request Request to a json format
    """
    json_request = dict()

    json_request['url'] = req.url

    if hasattr(req, 'headers'):
        json_request['headers'] = {}
        for header, value in req.headers.items():
            json_request['headers'][header] = value

    if hasattr(req, 'cookies') and req.cookies is not None:
        json_request['cookies'] = {}
        for key in req.cookies.keys():
            json_request['cookies'][key] = req.cookies[key]

    if hasattr(req, 'body'):
        json_request['body'] = req.body

    return json_request


def log_request(logger, req):
    """
    Helper dedicated to log a request
    """
    logger.debug(
        json.dumps(
            prepared_request_to_json(req),
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )
    )


def get_access_token(logger, s, data, idp_scheme, idp_port, idp_ip, realm_id):
    """
    Helper dedicated to obtain the access token for Keycloak
    :param logger:
    :param s: session s
    :param data: payload of the request
    :param idp_scheme: identity provider http scheme
    :param idp_port: identity provider port
    :param idp_ip: identity provider ip
    :param realm_id: id of the realm
    :return:
    """
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


if __name__ == "__main__":

    args = parser.parse_args()

    config_file = args.config

    if config_file:
        logger.info("loading config file from {path}".format(path=config_file))
        config = {}
        try:
            with open(config_file) as json_data:
                config = json.load(json_data)
                # Identity provider settings
                idp_ip = config["ip"]
                idp_port = config["port"]
                idp_scheme = config["http_scheme"]

                idp_username = config["username"]
                idp_password = config["password"]
                idp_client_id = config["client_id"]
                filename = config["json_file"]
        except IOError as e:
            logger.debug(e)
            raise IOError("Config file {path} not found".format(path=config_file))

    idp_realm_id = "master"

    s = Session()

    access_token_data={
        "client_id": idp_client_id,
        "username": idp_username,
        "password": idp_password,
        "grant_type": "password"
    }

    access_token = get_access_token(logger, s, access_token_data, idp_scheme, idp_port, idp_ip, idp_realm_id)

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

    if response.status_code == HTTPStatus.CREATED:
        print("Import of realm successfully done")
    else:
        if response.status_code == HTTPStatus.CONFLICT:
            print("Conflict: maybe the same realm exists already??")
        else:
            print("Something went wrong when trying to perform the import of the realm")
