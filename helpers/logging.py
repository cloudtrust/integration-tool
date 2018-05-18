#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2018:
#     Sebastien Pasche, sebastien.pasche@elca.ch
#     Sonia Bogos , sonia.bogos@elca.ch
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
import json


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
