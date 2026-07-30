"""Minimal cgi module for Cython 0.29.x compat on Python 3.13+."""
import html
from urllib.parse import parse_qs, parse_qsl


def escape(s, quote=True):
    return html.escape(s, quote=quote)


def parse_header(line):
    from email.message import Message
    m = Message()
    m['content-type'] = line
    return m.get_content_type(), m.get_params()
