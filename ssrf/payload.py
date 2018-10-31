#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : mr.chery (mr.chery666@gmail.com)
import yaml
from tools import payload_set
import requests


class payload_exploit(object):

    def __init__(self, payload_name, url, host, param):
        self.url = url
        self. param = param
        self.host = host
        self.payload_name = payload_name

    def payload_attack(self):
        with open('././payload.yaml') as f:
            payload_dict = yaml.load(f)
        attack_data = payload_dict[self.payload_name]
        payload = self.host + attack_data
        attack_url = payload_set.url_payload_set(self.url, self.param, payload)
        requests.get(attack_url)


def payload_list():
    with open('././payload.yaml') as f:
        payload_dict = yaml.load(f)
    return payload_dict

