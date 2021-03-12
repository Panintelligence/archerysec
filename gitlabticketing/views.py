# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, HttpResponseRedirect
from gitlabticketing.models import gitlabsetting
from django.core import signing
from webscanners.models import zap_scan_results_db, \
    burp_scan_result_db, arachni_scan_result_db, netsparker_scan_result_db, \
    acunetix_scan_result_db, \
    webinspect_scan_result_db
from staticscanners.models import bandit_scan_results_db, \
    findbugs_scan_results_db, \
    retirejs_scan_results_db, clair_scan_results_db, dependencycheck_scan_results_db, \
    trivy_scan_results_db, npmaudit_scan_results_db, nodejsscan_scan_results_db, tfsec_scan_results_db
from networkscanners.models import ov_scan_result_db, nessus_report_db
from django.urls import reverse
from notifications.signals import notify
import requests


def gitlab_setting(request):
    """

    :param request:
    :return:
    """
    r_username = request.user.username
    all_gitlab_settings = gitlabsetting.objects.filter(username=r_username)
    gitlab_url = ''
    gitlab_token = ''
    for gitlab in all_gitlab_settings:
        gitlab_url = gitlab.gitlab_server
        gitlab_token = signing.loads(gitlab.gitlab_token)

    if request.method == 'POST':
        gitlab_url = request.POST.get('gitlab_url')
        gitlab_token = request.POST.get('gitlab_token')

        gitlab_token = signing.dumps(gitlab_token)
        save_data = gitlabsetting(username=r_username,
                                  gitlab_server=gitlab_url,
                                  gitlab_token=gitlab_token)
        save_data.save()

        return HttpResponseRedirect(reverse('webscanners:setting'))

    return render(request, 'gitlab_setting_form.html', {'gitlab_server': gitlab_url,
                                                        'gitlab_token': gitlab_token
                                                        })


def submit_gitlab_ticket(request):
    r_username = request.user.username
    gitlab_setting = gitlabsetting.objects.filter(username=r_username)
    for gitlab in gitlab_setting:
        gitlab_url = gitlab.gitlab_server
        gitlab_token = signing.loads(gitlab.gitlab_token)

    url = "{}api/v4/projects?simple=true&per_page=100".format(gitlab_url)
    auth_token = 'bearer {}'.format(gitlab_token)
    resp = requests.get(url,
                        headers={'Authorization': auth_token})
    # TODO Needs updating to handle the pagination
    gitlab_projects = resp.json()

    if request.method == 'GET':
        summary = request.GET['summary']
        description = request.GET['description']
        scanner = request.GET['scanner']
        vuln_id = request.GET['vuln_id']
        scan_id = request.GET['scan_id']

        return render(request, 'submit_gitlab_ticket.html', {'gitlab_projects': gitlab_projects,
                                                             'summary': summary,
                                                             'description': description,
                                                             'scanner': scanner,
                                                             'vuln_id': vuln_id,
                                                             'scan_id': scan_id
                                                             })

    if request.method == 'POST':
        summary = request.POST.get('summary')
        description = request.POST.get('description')
        scanner = request.POST.get('scanner')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        project_id = request.POST.get('project_id')

        issue_dict = {
            'title': summary,
            'description': description
        }

        url = "{}api/v4/projects/{}/issues".format(gitlab_url, project_id)
        auth_token = 'bearer {}'.format(gitlab_token)

        resp = requests.post(url,
                             headers={'Authorization': auth_token}, json=issue_dict)
        issue_json = resp.json()
        new_issue = issue_json["references"]["full"]

        if scanner == 'zap':
            zap_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(reverse('zapscanner:zap_vuln_details') + '?scan_id=%s&scan_name=%s' % (
                scan_id,
                summary
            ))
        elif scanner == 'burp':
            burp_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(reverse('burpscanner:burp_vuln_out') + '?scan_id=%s&scan_name=%s' % (
                scan_id,
                summary
            ))
        elif scanner == 'arachni':
            arachni_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('arachniscanner:arachni_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id, summary))

        elif scanner == 'netsparker':
            netsparker_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(
                gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('netsparkerscanner:netsparker_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id, summary))

        elif scanner == 'webinspect':
            webinspect_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(
                gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('webinspectscanner:webinspect_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id, summary))

        elif scanner == 'acunetix':
            acunetix_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('acunetixscanner:acunetix_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id, summary))

        elif scanner == 'bandit':
            bandit_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('banditscanner:banditscan_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'dependencycheck':
            dependencycheck_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(
                gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('dependencycheck:dependencycheck_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'findbugs':
            findbugs_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(
                gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('findbugs:findbugs_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'clair':
            clair_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('clair:clair_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'trivy':
            trivy_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('trivy:trivy_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'npmaudit':
            npmaudit_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(
                gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('npmaudit:npmaudit_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'nodejsscan':
            nodejsscan_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(
                gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('nodejsscan:nodejsscan_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'tfsec':
            tfsec_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('tfsec:tfsec_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'open_vas':
            ov_scan_result_db.objects.filter(username=r_username, vul_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(reverse('networkscanners:vul_details') + '?scan_id=%s' % scan_id)
        elif scanner == 'nessus':
            nessus_report_db.objects.filter(username=r_username, vul_id=vuln_id).update(gitlab_ticket=new_issue)
            return HttpResponseRedirect(reverse('networkscanners:nessus_vuln_details') + '?scan_id=%s' % scan_id)
