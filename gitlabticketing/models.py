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

from __future__ import unicode_literals

from django.db import models


class gitlabsetting(models.Model):
    gitlab_server = models.TextField(blank=True, null=True)
    gitlab_token = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)

    @staticmethod
    def get_gitlab_url(username):
        gitlab_settings = gitlabsetting.objects.filter(username=username)
        return gitlab_settings[0].gitlab_server if gitlab_settings.count() > 0 else ''
