#!/bin/bash
mkdir -p /scripts/LOGBUNNY/data/list.blocked
mkdir -p /scripts/LOGBUNNY/data/hits.count
mkdir -p /scripts/LOGBUNNY/data/list.peers
chmod 0 /scripts/LOGBUNNY/data/list.blocked /scripts/LOGBUNNY/data/hits.count /scripts/LOGBUNNY/data/list /scripts/LOGBUNNY/data/list.peers /scripts/LOGBUNNY/data
rm /scripts/LOGBUNNY/data/hits.count/*
rm /scripts/LOGBUNNY/data/list.blocked/*
rm /var/log/mail.log.done.dovecotpostfix
iptables -F INPUT
iptables -F OUTPUT
