<?php

//Logbunny v0.902
//Devs: pbologna at sitook.com -- kirsten at sitook.com
/*

Changelog v0.902:
- replaced cbl.abuseat.org with sbl-xbl.spamhaus.org
- added SPF regex by default: if you are trying to personify another domain you're a bad guy and can take a hit on my scoretable
*/

$i=0;

$bunny['rebuildglobalwhitelistcommand']="/scripts/rebuild_whitelist.sh";
$bunny['maxTimeBack']=3600;
$bunny['rblhosts']=array(
		"bl.spamcop.net",
		"sbl-xbl.spamhaus.org"
	);

$i++;
$configuration[$i]['label']="dovecotpostfix";
$configuration[$i]['file']="/var/log/mail.log";
$configuration[$i]['patterns']=array(
	"/(?P<timestamp>\S+.\S+.\S+).\S+.dovecot: auth-worker\(\d+\): (pam|sql)\(\S+,(?P<ip>\S+)\): (Password mismatch|unknown user)/",
	"/(?P<timestamp>\S+.\S+.\S+).\S+.(postfix\/submission\/smtpd|postfix\/smtpd)\[\d+\]: warning: \S+\[(?P<ip>\S+)\]: SASL PLAIN authentication failed/",
	"/(?P<timestamp>\S+.\S+.\S+).\S+.postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from unknown\[(?P<ip>\S+)\]: 550 5.7.1 \<\S+\>: Recipient address rejected: Message rejected due to: SPF fail - not authorized./"
	);
$configuration[$i]['enabled']=TRUE;
$configuration[$i]['action']="/bin/ip route add unreachable __IP__";
$configuration[$i]['threshold']=5;
$configuration[$i]['expiryhits']=3600;
$configuration[$i]['rblenabled']=TRUE;
$configuration[$i]['rblscore']=3;

$i++;
$configuration[$i]['label']="openssh";
$configuration[$i]['file']="/var/log/auth.log";
$configuration[$i]['patterns']=array(
	"/(?P<timestamp>\S+.\S+.\S+).\S+.sshd\[\d+\]: Failed password for \S+ from (?P<ip>\S+)/"
	);
$configuration[$i]['enabled']=TRUE;
$configuration[$i]['action']="/bin/ip route add unreachable __IP__";
$configuration[$i]['threshold']=5;
$configuration[$i]['expiryhits']=3600;
$configuration[$i]['rblenabled']=TRUE;
$configuration[$i]['rblscore']=3;


?>
