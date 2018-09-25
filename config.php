<?php

//Logbunny v0.88
//Devs: pbologna at sitook.com -- kirsten at sitook.com

$i=0;

$bunny['rebuildglobalwhitelistcommand']="/scripts/rebuild_whitelist.sh";

$i++;
$configuration[$i]['label']="dovecotpostfix";
$configuration[$i]['file']="/var/log/mail.log";
$configuration[$i]['patterns']=array(
	"/(?P<timestamp>\S+.\S+.\S+).\S+.dovecot: auth-worker\(\d+\): (pam|sql)\(\S+,(?P<ip>\S+)\): (Password mismatch|unknown user)/",
	"/(?P<timestamp>\S+.\S+.\S+).\S+.(postfix\/submission\/smtpd|postfix\/smtpd)\[\d+\]: warning: \S+\[(?P<ip>\S+)\]: SASL PLAIN authentication failed/"
	);
$configuration[$i]['enabled']=TRUE;
$configuration[$i]['action']="/bin/ip route add unreachable __IP__";
$configuration[$i]['threshold']=10;
$configuration[$i]['expiryhits']=1800;

$i++;
$configuration[$i]['label']="openssh";
$configuration[$i]['file']="/var/log/auth.log";
$configuration[$i]['patterns']=array(
	"/(?P<timestamp>\S+.\S+.\S+).\S+.sshd\[\d+\]: Failed password for \S+ from (?P<ip>\S+)/"
	);
$configuration[$i]['enabled']=TRUE;
$configuration[$i]['action']="/bin/ip route add unreachable __IP__";
$configuration[$i]['threshold']=10;
$configuration[$i]['expiryhits']=1800;


?>
