<?php
$i=0;

$i++;
$configuration[$i]['label']="dovecotpostfix";
$configuration[$i]['file']="/var/log/mail.log";
$configuration[$i]['patterns']=array(
	"/(?P<timestamp>\S+.\S+.\S+).\S+.dovecot: auth-worker\(\d+\): (pam|sql)\(\S+,(?P<ip>\S+)\): (Password mismatch|unknown user)/",
	"/(?P<timestamp>\S+.\S+.\S+).\S+.(postfix\/submission\/smtpd|postfix\/smtpd)\[\d+\]: warning: \S+\[(?P<ip>\S+)\]: SASL PLAIN authentication failed/"
	)


?>
