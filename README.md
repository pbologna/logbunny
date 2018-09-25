<h2>#About</h2>
<p>logbunny is intended to parse logs and ban (iptables, route, whatever) bruteforce attacks to services like postfix, dovecot, openssh, etc.</p>

<h2>#Configuration</h2>
<p>it supports a configuration file (config.php) like this:</p>
<pre>
$i=0;

$i++;
$configuration[$i]['label']="dovecotpostfix";
$configuration[$i]['file']="/var/log/mail.log";
$configuration[$i]['patterns']=array(
        "/(?P<timestamp>\S+.\S+.\S+).\S+.dovecot: auth-worker\(\d+\): (pam|sql)\(\S+,(?P<ip>\S+)\): (Password mismatch|unknown user)/",
        "/(?P<timestamp>\S+.\S+.\S+).\S+.(postfix\/submission\/smtpd|postfix\/smtpd)\[\d+\]: warning: \S+\[(?P<ip>\S+)\]: SASL PLAIN authentication failed/"
        )
</pre>

<h2>#How it works</h2>
<p>STEP1 is all about collecting data and building a directory tree at LOGBUNNY/data</p>
<p>STEP2 is the procedure that moves offenders to the blocked list, executing actions</p>
<i>At the moment of writing some configurable option is still hardcoded (Ie. threshold and block action).</i>

<pre>
LOGBUNNY/data
    |___________hits.count
    |                 |___________192.168.13.15
    |                 |___________192.168.13.16
    |___________list.white
    |                 |___________192.168.1.1
    |                 |___________192.168.1.2
    |                 |___________192.168.1.3
    |___________list.offenders
    |                 |___________192.168.13.17
    |                 |___________192.168.13.18
    |___________list.blocked
                      |___________192.168.13.19
                      |___________192.168.13.20
</pre>

<h3>hits.count</h3> <p>contains filenames whose name is IP, content is last hit time and number of hits -- when hit number is more than threshold, the file is moved to list.offenders</p>

<h3>list.white</h3> <p>contains filenames whose name is IP, content can be null</p>

<h3>list.offenders</h3> <p>contains filenames whose name is IP, this file comes from hits.count (moved from there when hit number is more than threshold) and it is intended to be moved again to list.blocked by the STEP2 procedure, that is also responsable about ignoring white-listed IPs (list.white)</p>

<h2>#Contacts</h2>

Developers: pbologna at sitook.com -- kirsten at sitook.com
