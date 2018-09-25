<h2>#About</h2>
<p>logbunny is intended to parse logs and ban (iptables, route, whatever) bruteforce attacks to services like postfix, dovecot, openssh, etc.</p>

<h2>#Configuration</h2>
<p>it supports a configuration file (config.php) like this:</p>
<pre>
$i=0;

$bunny['rebuildglobalwhitelistcommand']="/scripts/rebuild_whitelist.sh";

$i++;
$configuration[$i]['label']="dovecotpostfix";
$configuration[$i]['file']="/var/log/mail.log";
$configuration[$i]['patterns']=array(
        "/(?P<timestamp>\S+.\S+.\S+).\S+.dovecot: auth-worker\(\d+\): (pam|sql)\(\S+,(?P<ip>\S+)\): (Password mismatch|unknown user)/",
        "/(?P<timestamp>\S+.\S+.\S+).\S+.(postfix\/submission\/smtpd|postfix\/smtpd)\[\d+\]: warning: \S+\[(?P<ip>\S+)\]: SASL PLAIN authentication failed/"
        )
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
</pre>

<h2>#How it works</h2>
<p>STEP1 is all about collecting data and building a directory tree at LOGBUNNY/data</p>
<p>STEP2 is the procedure that moves offenders to the blocked list, executing actions</p>
<i>At the moment of writing some configurable option is still hardcoded (Ie. threshold and block action).</i>

<pre>
LOGBUNNY/data
    |___________list.white
                      |___________192.168.1.1
                      |___________192.168.1.2
                      |___________192.168.1.3

LOGBUNNY/data.dovecotpostfix
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

LOGBUNNY/data.openssh
    |
   ...
</pre>

<h3>$bunny['rebuildglobalwhitelistcommand']</h3> <p>can point to whatever executable to be run just before STEP2 does its action-running work</h3>

<h3>hits.count</h3> <p>contains filenames whose name is IP, content is last hit time and number of hits -- when hit number is more than threshold, the file is moved to list.offenders</p>

<h3>list.white</h3> <p>contains filenames whose name is IP, content can be null -- Be aware there is a GLOBAL whitelist and a LOCAL whitelist for each labeled service</p>

<h3>list.offenders</h3> <p>contains filenames whose name is IP, this file comes from hits.count (moved from there when hit number is more than threshold) and it is intended to be moved again to list.blocked by the STEP2 procedure, that is also responsable about ignoring white-listed IPs (list.white)</p>

<h3>enabled</h3> <p>is a flag, can be TRUE or FALSE.</p>

<h3>expiryhits</h3> <p>is the max gap in seconds to consider hits together: if you use 1800 and the second hit arrives 1801 seconds after the first, the count will be resetted to 1 as the second hit arrives.</p>

<h3>threshold</h3> <p>is the max number of hits that makes an IP move from hits.count list to list.offenders.</p>

<h3>action</h3> <p>is a string containing the command to be run over list.offenders. The command should contain __IP__ as placeholder for real IP.</p>

<h2>#Contacts</h2>

Developers: pbologna at sitook.com -- kirsten at sitook.com
