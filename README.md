<h2>#About</h2>
<p>logbunny is intended to parse logs and ban (iptables, route, whatever) bruteforce attacks to services like postfix, dovecot, openssh, etc.</p>

<h2>#Features</h2>
<ul>
<li>does fast resume of log reading by saving offset position</li>
<li>does support MaxTimeBack so that one can ignore timestamps before a certain amount of time (for a quick startup!)</li>
<li>hit counts are stored on per-IP basis and can be analyzed as simple as reading a file</li>
<li>each single configuration can have its own hit counts, patterns, threshold and actions</li>
<li>supports RBL and scoring on per-specific-configuration basis. Ie. rblscore is 10 and IP is hit.counted (1) and positive to 4 RBL services, hit.count will be equal to 1+10x4=41.</li>
<li>support whitelists (global and per-specific-configuration) with pre-command to refresh whitelist via your own API before blocklist is applied</li>
<li>supports per-country increment hit. Ie. one hit from Brasil can worth +5 as we have no regular customers in Brasil so most likely it's gonna be a bad guy, while one hit from US is most likely legitimate and should not be penalized</li>
</ul>

<h2>#Installation</h2>
<p>here is how to install Logbunny</p>
<pre>
# mkdir /tmp/logbunny
# cd /tmp/logbunny
# git clone https://github.com/pbologna/logbunny.git
Cloning into 'logbunny'...
...

install php5-cli and php5-geoip (if interested into geolocating IPs) if not present -- Debian example:
# apt-get update
# apt-get install php5-cli
# apt-get install php5-geoip

make your whitelist like this -- in this example we add 127.0.0.1 and 10.0.0.254 to whitelist:
# mkdir /scripts/LOGBUNNY/data/list.white
# touch /scripts/LOGBUNNY/data/list.white/127.0.0.1
# touch /scripts/LOGBUNNY/data/list.white/10.0.0.254

to check behaviour you may run script to parse logs:
php /scripts/LOGBUNNY/SECURE_STEP1.sh

to check behaviour you may run script to apply actions:
php /scripts/LOGBUNNY/SECURE_STEP2.sh

edit /scripts/LOGBUNNY/SECURE_STEP1.sh and check DEBUG variable:
- DEBUG=1 means we stop parsing after 2 matches
- DEBUG=0 means we are in production

whenever you are satisfied you can automatize the run via crontab
adding the following suggested lines to /etc/crontab -- scan logs every 2 minutes and apply blocks every 3 minutes:
*/2 *   * * *   root    /scripts/LOGBUNNY/SECURE_STEP1.sh >/dev/null 2>&1
*/3 *   * * *   root    /scripts/LOGBUNNY/SECURE_STEP2.sh >/dev/null 2>&1

you can check what is being done by tailing logfile!
tail -f /scripts/LOGBUNNY/log

</pre>
<h2>#Configuration</h2>
<p>here is an example of configuration file (config.php):</p>
<pre>
$i=0;

$bunny['rebuildglobalwhitelistcommand']="/scripts/rebuild_whitelist.sh";
$bunny['maxTimeBack']=1800;
$bunny['rblhosts']=array(
                "bl.spamcop.net",
                "sbl-xbl.spamhaus.org"
        );

//global geoip scores to be used when specific configuration doesn't have one
$bunny['geoipscores']=array(
                                        "*"=>0,  //no penalty by default
                                        "IT"=>0, //no penalty for Italy
                                        "BR"=>5, //+5 penalty for BR
                                        "AL"=>5, //+5 penalty for AL
                                        "PL"=>5  //+5 penalty for PL
                                        );

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
$configuration[$i]['rblenabled']=TRUE;
$configuration[$i]['rblscore']=3;

//geoip-based penalties for this specific service
$configuration[$i]['geoipscores']=array(
                                        "*"=>0,
                                        "IT"=>0,
                                        "BR"=>6,
                                        "AL"=>6,
                                        "PL"=>6
                                        );

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
$configuration[$i]['rblenabled']=TRUE;
$configuration[$i]['rblscore']=3;

</pre>

<h2>#How it works</h2>
<p>STEP1 is all about collecting data and building a directory tree at LOGBUNNY/data</p>
<p>STEP2 is the procedure that moves offenders to the blocked list, executing actions</p>
<i>At the moment of writing some configurable option is still hardcoded (Ie. path is /scripts/LOGBUNNY).</i>

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

at development stage LOGBUNNY is at /scripts/LOGBUNNY and this path is still hardcoded

</pre>

<h3>$bunny['rblhosts']</h3> <p>contains RBL host suffixes to scan for</h3>

<h3>geoipscores</h3> <p>contains an array of penalties to apply on hits on per-country basis. Ie. one hit from Brasil can worth +5 as we have no regular customers in Brasil -- Thereis a global $bunny['geoipscores'] that applies to whatever configuration has geoipenabled=TRUE and then every configuration may have its own specific geoipscores</p>

<h3>$bunny['rebuildglobalwhitelistcommand']</h3> <p>can point to whatever executable to be run just before STEP2 does its action-running work</p>

<h3>$bunny['maxTimeBack']</h3> <p>is the max amount of seconds we can look in the past, every log line that refers to an earlier time is discarded -- 0 means disabled</p>

<h3>hits.count</h3> <p>contains filenames whose name is IP, content is last hit time and number of hits -- when hit number is more than threshold, the file is moved to list.offenders</p>

<h3>list.white</h3> <p>contains filenames whose name is IP, content can be null -- Be aware there is a GLOBAL whitelist and a LOCAL whitelist for each labeled service</p>

<h3>list.offenders</h3> <p>contains filenames whose name is IP, this file comes from hits.count (moved from there when hit number is more than threshold) and it is intended to be moved again to list.blocked by the STEP2 procedure, that is also responsable about ignoring white-listed IPs (list.white)</p>

<h3>enabled</h3> <p>is a flag, can be TRUE or FALSE. Disables/enables a specific configuration</p>

<h3>expiryhits</h3> <p>is the max gap in seconds to consider hits together: if you use 1800 and the second hit arrives 1801 seconds after the first, the count will be resetted to 1 as the second hit arrives.</p>

<h3>threshold</h3> <p>is the max number of hits that makes an IP move from hits.count list to list.offenders.</p>

<h3>action</h3> <p>is a string containing the command to be run over list.offenders. The command should contain __IP__ as placeholder for real IP.</p>

<h3>rblenabled</h3> <p>is a flag, can be TRUE or FALSE. Disables/enables RBL for a specific configuration</p>

<h3>rblscore</h3> <p>is an integer. If IP results positive hitcount is incremented by this number multiplied by the number of RBL who reported positive</p>

<h2>#Contacts</h2>

Developers: pbologna at sitook.com -- kirsten at sitook.com
