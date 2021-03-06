<?php

//Logbunny v0.91
//Devs: pbologna at sitook.com -- kirsten at sitook.com

include("config.php");
$DEBUGFOLDER="";

$lofp = fopen("/tmp/logbunny-STEP2.pid", "w+");
if (flock($lofp, LOCK_EX | LOCK_NB)) {  // acquire an exclusive lock
    ftruncate($lofp, 0);      // truncate file
    fwrite($lofp, "Write something here\n");
} else {
    die("Couldn't get the lock!");
}

foreach ($configuration as $oneconf)
{
        if ($oneconf['enabled']!==TRUE) {continue;}
	applyActions($oneconf,$DEBUGFOLDER);
}

    fflush($lofp);            // flush output before releasing the lock
    flock($lofp, LOCK_UN);    // release the lock

function rebuildGlobalWhitelist()
{
	if (isset($bunny['rebuildglobalwhitelistcommand']) && $bunny['rebuildglobalwhitelistcommand']!="")
	{
		echo "Running ".$bunny['rebuildglobalwhitelistcommand'];
		exec($bunny['rebuildglobalwhitelistcommand']);
	}
}

function applyActions($oneconf,$DEBUGFOLDER)
{
	$basedir="/scripts/LOGBUNNY/data.".$oneconf['label'].$DEBUGFOLDER;
	$globalwhitelistdir="/scripts/LOGBUNNY/data".$DEBUGFOLDER."/list.white";
	$whitelistdir=$basedir."/list.white";
	$offendersdir=$basedir."/list.offenders";
	$blockeddir=$basedir."/list.offenders";
	$actiontemplate=$oneconf['action'];
	echo "Scanning $offendersdir\n";
	$cdir = scandir($offendersdir);
	foreach ($cdir as $key => $value)
	{
		if (!is_dir($value))
		{
			if (file_exists($globalwhitelistdir."/".$value))
			{
				echo "present in global whitelist -- doing nothing\n";
				continue;
			}
			if (file_exists($whitelistdir."/".$value))
			{
				echo "present in local whitelist -- doing nothing\n";
				continue;
			}

			$builtAction=str_replace("__IP__",$value,$actiontemplate);
			echo "applyActions at ".$oneconf['label'].$DEBUGFOLDER." -- Exec: ".$builtAction."\n";
			exec($builtAction);
		        //echo "" > /scripts/LOGBUNNY/data/list.iptables/${i}

		}
	}
}

/*
for i in $(ls -1 /scripts/LOGBUNNY/data/list)
do
#       if [ -e /scripts/LOGBUNNY/data/list.iptables/${i} ]
#       then
#               continue
#       fi
        if [ -e /scripts/LOGBUNNY/data/list.white/${i} ]
        then
                continue
        fi
        #iptables -A INPUT -s ${i} -j DROP
        #iptables -A OUTPUT -d ${i} -j DROP
        #route add ${i} reject
        ip route add unreachable ${i}
        echo "" > /scripts/LOGBUNNY/data/list.iptables/${i}
done

*/
?>
