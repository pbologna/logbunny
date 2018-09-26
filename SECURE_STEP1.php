<?php

//Logbunny v0.90
//Devs: pbologna at sitook.com -- kirsten at sitook.com

//$mytag="dovecotpostfix";
$DEBUG=0;
$DEBUGFOLDER="";
include ("config.php");

$lofp = fopen("/tmp/logbunny.pid", "w+");
if (flock($lofp, LOCK_EX | LOCK_NB)) {  // acquire an exclusive lock
    ftruncate($lofp, 0);      // truncate file
    fwrite($lofp, "Write something here\n");
} else {
    die("Couldn't get the lock!");
}

if ($DEBUG==1)
{
	$DEBUGFOLDER=".debug";
}


foreach ($configuration as $oneconf)
{
        if ($oneconf['enabled']!==TRUE) {continue;}
	checkTree($oneconf,$DEBUG,$DEBUGFOLDER);
	scanWithConfiguration($oneconf,$bunny,$DEBUG,$DEBUGFOLDER);
}

    fflush($lofp);            // flush output before releasing the lock
    flock($lofp, LOCK_UN);    // release the lock

function checkTree($oneconf,$DEBUG,$DEBUGFOLDER)
{
	//make directories if they don't exist
	$mytag=$oneconf['label'];
	$dirarr=array(
			"/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER,
			"/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/hits.count",
			"/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/list.white",
			"/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/list.offenders",
			"/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/list.blocked"
			);
	foreach ($dirarr as $onedir)
	{
		if (!file_exists($onedir))
		{
			mkdir($onedir);
		}
	}
}

function scanWithConfiguration($oneconf,$bunny,$DEBUG,$DEBUGFOLDER)
{
	$mytag=$oneconf['label'];
	$patterns=$oneconf['patterns'];
	$file2parse=$oneconf['file'];
	$threshold=$oneconf['threshold'];
	$expiryhits=$oneconf['expiryhits'];
	$maxTimeBack=$bunny['maxTimeBack'];
	$rblhosts=$bunny['rblhosts'];
	$rblenabled=$oneconf['rblenabled'];
	$rblscore=$oneconf['rblscore'];
	$workablefile=1;

	$lasttimestamp="0";
	$lastline="";
	$timenow=time();
	$fp=fopen("/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/lastrun".$mytag,"w");
	if ($fp)
	{
		fputs($fp,$timenow."\n");
		fclose($fp);
	}

	$fp=fopen($file2parse.".done.".$mytag,"r");
	$lasttimestamp="0";
	$lasthash="invalid";
	if ($fp)
	{
		echo "Trying to use saved state from ".$file2parse.".done.\n";
		$lasttimestamp=trim(fgets($fp, 4096));
		$lastline=trim(fgets($fp, 4096));
		$lastlinenumber=trim(fgets($fp, 4096));
		$lasthash=trim(fgets($fp, 4096));
		$lastposition=trim(fgets($fp, 4096));
		fclose($fp);
	}
	
	$inc=0;
	$fsize=filesize($file2parse);
	$fp=fopen($file2parse,"r");
	echo "Searching for head...";
	$timepat="/(?P<timestamp>\S+.\S+.\S+)/";

	$headskip=0;
	$linenumber=-1;
	$firshlinehash="";

	while(!feof($fp))
	{
		$linenumber++;
		$prevPos=ftell($fp);
		$line = fgets($fp, 4096);
		if ($linenumber==0)
		{
			$hash1stLine=md5($line);
			echo "hash of first line calculated as $hash1stLine\n";
		}

		if ($lasttimestamp==0)
		{
			//no headcut at all
			//lets rollback so we are ready for line scanning
			echo "Saved Timestamp not consistent\n";
			fseek($fp,$prevPos);
			break;
		}

		if ($linenumber==0)
		{
			if ($hash1stLine==$lasthash)
			{
				//this is the file meant to be headcut
				//so we can skip to the saved position if filesize allows that
				if ($fsize>$lastposition)
				{
					$linenumber=$lastlinenumber;
					fseek($fp,$lastposition);
					echo "This was the file with saved position -- let's go to byte $lastposition (line $linenumber)\n";
					break;
				}
				else if ($fsize<$lastposition)
				{
					echo "This file has been truncated! Same header, different length! -- aborting\n";
					$workablefile=0;
					break;
				}
				else if ($fsize==$lastposition)
				{
					echo "Filesize ($fsize) unchanged since last scan ($lastposition) -- aborting\n";
					$workablefile=0;
					break;
				}
			}
			else
			{
				//not the file meant to headcut in
				//lets rollback so we are ready for line scanning
				echo "This was NOT the file we expect by position info as $hash1stLine is not $lasthash -- no headcut at all\n";
				fseek($fp,$prevPos);
				$lastline=-1;
				break;
			}
		}

		if (preg_match($timepat,$line,$matches))
		{
			$time=strtotime($matches['timestamp']);
			if ($time>$lasttimestamp)
			{
				//this line is already after the meant headcut
				//lets rollback
				echo "We are already after saved position ($time vs $lasttimestamp)\n";
				fseek($fp,$prevPos);
				$lastline=-1;
				break;
			}
			if ($time==$lasttimestamp && $line==$lastline)
			{
				echo "Exact headcut found at $lastline\n";
				//this line is exactly the last scanned (already scanned)
				//so lets go to on so that next fgets() will start from next line
				break;
			}
		}
		else
		{
			// "cant get timestamp at this line - lets skip
			continue;
		}
		if ($linenumber%1500==0)
		{
			echo ".";
		}
		$headskip++;
	} // while(!feof($fp))
	

	
	if ($workablefile==0)
	{
		//file marked as not workable
		//maybe unchanged! -- maybe truncated!
		return FALSE;
	}


        while(!feof($fp))
        {
                $linenumber++;
		$prevPos=ftell($fp);
                $line = fgets($fp, 4096);
                if (preg_match($timepat,$line,$matches))
                {
                        $time=strtotime($matches['timestamp']);
                        if (time()-$time<$maxTimeBack)
                        {
				echo "MaxTimeBack in action brought you this line: **$linenumber**\n";
				//lets roll back so that we provide with this line on next procedure
                        	fseek($fp,$prevPos);
                                break;
                        }
                        else
                        {
				if ($linenumber%15000==0)
				{
                                	echo "MaxTimeBack in action -- skipping $linenumber\n";
				}
				//lets go next
				continue;
                        }
                }
	}


	//LINE SCANNING STARTS HERE
	$lastline="";
	echo "After headcut we are at line $linenumber\n";
	$matched=0;
	while(!feof($fp))
	{
		$linenumber++;
		$line = fgets($fp, 4096);
		if (strlen($line)!=0)
		{
			$lastline=$line;
		}
	//	echo "while loop with lastline=**$lastline**\n";
	//	^%(__prefix_line)sauth-worker\(\d+\): (pam|sql)\(\S+,<HOST>\): (Password mismatch|unknown user)\s*$
	//	Sep 24 14:37:22 mx01 dovecot: auth-worker(8533): sql(pbologna@sitook.com,178.219.125.21): Password mismatch


		$foundMatch=0;
		$currentpat=-1;
		foreach ($patterns as $onepat)
		{
			$currentpat++;
			if (preg_match($onepat,$line,$matches))
			{
				$foundMatch=1;
				break;
			}
		}

		if ($foundMatch==0)
		{
			$currentpat=-1;
			//if not matching,
			//write one timestamp every 1500 lines so that on next run we are not going to rescan
			if ($linenumber%1000==0)
			{
				echo ".";
			}
			if ($linenumber%10000==0)
			{
				if (preg_match($timepat,$line,$matches))
				{
					$time=strtotime($matches['timestamp']);
					writeLastTimestamp($file2parse,$time,$mytag,$line,$linenumber,$hash1stLine,$fp,$timepat,__LINE__);
				}
			}
			continue;
		}
		else
		{
			$reason="matched".$currentpat;
		}

		$matched++;
		echo "------------------------\n\n\ncurrentpat:".$currentpat."\n";
		echo "MATCHED: ".$line."\n";
		echo "\n\n";
		$time=strtotime($matches['timestamp']);
		writeLastTimestamp($file2parse,$time,$mytag,$line,$linenumber,$hash1stLine,$fp,$timepat,__LINE__);
		print_r($matches);
		if($DEBUG==1 && $matched==2)
		{
			die("\ndebug stops after 2 matched\n");
		}
		//die("xxx");
	   $timestamp=$matches['timestamp'];
	   if ($reason=="")
	   {
		print_r($vars);
		echo "No reason to count a hit - lets go on";
		//we have no reason to count
		continue;
	   }
	   if (!addHitCount($matches["ip"],$matches["timestamp"],$DEBUGFOLDER,$mytag,$threshold,$expiryhits,$rblenabled,$rblhosts,$rblscore))
	   {
	      // count is not enough - mark new hit and ignore
	      continue;
	   }
	   $fp2=fopen("/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/list.offenders/".$matches["ip"],"a+");
	   fputs($fp2,$reason);
	   fclose($fp2);
	   //print_r($vars);
	} //end of while

	writeLastTimestamp($file2parse,"",$mytag,$lastline,$linenumber,$hash1stLine,$fp,$timepat,__LINE__);
	fclose($fp);
} // End of scanWithConfiguration

function writeLastTimestamp($file2parse,$time,$mytag,$line,$linenumber,$hash1stLine,$fp,$timepat,$caller)
{
//	echo "Entering writeLastTimestamp with line=**$line**";
	if ($time=="")
	{
		if (preg_match($timepat,$line,$matches))
		{
			$time=strtotime($matches['timestamp']);
		}
	}
	$line=trim($line);
	$pos=ftell($fp);
	echo "marking ".$file2parse.".done.".$mytag." with ".$time." (".date("M-d-Y H:i:s",$time).") -- $caller\n";
	$fp=fopen($file2parse.".done.".$mytag,"w");
	fputs($fp,$time."\n".$line."\n".$linenumber."\n".$hash1stLine."\n".$pos);
	fclose($fp);
}

//grep ChallengeSent /var/log/asterisk/security  | grep AccountID=\"sip

function addHitCount($ip,$timestamp,$DEBUGFOLDER,$mytag,$threshold,$expiryhits,$rblenabled,$rblhosts,$rblscore)
{
	$time=strtotime($timestamp);
	$timenow=time();
	/*
	if ($timenow-$time>1800)
	{
		//too old in the past - skipping
		return false;
	}*/
	$linz=array();
	$arr=array();

	$fname="/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/hits.count/".$ip;

	if (file_exists($fname))
	{
        	$ff=fopen($fname,"r");
	}
	else
	{
		$ff=false;
	}


	$increment=1;
	if ($rblenabled==TRUE)
	{
		$rbl_bad_hits=checkrbl($rblhosts,$rblscore,$ip);
		$increment=$increment+$rblscore*$rbl_bad_hits;
		if ($increment>1)
		{
			echo "Increment became $increment because of rbl\n";
		}
		else
		{
			echo "RBL had no effect on increment\n";
		}
	}
	else
	{
		echo "Skipping RBL check\n";
	}

	if ($ff)
	{
		$lasttime = fgets($ff, 4096);
		//get seconds from last hit - if too much then just mark this one as first hit
		if ($lasttime-$time>$expiryhits)
		{
			$lastcount = $increment;
		}
		else
		{
			$lastcount = fgets($ff, 4096);
			$lastcount = $lastcount+$increment;
			echo "Incrementing count to $lastcount for $ip\n";
		}
	        fclose($ff);
	}
	else
	{
		$lastcount=$increment;
	}

	echo "Marking new count: /scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/hits.count/".$ip." :".$lastcount."\n";
        $ff=fopen("/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/hits.count/".$ip,"w");
	fputs($ff,$time."\n".$lastcount."\n");
	fclose($ff);

	if ($lastcount>=$threshold)
	{
		return true;
	}

	return false;
}

function checkrbl($rblhosts,$rblscore,$ip)
{
	$total=0;
        $reverse_ip = implode(".", array_reverse(explode(".", $ip))); 
        foreach($rblhosts as $host){
            if(checkdnsrr($reverse_ip.".".$host.".", "A")){ 
	    	echo "Checking ".$reverse_ip.".".$host." -- MARKED\n";
                $total++; 
            }
	    else
	    {
		echo "Checking ".$reverse_ip.".".$host." -- CLEAN\n";
	    }
        }
	return $total;
}
