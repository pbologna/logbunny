<?php

//Logbunny v0.881
//Devs: pbologna at sitook.com -- kirsten at sitook.com

//$mytag="dovecotpostfix";
$DEBUG=0;
$DEBUGFOLDER="";
include ("config.php");

if ($DEBUG==1)
{
	$DEBUGFOLDER=".debug";
}


foreach ($configuration as $oneconf)
{
        if ($oneconf['enabled']!==TRUE) {continue;}
	checkTree($oneconf,$DEBUG,$DEBUGFOLDER);
	scanWithConfiguration($oneconf,$DEBUG,$DEBUGFOLDER);
}

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

function scanWithConfiguration($oneconf,$DEBUG,$DEBUGFOLDER)
{
	$mytag=$oneconf['label'];
	$patterns=$oneconf['patterns'];
	$file2parse=$oneconf['file'];
	$threshold=$oneconf['threshold'];
	$expiryhits=$oneconf['expiryhits'];

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
				//so we can skip to the saved position
				$linenumber=$lastlinenumber;
				fseek($fp,$lastposition);
				echo "This was the file with saved position -- let's go to byte $lastposition (line $linenumber)\n";
				break;
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
				echo "File starts after saved position -- No Headcut at all\n";
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
		if ($inc%1500==0)
		{
			echo ".";
			$inc=0;
		}
		$headskip++;
	}
	
	echo "After headcut we are at line $linenumber\n";
	$matched=0;
/*
		$pattern1="/(?P<timestamp>\S+.\S+.\S+).\S+.dovecot: auth-worker\(\d+\): (pam|sql)\(\S+,(?P<ip>\S+)\): (Password mismatch|unknown user)/";
		$pattern2="/(?P<timestamp>\S+.\S+.\S+).\S+.(postfix\/submission\/smtpd|postfix\/smtpd)\[\d+\]: warning: \S+\[(?P<ip>\S+)\]: SASL PLAIN authentication failed/";
		$patterns=array(
				$pattern1,
				$pattern2
			);
*/


//LINE SCANNING STARTS HERE
	while(!feof($fp))
	{
		$linenumber++;
		$line = fgets($fp, 4096);
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
			if ($linenumber%10000==0)
			{
				if (preg_match($timepat,$line,$matches))
				{
					$time=strtotime($matches['timestamp']);
					writeLastTimestamp($file2parse,$time,$mytag,$line,$linenumber,$hash1stLine,$fp);
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
		writeLastTimestamp($file2parse,$time,$mytag,$line,$linenumber,$hash1stLine,$fp);
		print_r($matches);
		if($DEBUG==1 && $matched==2)
		{
			die("\ndebug stops after 2 matched\n");
		}
		//die("xxx");
	
	   $timestamp=$matches['timestamp'];
	   if ($lasttimestamp>$timestamp)
	   {
		//skipping as already processed
		$inc++;
	   }
	
	   if ($reason=="")
	   {
		print_r($vars);
		echo "No reason to count a hit - lets go on";
		//we have no reason to count
		continue;
	   }
	
	   if (!addHitCount($matches["ip"],$matches["timestamp"],$DEBUGFOLDER,$mytag,$threshold,$expiryhits))
	   {
	      // count is not enough - mark new hit and ignore
	      continue;
	   }
	
	   $fp2=fopen("/scripts/LOGBUNNY/data.".$mytag.$DEBUGFOLDER."/list.offenders/".$matches["ip"],"a+");
	   fputs($fp2,$reason);
	   fclose($fp2);
	   //print_r($vars);
	
	} //end of while
	fclose($fp);
} // End of scanWithConfiguration

function writeLastTimestamp($file2parse,$time,$mytag,$line,$linenumber,$hash1stLine,$fp)
{
	$line=trim($line);
	$pos=ftell($fp);
	echo "marking ".$file2parse.".done.".$mytag." with ".$time." (".date("M-d-Y H:i:s",$time).")\n";
	$fp=fopen($file2parse.".done.".$mytag,"w");
	fputs($fp,$time."\n".$line."\n".$linenumber."\n".$hash1stLine."\n".$pos);
	fclose($fp);
}

//grep ChallengeSent /var/log/asterisk/security  | grep AccountID=\"sip

function addHitCount($ip,$timestamp,$DEBUGFOLDER,$mytag,$threshold,$expiryhits)
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
	if ($ff)
	{
		$lasttime = fgets($ff, 4096);
		//get seconds from last hit - if too much then just mark this one as first hit
		if ($lasttime-$time>$expiryhits)
		{
			$lastcount = 1;
		}
		else
		{
			$lastcount = fgets($ff, 4096);
			$lastcount = $lastcount+1;
			echo "Incrementing count to $lastcount for $ip\n";
		}
	        fclose($ff);
	}
	else
	{
		$lastcount=1;
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
