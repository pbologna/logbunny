<?php
//$mytag="dovecotpostfix";
$DEBUG=1;
$DEBUGFOLDER="";
include ("config.php");

foreach ($configuration as $oneconf)
{
	scanWithConfiguration($oneconf,$DEBUG,$DEBUGFOLDER);
}

function scanWithConfiguration($oneconf,$DEBUG,$DEBUGFOLDER)
{
	$mytag=$oneconf['label'];
	$patterns=$oneconf['patterns'];
	$file=$oneconf['file'];
	if ($DEBUG==1)
	{
		$DEBUGFOLDER=".debug";
		$mytag=$mytag.".debug";
	}

	
	//	to fully reset (make analyzer analyze ALL from scratch:
	//	rm /var/log/asterisk/security.ana
	$lasttimestamp="0";
	$lastline="";
	$timenow=time();
	$fp=fopen("/scripts/LOGBUNNY/data".$DEBUGFOLDER."/lastrun".$mytag,"w");
	if ($fp)
	{
		fputs($fp,$timenow."\n");
		fclose($fp);
	}

	$fp=fopen($file.".done.".$mytag,"r");
	$lasttimestamp="0";
	if ($fp)
	{
		$lasttimestamp=fgets($fp, 4096);
		$lastline=fgets($fp, 4096);
		fclose($fp);
	}
	
	$inc=0;
	$fp=fopen($file."","r");
	echo "Searching for head...";
	$timepat="/(?P<timestamp>\S+.\S+.\S+)/";

	$headskip=0;
	while(!feof($fp))
	{
		if ($lasttimestamp==0)
		{
			//no head cut
			break;
		}
		$line = fgets($fp, 4096);
		if (preg_match($timepat,$line,$matches))
		{
			$time=strtotime($matches['timestamp']);
			if ($time>$lasttimestamp) {break;}
			if ($time==$lasttimestamp && $line==$lastline) {break;}
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
	
	echo "Head found by skipping $headskip\n";
	$cou=0;
	$matched=0;
/*
		$pattern1="/(?P<timestamp>\S+.\S+.\S+).\S+.dovecot: auth-worker\(\d+\): (pam|sql)\(\S+,(?P<ip>\S+)\): (Password mismatch|unknown user)/";
		$pattern2="/(?P<timestamp>\S+.\S+.\S+).\S+.(postfix\/submission\/smtpd|postfix\/smtpd)\[\d+\]: warning: \S+\[(?P<ip>\S+)\]: SASL PLAIN authentication failed/";
		$patterns=array(
				$pattern1,
				$pattern2
			);
*/
	while(!feof($fp))
	{
		$cou=$cou+1;
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
			if ($cou%1500==0)
			{
				if (preg_match($timepat,$line,$matches))
				{
					$time=strtotime($matches['timestamp']);
					writeLastTimestamp($file,$time,$mytag,$line);
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
		writeLastTimestamp($file,$time,$mytag,$line);
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
	
	   if (!addHitCount($matches["ip"],$matches["timestamp"],$DEBUGFOLDER))
	   {
	      // count is not enough - mark new hit and ignore
	      continue;
	   }
	
	   $fp2=fopen("/scripts/LOGBUNNY/data".$DEBUGFOLDER."/list.offenders/".$matches["ip"],"a+");
	   fputs($fp2,$reason);
	   fclose($fp2);
	   //print_r($vars);
	
	} //end of while
	fclose($fp);
	system("/scripts/SECURE_STEP2.sh");
}

function writeLastTimestamp($file,$time,$mytag,$line)
{
	echo "marking ".$file.".done.".$mytag." with ".$time." (".date("M-d-Y H:i:s",$time).")\n";
	$fp=fopen($file.".done.".$mytag,"w");
	fputs($fp,$time."\n".$line);
	fclose($fp);
}

//grep ChallengeSent /var/log/asterisk/security  | grep AccountID=\"sip

function addHitCount($ip,$timestamp,$DEBUGFOLDER)
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

	$fname="/scripts/LOGBUNNY/data".$DEBUGFOLDER."/hits.count/".$ip;

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
		if ($lasttime-$time>1800)
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

	echo "Marking new count: /scripts/LOGBUNNY/data".$DEBUGFOLDER."/hits.count/".$ip." :".$lastcount."\n";
        $ff=fopen("/scripts/LOGBUNNY/data".$DEBUGFOLDER."/hits.count/".$ip,"w");
	fputs($ff,$time."\n".$lastcount."\n");
	fclose($ff);

	if ($lastcount>=10)
	{
		return true;
	}

	return false;
}
