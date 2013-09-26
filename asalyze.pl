#!/usr/bin/perl -w
# ex: ./asalyze.pl --log=/var/log/fwsm.log -d/-b

use strict;
no warnings;
use Getopt::Long;
use Time::Local;

## Global variables
my ($o_verb, $o_help, $o_log, $o_bw, $o_deny);

## Funtions
sub check_options {
	Getopt::Long::Configure ("bundling");
	GetOptions(
		'l:s'     => \$o_log,            'log:s'	=> \$o_log,
		'b'     => \$o_bw,            'bandwidth'	=> \$o_bw,
		'd'     => \$o_deny,            'deny'	=> \$o_deny,
		'v'     => \$o_verb,            'verbose'	=> \$o_verb,
		'h'     => \$o_help,            'help'	=> \$o_help,
	);

	if(defined ($o_help)){
		help();
		exit 1;
	}

	if(!defined($o_log)){
		print "--log missing\n";
		exit 1;
	}

	if(!defined($o_bw) && !defined($o_deny)){
		print "You need to choose output option\n";
		exit;
	}
}

sub help() {
	print "$0\n";
        print <<EOT;
-v, --verbose
        print extra debugging information
-h, --help
	print this help message
# Input
-l, --log
	logfile to read
# Output
-b, --bandwidth
	Display information about bandwidth consumption
-d, --deny
	Display information about deny
EOT
}

sub print_usage() {
        print "Usage: $0 [-v] ]\n";
}

sub ProcessHost($){
	my ($host) = @_;

	my $ip_port;
	my $name;
	if($host =~ ":"){
		($name, $ip_port) = split(":", $host);
	} else {
		$ip_port = $host;
	}

	my($ip, $port) = split("/", $ip_port);

	return ($ip, $port, $name);
}


sub header($){
	my ($header) = @_;
format HEAD =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$header
===============================================================================
.
local $~ ="HEAD";
write;

}

sub Summary($$){
	my(%hash) = %{$_[0]};
	my $datatype = $_[1];

	my $i=0;
	my $total;
	foreach my $key (sort {$hash{$b}<=>$hash{$a}} keys %hash) {
		$i++;
		my $entries = $hash{$key};
		$total = $entries + $total;
		if($datatype eq "bytes"){
			$entries = Bytes2HR($entries);
		}	

	format out = 	
@<<<<     @<<<<<<<<<<<<<<<<<<<<<     @<<<<<<<<<<<<<<<
$i, $key, $entries
.
local $~ ="out";
write;

		if($i > 9){
			print "Total: ";
			if($datatype eq "bytes"){
				print Bytes2HR($total);
			} else {
				print "$total";
			}
			print "\n";
			return;
		}
	}
}

sub Bytes2HR($){
	my ($bytes) = @_;

	if($bytes < 1024){
		return $bytes." bytes";
	} elsif($bytes < 1048576){
		return int($bytes/1024)." KB";
	} else {
		return int($bytes/1024/1024)." MB";
	}
}

sub DenyProcess($){
#tkf 
	my @arr = @{$_[0]};

	my %cache_src;
	my %cache_dst;
	my %cache_port;
	foreach(@arr){
		my ($msg, $action, $proto, $src, $dst, $duration, $bytes) = split(";;", $_);
		my ($src_ip, $src_port, $src_name) = ProcessHost($src);
		my ($dst_ip, $dst_port, $dst_name) = ProcessHost($dst);

		if($action eq "deny"){
			# Proto/Port
			my $src_proto_port = "$proto/$src_port";
			my $dst_proto_port = "$proto/$dst_port";
			$cache_port{$src_proto_port} = $cache_port{$src_proto_port} + 1;
			$cache_port{$dst_proto_port} = $cache_port{$dst_proto_port} + 1;

			# Src/Dest
			$cache_src{$src_ip} = $cache_src{$src_ip} +1;
			$cache_dst{$dst_ip} = $cache_dst{$dst_ip} +1;
		}
	}

	# Summary
	print "# Top destination ports\n";
	header("Nr        Proto/Port                     #");
	Summary(\%cache_port, "");

	print "# Top src\n";
	header("Nr        Src                     #");
	Summary(\%cache_src, "");

	print "# Top dst\n";
	header("Nr        dst                     #");
	Summary(\%cache_dst, "");
}

# Logfile parsing. 
sub ProcessLog($){
	my ($log) = @_;

	my $i=0;
	my @arr;
	my ($sec_curr, $sec_prev);
	my $g_records=0;
	my $g_sec_total=0;
	open(L, "$log");
	my $g_time_start=time();
	while(<L>){
		chomp($_);
		
		my @vals = split(" ", lc($_));
		my $month = $vals[0];
		my $day = $vals[1];
		my $time = $vals[2];
		my $device = $vals[3];
		my $msg = $vals[4];
		my $action = $vals[5];

		# Process the line and get important data
		my ($proto, $conn_id, $src, $dst, $duration, $bytes);


		# General stats
		my ($hour, $min, $sec_curr) = split(":", $time);

		if($sec_prev ne $sec_curr){
			# Seconds have increased
			$g_sec_total++;
		} 

		# Count records
		$g_records++;

		# Keep current sec
		$sec_prev=$sec_curr;

		if($msg eq "%fwsm-6-302013:"){
			$proto = $vals[7];
			$conn_id = $vals[9];
			$src = $vals[11];
			$dst = $vals[14];
		} elsif($msg eq "%fwsm-6-302016:" || $msg eq "%asa-6-302014:" || $msg eq "%asa-6-302016:"){
			$proto = $vals[6];
			$conn_id = $vals[8];
			$dst = $vals[10];
			$src = $vals[12];
			$duration = $vals[14];
			$bytes = $vals[16];
		} elsif($msg eq "%fwsm-6-106028:"){
			$proto = $vals[6];
			$src = $vals[12];
			$dst = $vals[14];
		} elsif($msg eq "%fwsm-6-106015:"){
			$proto = $vals[6];
			$src = $vals[10];
			$dst = $vals[12];
		} elsif($msg eq " %fwsm-4-106023"){
			$proto = $vals[6];
			$src = $vals[8];
			$dst = $vals[10];
		} elsif($msg eq "%fwsm-2-106007:"){
			$proto = $vals[7];
			$src = $vals[9];
			$dst = $vals[11];
		} else {
			next;
		}
		$arr[$i] = "$msg;;$action;;$proto;;$src;;$dst;;$duration;;$bytes";
		$i++;
	}
	close(L);

	my $g_time_end = time();
	my $g_time_total = $g_time_end - $g_time_start;

	my $rps = int($g_records / $g_sec_total);
	print "### Summary\n";
	print "# General\n";
	print "Summary generated in: $g_time_total secs\n"; 
	print "Time covered: $g_sec_total secs\n";
	print "\n";

	print "# Connections\n";
	print "Total connections: $g_records\n";
	print "Connections per sec: $rps\n\n";

	return @arr;
}


sub BandwidthProcess($){
	my @arr = @{$_[0]};

	my %cache_src;
	my %cache_dst;
	my %cache_port;
	my $bytes_total=0;
	foreach(@arr){
		my ($msg, $action, $proto, $src, $dst, $duration, $bytes) = split(";;", $_);
		my ($src_ip, $src_port, $src_name) = ProcessHost($src);
		my ($dst_ip, $dst_port, $dst_name) = ProcessHost($dst);

		# Proto/Port
		my $src_proto_port = "$proto/$src_port";
		my $dst_proto_port = "$proto/$dst_port";
		$cache_port{$src_proto_port} = $cache_port{$src_proto_port} + $bytes;
		$cache_port{$dst_proto_port} = $cache_port{$dst_proto_port} + $bytes;

		# Src/Dest
		$cache_src{$src_ip} = $cache_src{$src_ip} + $bytes;
		$cache_dst{$dst_ip} = $cache_dst{$dst_ip} + $bytes;

		# Total bytes
		$bytes_total = $bytes_total + $bytes;		
	}

	# Summary
	print "# Top destination ports\n";
	header("Nr        Proto/Port                     # bytes");
	Summary(\%cache_port, "bytes");

	print "# Top src\n";
	header("Nr        Src                     # bytes");
	Summary(\%cache_src, "bytes");

	print "# Top dst\n";
	header("Nr        dst                     # bytes");
	Summary(\%cache_dst, "bytes");

	print "\n\n";
	print "Total transfered bytes: ".Bytes2HR($bytes_total)."\n";
}


## Main
check_options();

my @arr = ProcessLog($o_log);

if($o_bw){
	print "Processing Bandwitdh\n";
	BandwidthProcess(\@arr);
} elsif($o_deny){
	print "Processing denys\n";
	DenyProcess(\@arr);
}
