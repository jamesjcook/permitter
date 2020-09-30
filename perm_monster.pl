#!/usr/bin/env perl
# an ugly permission adjuster tries to set permissions of technician user to useful bucket
# finds all data with headfiles, gets the project code
# looks for a group named for the investigator
# changes group from defacto to investigator.
#
# Gonna just run this on a schedule every 4 hours

use strict;
use warnings;
use Carp qw(carp croak cluck confess);
use File::Basename;

use Env qw(RADISH_PERL_LIB RADISH_RECON_DIR WORKSTATION_HOME WKS_SETTINGS RECON_HOSTNAME WORKSTATION_HOSTNAME BIGGUS_DISKUS HOME);
use lib split(':',$RADISH_PERL_LIB);
require Headfile;
use pipeline_utilities;
use civm_simple_util qw(activity_log load_file_to_array get_engine_constants_path printd uniq whoami whowasi debugloc sleep_with_countdown $debug_val $debug_locator);



### Make sure we dont run over ourselves
my $PID_N=$$;
my $PIDFILE=File::Spec->catfile($HOME,".perm_monster.pid");
if ( -e $PIDFILE ){
    open my $tid, "<","$PIDFILE";
    croak "existing file $PIDFILE corrupt\n" unless -T $tid;
    my @all=<$tid>;
    close $tid;
    chomp(@all);
    my $prev_id=$all[0];
    my $ps_check="ps -p $prev_id >& /dev/null || echo \"NOPID\"";
    my $chk=qx($ps_check);;
    chomp($chk);
    if ($chk=~/NOPID/x){
	print("Old pid file left lying around\n");
	unlink $PIDFILE;
    } else {
	$PID_N=$prev_id;
    }
}

if ( ! -e $PIDFILE) {
    open SESAME_OUT, ">$PIDFILE";
    print SESAME_OUT $PID_N;
    close SESAME_OUT;
} else {
    die "last run in progress PID=$PID_N from $PIDFILE\n";
}
###

###
# set hardcode vars (maybe we should make options?)
###
my $tech_user='cof';
my $defacto_group='ipl';
my $groupvar='(U_code|archivedestination_project_directory_name)';

# get all groups on sys for later 
my $cmd;
$cmd="dscl . list /Groups";
my @groups=qx($cmd);
# make sure defacto group is on sys
my @def_check=grep {/^$defacto_group$/x } @groups;
if(scalar(@def_check)!=1){
    die("Bad default group \"$defacto_group\", found ".scalar(@def_check)." matches (we need exactly one).\n");
}

# max count of things to process, really just used in testing
my $lim='|head -n 200';
# "normal" mode, no limit
$lim='';
# max age to process with, to avoid look at everything forever for all time.
# we'd have to play with this anytime we add a new localgroup, but we can
# limit it for now to the last 24 hrs
my $time_lim='';
# "normal" mode the last few hrs
$time_lim='-mtime -6h';

# had to use more advanced open command to discard find's stderr because its fequent permission denied errors
# and we dont care in this context
$cmd="find $BIGGUS_DISKUS/ -iname \"*.headfile\" -maxdepth 3 -user $tech_user -group $defacto_group    $time_lim    $lim ";

my $plogdir=File::Spec->catfile($BIGGUS_DISKUS,'.permitter');
if ( ! -d $plogdir) {
    mkdir($plogdir);
}

# hash ref of the dirs to set, with content of the codes, hope to only ever get one code
my $directories;
# dirs with more than one hf with more than one code
my @bad_dirs;
# dirs that appear to have been interrupted before chgrp completed(this should be just about impossible)
my @interrupt_dirs;
# expected local groups with array of headfiles asking for them
my $missing_groups;
# headfiles with array of groups when not exactly one choice
my $ambiguous_group;

###
#EXAMPLE capture stdout discard stderr
###
# per https://stackoverflow.com/questions/3263912/how-to-discard-stderr-from-an-external-command-in-perl
if ( 0 ) {
use IPC::Open3;
use File::Spec;
use Symbol qw(gensym);
open(NULL, ">", File::Spec->devnull);
my $pid = open3(gensym, \*PH, ">&NULL", "cmd");
while( <PH> ) { }
waitpid($pid, 0);
}

# simplistic read stdout as we go.
#my $pid = open( my $CID,"-|", "$cmd"  ) ;

use IPC::Open3;
use File::Spec;
use Symbol qw(gensym);
open(NULL, ">", File::Spec->devnull);
#my $CID;
my $pid = open3(gensym, my $CID,">&NULL", "$cmd"  );

while ( my $line=<$CID> ) {
    chomp $line;
    my $hf=$line;
    #print("Check $hf\n");
    # while more headifles pop up,
    
    my $gr_ex="grep -E '^$groupvar=' $hf";
    #print($pc_ex."\n");
    my @gr_lines=qx($gr_ex);
    chomp(@gr_lines);
    foreach(@gr_lines){
	$_=~s/$groupvar=[0-9]+[.]([^#\s]+)[.][0-9]+.*$/$2/x;
    }
    @gr_lines=uniq(@gr_lines);
    if(scalar(@gr_lines)==1){
	# good things we have just 1 group
    } else {
	# bad things we have 0 or more than 1 group
	##elsif(scalar(@gr_lines)==0){
	print("Bad hf group count $hf\n");
	$ambiguous_group->{$hf}=@gr_lines;
	next;
    }
    # Only one group found in headfile, continue;
    my $pc_ex=$gr_lines[0];
    my @UC_check=grep {/^$pc_ex$/x} @groups;
    if(scalar(@UC_check)!=1){
	if( ! exists($missing_groups->{$pc_ex}) ) {
	    print("Bad local project group \"$pc_ex\" in ($hf), found ".scalar(@UC_check)." matches (we need exactly one).\n");
	}
	push(@{$missing_groups->{$pc_ex}},$hf);
	next;
    }
    # we have exaclty one of this group so we're in good shape
    my $local_group=$UC_check[0];
    chomp($local_group);
        
    # get directory
    my($p,$n,$e)=fileparts($hf,3);
    # allowing multi-depth files now
    my ($tp)=$p;
    # squash multi slash
    $tp=~s:/+:/:gx;
    # trim scratchdir
    $tp=~s:$BIGGUS_DISKUS/::x;
    # set operation dir base in scratch, NOT the deep path we found headfile in
    my @dirs = File::Spec->splitdir( $tp );
    $p=File::Spec->catdir($BIGGUS_DISKUS,$dirs[0]);
    if ( ! exists($directories->{$p} ) ) {
	push(@{$directories->{$p}},$local_group);
	
	my $plog=File::Spec->catfile($BIGGUS_DISKUS,'.permitter',basename($p).".log");
	my $chown="echo $hf > $plog; date >> $plog;( ( (chgrp -PR $local_group $p 2>&1) >> $plog ) && ( echo \"done \"; date) >> $plog; )& ";
	if ( ! -e $plog ) {
	    #print("$chown \n");
	    qx($chown);
	    #last;
	} else {
	    # if log already exists we might be recovering from an error
	    carp ("ERROR $plog exists! dir must have had hiccup! ");
	    push(@interrupt_dirs,$p);
	}
    } else {
	#print("Already found dir $p with previous hf\n"); 
	if(${$directories->{$p}}[0] ne $local_group) {
	    carp("$p has mutliple headfiles, and different codes! ($hf)");
	    push(@bad_dirs,$p);
	}
    }
}

# Full output
#Data::Dump::dump("no local_group",$missing_groups,"multi_code_multi_hf",\@bad_dirs,"progress_interrupt",\@interrupt_dirs,"group ambiguous in hf",$ambiguous_group);

# least important output
#"no local_group",$missing_groups
#
# group count not exactly 1
my @ambg=keys %$ambiguous_group;
Data::Dump::dump("hf group choice ambiguous (group count not 1)",$ambiguous_group)if scalar(@ambg);
# directory has multiple group choices from multiple headfiles
Data::Dump::dump("multiple hf's with mutliple groups",\@bad_dirs) if scalar(@bad_dirs);
# warning
# Data::Dump::dump("progress_interrupt",\@interrupt_dirs);

my $rm_ok = unlink $PIDFILE;
