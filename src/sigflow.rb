#!/usr/bin/env ruby
'di '
'ig00 '
# TODO:
#
# 1. Add megaco messages from eventhistory? See Proc_m0_s23.b.
#
# 2. Verizon session side?
#
# 3. Improve performance when reading PCAP files. Change XML parser or use fileds instead of PDML?
#
# 5. Config file for ports.
#
# 8. Add support for MTAS white-box tracing; i.e. trace SIP messages from SipDistributor
#    to Application process and megaco messages from h248 processes to Application proc.
#
# 9. Display the internals of the application process such as incoming dialogs, service session
#    and outgoing dialogs. Also display how sip events traverse theses objects and what service
#    primitives the services return. Since this depends on the sip messages sent and received
#    the user could click on the MTAS line at for example an INVITE and see this internal snapshot
#    efter the INVITE.
#
# 10.Check tags in To header and From header and branch so that it matches. Can catch many
#    errors by this.
#
# 11. For PCAP files from system test we could include SBG and CSCF in the diagram as separate nodes.
#

require 'optparse'
require 'sf_pcap_file'
require 'sf_log_file'
require 'sf_traffic_scenario'

$options = { :charging => false, :sh => false, :megaco => false, :dark => false, :run => false, :multiple_diagrams => false, :merge_users => false, :split_mtas => false, :service_events => false, :tcap => false, :version => false, :help => false, :hidden_messages => false}
$debug = false
$method_trace = false
$parameters = ARGV.join(" ")

$base_dir = File.expand_path("../", File.dirname(__FILE__)) + '/'
$sipcall_dir = '/vobs/tas/tas_code/imsas/utils/sipcall/'
$script_generator_dir = '/home/egayazi/sipcall/'

def run_scenario(messages)
    File.open('msgs', 'w') do |out_file|
        messages.each do |message|
            next if !message.sip?
            message.to_file(out_file)
        end
    end
    system("#{$script_generator_dir}generate.pl < msgs | less > #{$sipcall_dir}result.pl")
    Dir.chdir($sipcall_dir) do
        system('chmod u+x result.pl')
        system('./result.pl -maia')
    end
end

if $method_trace
    $indent = 0
    set_trace_func proc { |event, file, line, id, binding, classname|
        if file.include?('sigflow') && (event == 'call' || event == 'return')
            printf "%25s:%-4d ", file.split('/').last, line
            if event == 'return'
                $indent -= 2 if $indent > 0
            end
            $indent.times do
                print '| '
            end
            if event == 'call'
                puts "#{id} {"
                $indent += 2
            else
                puts "}"
            end
        end
    }
end

op = OptionParser.new do |opts|
    opts.banner = "Description: Generates an HTML representation of an MTAS traffic scenario.\n" +
                  "Usage: sigflow [options]"
    opts.on("-h", "--help", "Show detailed help message.") do |h|
        $options[:help] = true
    end
    opts.on("-v", "--version", "Show version and changelog.") do |h|
        $options[:version] = true
    end
    opts.on("-f", "--file FILE",
            "Name of the input file. This could be a pcap file,",
            "an event history, a processor log or a log produced",
            "by the loganalyzer script.") do |fname|
        $options[:file] = fname
    end
    opts.on("-i", "--frame-interval FIRST:LAST",
            "Specify which frames to include when reading a PCAP or what interval of found messages to include when reading a log file.",
            "file. FIRST is the starting frame number and LAST is",
            "last frame to include.") do |frames|
        $options[:frame_interval] = true
        if frames =~ /(\d+):(\d+)/
            $options[:frame_interval_first] = $1
            $options[:frame_interval_last] = $2
        else
            puts "Syntax error, expected frame interval on form FIRST:LAST."
            exit(0)
        end
    end
    opts.on("-r", "--run", "Run the scenario.") do |r|
        $options[:run] = true
    end
    opts.on("-c", "--charging", "Include charging diameter messages.") do |o|
        $options[:charging] = true
    end
    opts.on("-s", "--hss", "Include Sh diameter messages.") do |o|
        $options[:sh] = true
    end
    opts.on("-m", "--megaco", "Include megaco messages.") do |o|
        $options[:megaco] = true
    end
    opts.on("-F", "--filter FILTER",
            "Filter expression for SIP traffic. Example:",
            "  -F \"headers['Call-ID']=='X' && status_code > 199 && method != 'OPTIONS'\"") do |filter|
        $options[:filter] = filter
    end
    opts.on("-a", "--address IP-ADDRESS(es)",
            "IP address(es) of MTAS. More than one IP address can",
            "be specified as a comma separated list without spaces.") do |address|
        $options[:mtas_ip_addresses] = address
    end
    opts.on("-u", "--user USER",
            "Only include SIP messages that include the supplied",
            "user string in the To and From headers. Example:",
            "  -u _user",
            "In the example above, if the input file contains",
            "calls related to A_user1, B_user2 and C_user2,",
            "then those calls will be in the sequence diagram.") do |user|
        $options[:user] = user
    end
    opts.on("-M", "--multiple",
            "Used together with '-u/--user', this generates one",
            "sequence diagram per matched user. Example:",
            "  -u _user -M",
            "In the example above, if the input file contains",
            "messages related to A_user1, B_user2 and C_user3,",
            "then three sequence diagrams will be generated.") do |m|
        $options[:multiple_diagrams] = true
    end
    opts.on("-e", "--merge",
            "Merge related user ids and phone numbers to one line",
            "in the sequence diagram.") do |e|
        $options[:merge_users] = true
    end
    opts.on("-p", "--splitmtas",
            "Display one MTAS line per served user. With this",
            "option there can be several MTAS lines for the same",
            "MTAS role in the sequence diagram.") do |e|
        $options[:split_mtas] = true
    end
    opts.on("-E", "--serviceevents",
            "Displays service events found in AppTrace or EventHistory logs") do |e|
        $options[:service_events] = true
    end
    opts.on("-C", "--cap",
            "Include tcap messages containing camel or inap") do |e|
        $options[:tcap] = true
    end
    opts.on("-H", "--hidden",
            "Displays in the diagram if there are messages available from protocols you have not selected.") do |e|
        $options[:hidden_messages] = true
    end
    opts.on("-d", "--dark",
            "Set sequence diagram background color to dark grey.") do |d|
        $options[:dark] = true
    end
end

trap("INT") do
    exit(0)
end

begin
    op.parse!
rescue
    puts op
    exit(0)
end

if $options[:help]
    system("man #{$0}")
    exit(0)
end

if $options[:version]
    NL = "\n"
    current_version = "Current version: 2016-04-10" + NL
    changelog = 
    NL + "2016-04-10:" + NL +
    "   -Fixed a problem with determining if a dialog is between two MTAS:es." + NL +
    NL + "2016-04-01:" + NL +
    "   -Improved extraction of megaco messages from log files." + NL +
    NL + "2016-03-22:" + NL +
    "   -Fixed bug with early dialog captions." + NL +
    NL + "2016-03-14:" + NL +
    "   -Made the \"hidden messages\" feature into an option, -H." + NL +
    NL + "2016-01-13:" + NL +
    "   -Corrected recent bug introduced causing problems finding messages in processor logs (sf_sip.rb)." + NL +
    NL + "2016-01-08:" + NL +
    "   -Fixed issue that Sigflow did not recognise charging messages." + NL +
    "   -Improved endpoint correlation." + NL +
    NL + "2016-01-05:" + NL +
    "   -Early dialogue captions added." + NL +
    NL + "2015-12-28:" + NL +
    "   -Users filtering (-u option) now supported for log files." + NL +
    NL + "2015-12-18:" + NL +
    "   -Fixed issue with SIP messages not displayed following presence of a diameter message without application-id." + NL +
    "   -Case independent identification of pcap files." + NL +
    NL + "2015-07-21:" + NL +
    "   -Reverted change that ignored dialogs with the initial request being \"BYE\"." + NL +
    "   -Improved finding of state change events." + NL +
    "   -Added service events including Capsule abortion." + NL +
    "   -Fixed issue with reading wrong timestamps from log files." + NL +
    "   -Sorting messages by timestamp in log files is now done using a stable sort to preserve message order when timestamps are equal." + NL +
    "   -Sigflow now tries to decode messages with the destination port 6001 as SIP messages." + NL +
    "   -Dialogs now work even without a single SIP request at all" + NL +
    "   -Fixed problems with messages in a dialog between two MTASes going the wrong direction if their duplicate is missing." + NL +
    "   -Fixed a problem with service events being inserted in the wrong position in the diagram." + NL +
    "   -Fixed a problem with Sigflow comparing ports wrongly when searching for MTAS IPs." + NL +
    "   -Sigflow can now handle log files with the timezone \"JST\"." + NL +
    "   -Completely rewrote the way Sigflow finds and handles session-side and AS-type information. Sigflow can now find it in many more ways." + NL +
    "   -Rewrote the way Sigflow tries to fix dialog endpoints" + NL +
    "   -Fixed major problem with the -p, --splitmtas option." + NL +
    "   -Removed warning when using -m, -s and -c options and multiple MTAS IPs were found." + NL +
    "   -The frame number interval option, -i, now works for log files. There it will number all found messages starting from 1 and remove those outside the interval." + NL +
    "   -Added checks to recognise if a message has been cut off when reading messages from log files." + NL +
    "   -Set some limits to the diagram canvas size to avoid it not rendering at all when to big." + NL +
    "   -Sigflow now always searches for megaco, charging and sh messages but only displays them if their option is enabled." + NL +
    "   -The generated diagram now displays what options Sigflow was run with." + NL +
    "   -The generated diagram now displays if there are megaco, charging and/or sh messages available but hidden due to their options not being used." + NL +
    "   -Rewrote method for reading megaco message from log files. Should be better at knowing when they end now." + NL +
    "   -Dialog colors in the diagram are now determined by icid-value instead of to/from combination as the to/from headers can be written in three different ways." + NL +
    "   -Fixed that sometimes megaco responses had the wrong endpoints. They now serach for their request to determine their endpoints." + NL +
    "   -Added two new background call-colors to diagrams." + NL +
    "   -Improved determining of service event nodes." + NL +
    "   -Fixed problem with the last message in a diagram having the wrong call-color sometimes." + NL +
    "   -Sigflow can now find charging diameter in log files." + NL +
    "   -The -F option can now be used to filter by request method." + NL +
    "   -Added -C option to display tcap messages containing camel or inap components." + NL +
    NL + "2015-05-15:" + NL +
    "   -Added new -E option. This option displays service events found in AppTrace or EventHistory logs. Currently only displays State changed events." + NL +
    "   -Megaco option (-m) now works for log files. Currently it onlt displays H248 send and recieve." + NL +
    "   -Frame number is now displayed for messages." + NL +
    "   -Fixed problems with finding incorrect diameter MTAS IPs." + NL +
    "   -Added method for finding MTAS addresses from megaco messages." + NL +
    "   -Sip messages are no longer read from diameter/megaco addresses." + NL +
    "   -P-Served-User header is now prioritised higher than port when determining MTAS session side." + NL +
    "   -Dialogs with the initial request \"BYE\" are now ignored." + NL +
    "   -Fixed problem with paths containing back-slashes."
    puts current_version
    puts changelog
    exit(0)
end

in_fname = $options[:file]
if in_fname.nil?
    puts op
    exit(0)
end

if in_fname.split('.').last.downcase.include?('cap')
    messages = PcapFile.read(in_fname)
else
    messages, snapshots, service_events = LogFile.read(in_fname)
end
if messages.empty?
    puts 'Could not find any SIP messages.'
    exit(0)
end

if $options[:run]
    run_scenario(messages)
else
    if !$options[:user].nil? && $options[:multiple_diagrams]
        if in_fname.split('.').last.downcase.include?('cap')
            users = PcapFile.users
        else
            users = LogFile.users
        end
        users.each do |user|
            user_messages = []
            messages.each do |message|
                next if !message.sip?
                user_messages << message if message.user_is?(user)
            end
            scenario = TrafficScenario.new(user_messages, in_fname + '_' + user, $base_dir)
            scenario.process
        end
    else
        scenario = TrafficScenario.new(messages, in_fname, $base_dir)
        scenario.snapshots = snapshots
        scenario.service_events = service_events
        scenario.process
    end
end
exit(0)

__END__

.00
'di
.TH sigflow 7 "2015-07-21"
.SH NAME
sigflow \- Generate an HTML representation of an MTAS traffic scenario
.SH SYNOPSIS
.B sigflow.sh \fI[OPTION]\fR
.SH DESCRIPTION
.PP
Generate an HTML representation of an MTAS traffic scenario from a PCAP file, a processor log or an event history.
.PP
This tool is designed to handle scenarios which involve more than one MTAS. Such scenarios could come from system test or from customer sites.
.TP
.BR \-a ", " \-\-address " " \fIIP-ADDRESS(es)\fR
IP address(es) of MTAS in the PCAP file. More than one IP address can be specified as a comma separated list without spaces. Normally this option is not needed since sigflow can find the MTAS IP addresses automatically.
.TP
.BR \-c ", " \-\-charging
Include charging diameter messages.
.TP
.BR \-e ", " \-\-merge
Merge related user IDs and phone numbers to one line in the sequence diagram.
.TP
.BR \-f ", " \-\-file " " \fIFILE\fR
Name of the input file. This could be a PCAP file, an event history, a processor log or a log produced by the loganalyzer script.
.TP
.BR \-F ", " \-\-filter " " \fIFILTER\fR
Filter expression for SIP traffic. Example: -F "headers['Call-ID']=='X' && status_code > 199 && method != 'OPTIONS'"
.TP
.BR \-h ", " \-\-help
Show this help message.
.TP
.BR \-i ", " \-\-frame\-interval " " \fIFIRST:LAST\fR
Specify which frames to include when reading a PCAP file or what interval of found messages to include when reading a log file. FIRST is the starting frame number and LAST is last frame to include.
.TP
.BR \-m ", " \-\-megaco
Include megaco messages.
.TP
.BR \-M ", " \-\-multiple
Used together with \fB\-u/\-\-user\fR, this generates one sequence diagram per matched user. Example: -u _user -M. In this example, if the input file contains messages related to A_user1, B_user2 and C_user3, then three sequence diagrams will be generated.
.TP
.BR \-p ", " \-\-splitmtas
Display one MTAS line per served user. With this option there can be several MTAS lines for the same MTAS role in the sequence diagram.
.TP
.BR \-E ", " \-\-serviceevents
Displays service events found in AppTrace or EventHistory logs.
.TP
.BR \-C ", " \-\-cap
Include tcap messages containing camel or inap
.TP
.BR \-H ", " \-\-hidden
Displays in the diagram if there are messages available from protocols you have not selected.
.TP
.BR \-s ", " \-\-hss
Include Sh diameter messages. Only supported for PCAP files.
.TP
.BR \-u ", " \-\-user " " \fIUSER\fR
Only include SIP messages that include the supplied user string in the To and From headers. Example: -u _user. In this example, if the input file contains calls related to A_user1, B_user2 and C_user2, then those calls will be in the sequence diagram.
.SH EXAMPLES
.PP
\fBsigflow.sh \-f Proc_m0_s9\fR
.PP
Generate a sequence diagram from the processor log Proc_m0_s9. The generated HTML file will be named Proc_m0_s9.html.
.PP
\fBsigflow.sh \-f TC_CAC_TERM0065.pcap\fR
.PP
Generate a sequence diagram from the PCAP file TC_CAC_TERM0065.pcap.
.PP
\fBsigflow.sh \-csmf TC_CAC_TERM0065.pcap\fR
.PP
Generate a sequence diagram from the PCAP file TC_CAC_TERM0065.pcap. Also, include charging and Sh messages, as well as megaco messages.
.PP
\fBsigflow.sh -f 3pty_terminal_based_Pirelli.pcap -u 38220284001 -F "status_code > 100"\fR
.PP
Generate a sequence diagram from the PCAP file 3pty_terminal_based_Pirelli.pcap. Only include SIP messages related to users that contain '38220284001' in their To and From headers. Also, discard any 100 Trying responses.
.SH BUGS
The chrome browser is currently not supported due to limitations in cross-frame scripting.
.SH AUTHOR
Klas Buhre (qklabuh) <klas.xx.buhre@ericsson.com>

