# Sigflow 
## Introduction:

Sigflow is a tool visualizing MTAS related signalling sequences from a PCAP file, processor or event history log.

MTAS roles supported: Tel AS (incl Business Line), SCC AS, ST AS and NW AS
Interfaces supported: Isc/Ma (SIP), Dh/Sh (Diameter), Rf/Ro (Diameter), Mp (H.248), Mr (SIP), CAT (SIP), CAMEL (TCAP)

Sigflow will by default search for all available MTAS roles and interface signals found in the trace. Selected interfaces are presented in the sequence diagram while available interfaces are listed at the top of the diagram together with the list of parameters used in the analysis of the input file. 
In case Sigflow cannot identify what role of MTAS a signal is related to, the default role 'AS' will be used.
Each call (combination To/From headers) is presented in the sequence with a specific colour. The details of each signal is presented in the window on the right hand side, by clicking on the signal of interest. Specific signal captions are used to provide more details of the signal like 1) whether an INVITE is the initial or re-INVITE, 2) if a message includes SDP, 3) early dialog indication etc. 
Sigflow sometimes fail in correctly visualizing the actual signalling sequence of involved MTAS roles. If so, try specify the SIP address of MTAS using the -a option.

## Usage:

In the 'Generate' frame on the left, browse your file and enter any extra parameters, check-boxes you want to use (optional), then press the button to generate the sequence diagram.
Depending on your file, the generation might take several minutes, please be patient!
Once generated, the HTML pages will stay hosted on the server for at least 24 hours.
In case the sequence diagram gets too large (due to the number of signals and network entities), your browser might only render the diagram partly or not render it at all. If this happens you can try a different browser or use the user or frame interval parameter to specify rendering of a section of the trace content.

## Extra parameters:

-a, --address <ip-address(es)>
IP address(es) of MTAS in the PCAP file. More than one IP address can be specified as a comma separated list without spaces. Normally this option is not needed since Sigflow can find the MTAS IP addresses automatically.

-e, --merge
Merge related user IDs and phone numbers to one line in the sequence diagram.

-F, --filter <filter>
Filter expression for SIP traffic. Example: -F "headers['Call-ID']=='X' && status_code > 199"

-i, --frame-interval <first>:<last>
Specify which frames to include when reading a PCAP file or what interval of found messages to include when reading a log file. <first> is the starting frame number and <last> the last frame to include.

-m, --megaco
Include megaco messages.

-c, --charging
Include charging diameter messages.

-s, --hss
Include Sh diameter messages. Only supported for PCAP files.

-C, --cap
Include TCAP messages containing CAMEL or INAP.

-u, --user <user>
Only include SIP messages that include the supplied user string in the To and From headers. Example: -u _user. In this example, if the input file contains calls related to A_user1, B_user2 and C_user2, then those calls will be in the sequence diagram.

-p, --splitmtas
Display one MTAS actor per served user. With this option there can be several MTAS actors for the same MTAS role in the sequence diagram.

-E, --serviceevents
Include service state change events found in AppTrace or EventHistory logs.

-H, --hidden
Displays in the diagram if there are messages available from protocols not selected.

-d, --dark
Set sequence diagram background color to dark grey.

-T, --methodflow
For log files containing method trace. Incoming messages will contain help with running the Methodflow program on the log file lines until the next incoming message.

