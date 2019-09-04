# NAME
#   pivotPCAP.bro - Module to create links to PCAP solutions in conn.log
# 
# DESCRIPTION
# 
#   This module extends the conn.log to include a pcap_link column that
#   contains a properly formed search uri for a given configured full pcap
#   solution.  Several pcap solutions are supported; however, only one solution 
#   can be configure at a time.
# 
# CONFIGURATION
#   Full PCAP products:
#     FireEye PX------FIREEYE
#     Endace----------ENDACE
#     Counterflow-----COUNTERFLOW
#     Moloch----------MOLOCH
#     Stenographer----STENOGRAPHER
# 
#   The following configuration variables MUST be configured in this source
#   file or within a configureation file using the configuration framework.
#
#     const product : PRODUCT=FIREEYE &redef;
#     const hostDomainName_orIP : string = "watcher.corelight.com";
# 
# AUTHOR
# 
#     Paul Bartruff <paul@corelight.com>
# 
# LICENSE
# 
#   Copyright (C) 2019, Paul Bartruff
#   All rights reserved.
#   
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#   
#   (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#   
#   (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#   
#   (3) Neither the name of the University of California, Lawrence Berkeley
#       National Laboratory, U.S. Dept. of Energy, International Computer
#       Science Institute, nor the names of contributors may be used to endorse
#       or promote products derived from this software without specific prior
#       written permission.
#   
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#   ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
# 
# 
# VERSION
# 
#     1.0

@load base/protocols/conn
@load base/frameworks/logging
@load misc/dump-events

module pivotPCAP;

export
{
  type PRODUCT : enum
  {
    FIREEYE,
    ENDACE,
    COUNTERFLOW,
    MOLOCH,
    STENOGRAPHER
  };

  #Configuration Variables
  #option product : PRODUCT=FIREEYE &redef;
  const product : PRODUCT=FIREEYE &redef;
  #option hostDomainName_orIP : string = "127.0.0.1" &redef;
  const hostDomainName_orIP : string = "127.0.0.1" &redef;
}

# Add PCAP Link field to the connection log record.
redef record Conn::Info += {
  pcap_link: string &default="-" &log;  
  #pcap_link: string &log;  
};

event connection_state_remove(c: connection)
{
  #Get Start and end time of connection and build uri for each supported product.
  #Particular attention to the time format will be important, as each product will
  #likely have different queries using time.

  #Use 1 second before connection established and 1 second after connection closes
  local startTime = c$start_time-1 sec;
  local endTime  = c$start_time+c$duration+1 sec;
  local originator : addr = c$id$orig_h;
  local oPort : port = c$id$orig_p;
  local responder : addr = c$id$resp_h;
  local rPort : port = c$id$resp_p;

  switch ( product )
    {
    case FIREEYE:
      #FireEye PX URI
      c$conn$pcap_link = fmt("https://%s/i/searches.html?stime=%s&etime=%s&xpf=host %s and %s", hostDomainName_orIP, strftime("%Y%m%d.%H%M%S", startTime), strftime("%Y%m%d.%H%M%S", endTime), originator, responder);
      #c$conn$pcap_link = fmt("https://%s/i/searches.html?stime=%s&etime=%s&xpf=host %s and %s", hostDomainName_orIP, startTime, endTime, originator, responder);
      break;
    case ENDACE:
      #Endace
      break;
    case COUNTERFLOW:
      #Counterflow
      break;
    case MOLOCH:
      #Moloch
      c$conn$pcap_link = fmt("%s/sessions?graphType=lpHisto&seriesType=bars&expression=ip%%3D%%3D%s%%26%%26ip%%3D%%3D%s&stopTime=%s&startTime=%s", hostDomainName_orIP,10.1.2.1, 192.168.14.3, 1561608000, 1561521600);
      break;
    case STENOGRAPHER:
      #Stenographer
      #c$conn$pcap_link = fmt("stenoread /'host %s and host %s after %s before %s/'", originator, responder, strftime("%FT%TZ", startTime), strftime("%FT%TZ", endTime)); 
      c$conn$pcap_link = fmt("stenoread 'host %s and host %s after %s before %s'", originator, responder, strftime("%FT%T%z", startTime), strftime("%FT%T%z", endTime));
      break;
    default:
      break;
    }
}
