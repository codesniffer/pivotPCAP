# NAME
   pivotPCAP.bro - Module to create links to PCAP solutions in conn.log
## DESCRIPTION
   This module extends the conn.log to include a pcap_link column that
   contains a properly formed search uri for a given configured full pcap
   solution.  Several pcap solutions are supported; however, only one solution 
   can be configure at a time.
## CONFIGURATION
### Full PCAP product number:
    - 0 FireEye PX
    - 1 Endace
    - 2 Counterflow
    - 3 Moloch
    - 4 Stenographer 
   The following configuration variables MUST be configured in this source
   file or within a configuration file using the configuration framework.  For example
   to configure a FireEye PX as the full PCAP solution and it's hostname as
   watcher.corelight.com, make the following changes in the "Configuration Variables" section
   of the source file.

     option product : int = 0;
     option hostDomainName_orIP : string = "watcher.corelight.com";
