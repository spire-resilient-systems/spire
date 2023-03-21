Version 3.3 - December 23, 2020
    * Update to use Spines 5.5, for details refer to CHANGELOG in spines
    * Updated prime to use OpenSSL 1.1.1 version

Version 3.2 - November 26, 2018
    * Updated to use Spines 5.4, which fixed a bug that could be triggered when
      link encryption is used in Prime

Version 3.1 - March 14, 2018
    * Added capability to automatically reset the system if the system
      assumptions are violated (specifically, if there are no longer enough
      correct replicas with the system state to re-integrate recovering
      replicas)
    * Improved proactive recovery implementation to ensure that recovering
      replicas can always rejoin the system and issue new updates (regardless
      of their malicious activity prior to being recovered)

Version 3.0 - May 17, 2017
    * Redesigned replication model:
        - Each Prime replica now serves a single application replica
        - Each Prime replica delivers a totally ordered stream of updates to its application replica
        - Prime provides an ephemeral ordering service (no persistent storage). State transfer
          must be handled at the application level. Prime signals the application if it may need 
          to do a state transfer.
    * Added support for network partitions:
        - If no quorum of connected replicas, progress resumes once partition heals
        - If replica(s) are partitioned from a quorum, will catchup once reconnected

Version 2.0 - September 17, 2014
    * Added support for Diversity (via MultiCompiler)
    * Added support for Proactive Recovery
    * Added State Transfer protocol:
        - Allows a replica to recover a clean copy of the state (if necessary) after proactive recovery

Version 1.1 - December 07, 2013
    * Added Prime View Change implementation

Version 1.0 - May 4, 2010
    * Initial Release
