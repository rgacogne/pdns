End of life statements
======================

We aim to have a release every six months.
The latest release receives correctness, stability and security updates.
The two releases before that get critical updates only.
Older releases are marked end of life and receive no updates at all.
Pre-releases do not receive immediate security updates.

The currently supported release train of PowerDNS Authoritative Server is 4.9.

PowerDNS Authoritative Server 4.8 will only receive critical updates; it will be end of life after PowerDNS Authoritative Server 5.1 is released.

PowerDNS Authoritative Server 4.7 will only receive critical updates; it will be end of life after PowerDNS Authoritative Server 5.0 is released.

PowerDNS Authoritative Server 4.0 through 4.6, 3.x, and 2.x are End of Life.

Note: Users with a commercial agreement with PowerDNS.COM BV or Open-Xchange
can receive extended support for releases which are End Of Life. If you are
such a user, these EOL statements do not apply to you.

.. list-table:: PowerDNS Authoritative Server Release Life Cycle
   :header-rows: 1

   * - Version
     - Release date
     - Critical-Only updates
     - End of Life
   * - 4.9
     - 15th of March 2024
     - ~ March 2025
     - ~ March 2026
   * - 4.8
     - 1st of June 2023
     - 15th of March 2024
     - ~ September 2025
   * - 4.7
     - 20th of October 2022
     - 1st of June 2023
     - ~ March 2025
   * - 4.6
     - January 2022
     - October 2022
     - EOL March 2024
   * - 4.5
     - July 2021
     - January 2022
     - EOL June 2023
   * - 4.4
     - December 2020
     - January 2022
     - EOL October 2022
   * - 4.3
     - April 2020
     - April 2021
     - EOL January 2022
   * - 4.2
     - August 2019
     - December 2020
     - EOL July 2021
   * - 4.1 and older
     - EOL
     - EOL
     - EOL

PowerDNS Authoritative Server 3.x
---------------------------------
1st of December 2017

The PowerDNS Authoritative Server 3.x releases are no longer supported, and
will not receive any further updates, not even for security purposes.

All users are urged to upgrade to the latest version.  To upgrade from 3.x to 4.x,
:doc:`follow these instructions <../upgrading>`

If you need help with upgrading, we provide `migration
services <https://www.powerdns.com/support-services-consulting.html>`__
to our supported users. If you are currently running 3.x and need
help to tide you over, we can also provide that as part of a `support
agreement <https://www.powerdns.com/support-services-consulting.html>`__.

PowerDNS Authoritative Server 2.x
---------------------------------

21st of May 2015 (updated January 2017)

PowerDNS Authoritative Server 2.9.22 was released in January 2009.
Because of its immense and durable popularity, some patch releases have
been provided, the last one of which (2.9.22.6) was made available in
January 2012.

The 2.9.22.x series contains a number of probable and actual violations
of the DNS standards. In addition, some behaviours of 2.9.22.x are
standards conforming but cause interoperability problems today. Finally,
2.9.22.4 and earlier are impacted by :doc:`PowerDNS Security Advisory 2012-01
<../security-advisories/powerdns-advisory-2012-01>`,
which means PowerDNS can be used in a Denial of Service attack.

Although we have long been telling users that we can no longer support
the use of 2.x, and urging upgrading, with this statement we formally
declare 2.x end of life.

This means that any 2.x issues will not be addressed. This has been the
case for a long time, but with this statement we make it formal.

To upgrade to 3.x, please consult the `instructions on how to upgrade
the database <https://doc.powerdns.com/3/authoritative/upgrading/#29x-to-30>`__.
To upgrade from 3.x to 4.x, :doc:`follow these instructions <../upgrading>`.
If you need help with upgrading, we provide `migration
services <https://www.powerdns.com/support-services-consulting.html>`__
to our supported users. If you are currently running 2.9.22 and need
help to tide you over, we can also provide that as part of a `support
agreement <https://www.powerdns.com/support-services-consulting.html>`__.

But we urge everyone to move on to PowerDNS Authoritative Server 4.x - it is a faster, more standards conforming and more powerful
nameserver!
