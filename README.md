# cumi
Cumi is a lightweight, real-time Squid access-log monitoring and domain detection tool.<br/><br/>

It watches Squid's access log, checks requested domains against categorized malicious-domain signatures, and generates an alert when a match is found.<br/>

## LogFormat in squid.conf:
logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt<br/>
access_log /var/log/squid/access.log squid
