#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.130.176.0 netmask 255.255.252.0 {
     option broadcast-address 140.130.179.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.130.177.1 140.130.177.254;
             range 140.130.178.1 140.130.178.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.130.176.6;
     option ntp-servers 140.130.176.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.130.176.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.201.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.201.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.201.57.1 140.201.57.254;
             range 140.201.58.1 140.201.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.201.56.6;
     option ntp-servers 140.201.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.201.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.202.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.202.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.202.57.1 140.202.57.254;
             range 140.202.58.1 140.202.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.202.56.6;
     option ntp-servers 140.202.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.202.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.203.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.203.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.203.57.1 140.203.57.254;
             range 140.203.58.1 140.203.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.203.56.6;
     option ntp-servers 140.203.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.203.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.204.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.204.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.204.57.1 140.204.57.254;
             range 140.204.58.1 140.204.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.204.56.6;
     option ntp-servers 140.204.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.204.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.205.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.205.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.205.57.1 140.205.57.254;
             range 140.205.58.1 140.205.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.205.56.6;
     option ntp-servers 140.205.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.205.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.206.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.206.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.206.57.1 140.206.57.254;
             range 140.206.58.1 140.206.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.206.56.6;
     option ntp-servers 140.206.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.206.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.207.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.207.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.207.57.1 140.207.57.254;
             range 140.207.58.1 140.207.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.207.56.6;
     option ntp-servers 140.207.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.207.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.208.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.208.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.208.57.1 140.208.57.254;
             range 140.208.58.1 140.208.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.208.56.6;
     option ntp-servers 140.208.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.208.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.209.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.209.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.209.57.1 140.209.57.254;
             range 140.209.58.1 140.209.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.209.56.6;
     option ntp-servers 140.209.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.209.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.210.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.210.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.210.57.1 140.210.57.254;
             range 140.210.58.1 140.210.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.210.56.6;
     option ntp-servers 140.210.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.210.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM02 
subnet 140.211.56.0 netmask 255.255.252.0 {
     option broadcast-address 140.211.59.255;
     option subnet-mask 255.255.252.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 140.211.57.1 140.211.57.254;
             range 140.211.58.1 140.211.58.254;
        }
     option domain-name "vs.commerzbank.com";
     option routers 140.211.56.6;
     option ntp-servers 140.211.56.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 140.211.56.0/255.255.252.0 _____*****");
   }
}
#
#-------------------------------------------------------------
#Automatisch erzeugte Konfiguration am 1237987025
# FFM73 
subnet 141.30.120.0 netmask 255.255.255.0 {
     option broadcast-address 141.30.120.255;
     option subnet-mask 255.255.255.0;
	pool
	{
             deny dynamic bootp clients;
             failover peer "cobafailover";
             range 141.30.120.64 141.30.120.127;
             range 141.30.120.128 141.30.120.193;
        }
     option domain-name "vs.commerzbank.com";
     option routers 141.30.120.6;
     option ntp-servers 141.30.120.6;
     option domain-name-servers 39.101.101.101, 39.102.102.102;
     option netbios-name-servers 140.131.11.3, 140.131.11.4;
   if substring(option vendor-class-identifier, 0, 9) = "PXEClient" {
     option dhcp-server-identifier 140.15.248.57;
     option tftp-server-name "140.15.248.57";
     next-server 140.15.248.57;
     option vendor-encapsulated-options 06:01:07:08:07:ff:f0:01:8c:0f:f8:39:09:18:ff:f0:15:4e:65:74:53:75:70:70:6f:72:74:42:6f:6f:74:43:6f:6e:74:72:6f:6c:0a:04:00:41:41:41:47:03:00:00:00:ff;
     option vendor-class-identifier "PXEClient";
     option option-128 42:63:52:65:50:32:00;
     option option-129 42:63:53:72:56:8c:0f:f8:39:07:d0;
     log (info, "*****_____ Matched PXE vs Netz 141.30.120.0/255.255.255.0 _____*****");
   }
}
#
