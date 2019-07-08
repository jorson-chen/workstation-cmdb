Live Workstations from Security
-------------------------------

The scripts combine the results from all the security agents installed in a workstation and feed them into Service Now CMDB for various purposes such as tracking stolen devices, figuring out which device was not registered to the security tool or which device lacks a security tool, check which devices are not encrypted or why is this device not being scanned in Tenable even though its online, who does this IP belong to, mapping user to device etc.
Reason: Discovery service in Service Now is costly

I have provided the base for building the tool which might need slight modification based on the security agents you run in your company and the device naming convention to weed out the strayed ones. All the devices are aggregated based taking the device name as the primary key. Hence its important to normalize them.

As the SCCM database is hit pretty heavily for pushing updates or polling by the sccm agents installed in the endpoints, i have separated it out from the actual tool. You can merge them if you have the bandwidth.

You can schedule a cron job or a jenkins job to run this periodically for example once in 2 hours.

Commands to run:
`
python3 -B sccm_snow_integration -d 30
python3 -B source_of_truth -d 30
`