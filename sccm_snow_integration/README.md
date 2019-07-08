SCCM_Service_Now_Integrator
---------------------------

Collects all workstations seen in the past (30 days by default, can be changed with -d option) from SCCM and pushes them to Computer Table (CMDB_CI_Computer) in Service Now.

Custom fields in Service Now Computer Table are created to take in the relevant fields from sccm.

Custom fields in the Service Now Computer Table (CMDB_CI_Computer) have a prefix of `u_`. You would need to create the fields in Service Now Computer Table (CMDB_CI_Computer) with the same label as shown below:
    ```
    u_usernames : String
    u_external_ip_addresses : String
    u_office : : String
    u_encrypted : String
    u_ad_domain : String
    u_present_in_sccm : True/False
    u_present_in_tenable : True/False
    u_present_in_crowdstrike : True/False
    u_present_in_cylance : True/False
    u_present_in_jamf : True/False
    ```
    
You would also need to add 2 keys to the OS Dictionary field of CMDB_CI_Computer Table, if not already present:
    Windows 
    Mac OS

The name you provide for your application would be used to search in the Computers Table in Service Now. Hence you would need to add a new key to the `discovery_source` dictionary field in Service Now.    

Install requirements: `pip install -r requirements.lock`

Run `python3 -B . --help`