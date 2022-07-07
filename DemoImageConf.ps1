Configuration DemoImageConfv1 {
    
    #Import resources
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    #Import-DscResource -ModuleName 'xDSCDomainjoin'
    #Import-DscResource -ModuleName 'SqlServerDsc'
    Import-DscResource -ModuleName 'ComputerManagementDsc'

    #https://github.com/dsccommunity/AuditPolicyDsc
    Import-DscResource -ModuleName 'AuditPolicyDsc' -ModuleVersion 1.4.0.0
    
    #https://github.com/dsccommunity/SecurityPolicyDsc
    Import-DscResource -ModuleName 'SecurityPolicyDsc' -ModuleVersion 2.10.0.0
    
  
    
	Node 'localhost' 
    {

	    File Setuphostnamegetting
        {
            DestinationPath = 'C:\Temp\Hostname.ps1'
            Ensure = "Present"
            Contents = 'function get-hostname {
                $hostname = hostname
                return $hostname}
                
                get-hostname'
        }
	        
        ######################################################################################################################################################################################
        # Security hardening settings
        ######################################################################################################################################################################################
        
        AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'
            # 4.3.1 (CIS Baseline Level 1) Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                    = 24
            # 4.3.2 (CIS Baseline Level 1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
            Maximum_Password_Age                        = 60
            # 4.3.3 (CIS Baseline Level 1) Ensure 'Minimum password age' is set to '1 or more day(s)'
            Minimum_Password_Age                        = 3
            # 4.3.4 (CIS Baseline Level 1) Ensure 'Minimum password length' is set to '14 or more character(s)'
            Minimum_Password_Length                     = 14
            # 4.3.5 (CIS Baseline Level 1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'
            # 4.3.6 (CIS Baseline Level 1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            # 4.4.1 (CIS Baseline Level 1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
            Account_lockout_duration                    = 15
            # 4.4.2 (CIS Baseline Level 1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                   = 10
            # 4.4.3 (CIS Baseline Level 1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
            Reset_account_lockout_counter_after         = 15
        }
        
        #  4.1.15 (CIS Baseline Level 1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account and member of Administrators group' (MS only)
          
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = @('Guests', 'Local account')
            Force    = $True
        }
         
        SecurityOption AccountSecurityOptions {       
            
            Name                                                                                                            = 'AccountSecurityOptions'
            # 3.1.1 (CIS Baseline Level 1) Ensure 'Accounts: Administrator account status' is set to 'Enabled' (MS only)
            Accounts_Administrator_account_status                                                                           = 'Enabled'
            # 3.1.2 (CIS Baseline Level 1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
            Accounts_Block_Microsoft_accounts                                                                               = 'Users cant add or log on with Microsoft accounts'
            # 3.1.3 (CIS Baseline Level 1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
            Accounts_Guest_account_status                                                                                   = 'Disabled'
            # 3.1.4 (CIS Baseline Level 1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only                                       = 'Enabled'
            # 3.1.5 (CIS Baseline Level 1) Configure 'Accounts: Rename administrator account'
            Accounts_Rename_administrator_account                                                                           = 'admingccc' # WARNING! Any value different from Administrator
            # 3.1.6 (CIS Baseline Level 1) Configure 'Accounts: Rename guest account'
            Accounts_Rename_guest_account                                                                                   = 'CoGCguest' # WARNING! Any value different from Guest
            # 2.3.2.1 (CIS Baseline Level 1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
            # 4.2.2.1 (CIS Baseline Level 1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
            Audit_Shut_down_system_immediately_if_unable_to_log_security_audits                                             = 'Disabled'
            # 4.2.3.1 (CIS Baseline Level 1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
            Devices_Allowed_to_format_and_eject_removable_media                                                             = 'Administrators'
            # 4.2.3.2 (CIS Baseline Level 1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
            Devices_Prevent_users_from_installing_printer_drivers                                                           = 'Enabled'
            # 4.2.4.1 (CIS Baseline Level 1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always                                              = 'Enabled' 
            # 2.3.6.2 (CIS Baseline Level 1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible                                               = 'Enabled'
            # 4.2.4.2 (CIS Baseline Level 1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled' 
            Domain_member_Digitally_sign_secure_channel_data_when_possible                                                  = 'Enabled'
            # 4.2.4.3 (CIS Baseline Level 1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
            Domain_member_Disable_machine_account_password_changes                                                          = 'Disabled'
            # 4.2.4.4 (CIS Baseline Level 1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
            Domain_member_Maximum_machine_account_password_age                                                              = '30'
            # 4.2.4.5 (CIS Baseline Level 1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
            Domain_member_Require_strong_Windows_2000_or_later_session_key                                                  = 'Enabled'
            # 4.2.5.2 (CIS Baseline Level 1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
            Interactive_logon_Do_not_display_last_user_name                                                                 = 'Enabled' 
            # 4.2.5.1 (CIS Baseline Level 1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
            Interactive_logon_Do_not_require_CTRL_ALT_DEL                                                                   = 'Disabled' 
            # 4.2.5.3 (CIS Baseline Level 1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
            Interactive_logon_Machine_inactivity_limit                                                                      = '900' 
            # 4.2.5.4 (CIS Baseline Level 1) Configure 'Interactive logon: Message text for users attempting to log on' 
            Interactive_logon_Message_text_for_users_attempting_to_log_on                                                   = 'This computer system is property of the Gold Coast City Council. It is for authorised use only. Users (authorised or unauthorised) have no explicit or implicit expectation of privacy. Any or all uses of this system and all files on this system may be intercepted"," monitored"," recorded"," copied"," audited"," inspected and disclosed to an authorised site"," authorised Gold Coast City Council personnel and law enforcement personnel. By using this system the user consents to such interception"," monitoring"," recording"," copying"," auditing"," inspection and disclosure at the discretion of an authorised site or authorised Gold Coast City personnel. Unauthorised or improper use of this system may result in administrative disciplinary action and civil and criminal penalties. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this warning.'
            # 4.2.5.5 (CIS Baseline Level 1) Configure 'Interactive logon: Message title for users attempting to log on'
            #Interactive_logon_Message_title_for_users_attempting_to_log_on = '<Logon Warning>'
            Interactive_logon_Message_title_for_users_attempting_to_log_on                                                  = 'ATTENTION!'
            # 4.2.5.6 (CIS Baseline Level 2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '3 or fewer logon(s)' (MS only) 
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available                 = '3'
            # 4.2.5.7 (CIS Baseline Level 1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
            Interactive_logon_Prompt_user_to_change_password_before_expiration                                              = '14'
            # 4.2.5.8 (CIS Baseline Level 1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
            Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation                                = 'Enabled' 
            # 4.2.5.9 (CIS Baseline Level 1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
            Interactive_logon_Smart_card_removal_behavior                                                                   = 'Lock Workstation'
            # 4.2.6.1 (CIS Baseline Level 1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
            Network_access_Allow_anonymous_SID_Name_translation                                                             = 'Disabled' 
            # 4.2.6.2 (CIS Baseline Level 1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only) 
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts                                               = 'Enabled'
            # 4.2.6.3 (CIS Baseline Level 1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only) 
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares                                    = 'Enabled'
            # 4.2.6.4 (CIS Baseline Level 2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
            Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication                     = 'Enabled' 
            # 4.2.6.5 (CIS Baseline Level 1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users                                                = 'Disabled' 
            # The 3x below settings (.6.6, .6.7, .6.8) have been commented out due to a bug in SecurityPolicyDSC Module https://github.com/dsccommunity/SecurityPolicyDSC/issues/83
            # 4.2.6.6 (CIS Baseline Level 1) Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only) 
            # 4.2.6.7 (CIS Baseline Level 1) Configure 'Network access: Remotely accessible registry paths' 
            #Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            # 4.2.6.8 (CIS Baseline Level 1) Configure 'Network access: Remotely accessible registry paths and sub-paths' 
            #Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\CurrentVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog'
            # 4.2.6.9 (CIS Baseline Level 1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' 
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares                                              = 'Enabled' 
            # 4.2.6.10 (CIS Baseline Level 1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only) 
            #Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = 'Administrators: Remote Access: Allow'
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM                                             = @(
                MSFT_RestrictedRemoteSamSecurityDescriptor {
                    Permission = 'Allow'
                    Identity   = 'Administrators'
                }
            )
            # 4.2.6.11 (CIS Baseline Level 1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
            Network_access_Shares_that_can_be_accessed_anonymously                                                          = ''
            # 4.2.6.12 (CIS Baseline Level 1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' 
            Network_access_Sharing_and_security_model_for_local_accounts                                                    = 'Classic - local users authenticate as themselves'
            # 4.2.7.1 (CIS Baseline Level 1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM                                           = 'Enabled'
            # 4.2.7.2 (CIS Baseline Level 1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' 
            Network_security_Allow_LocalSystem_NULL_session_fallback                                                        = 'Disabled'
            # 4.2.7.3 (CIS Baseline Level 1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' 
            Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities                  = 'Disabled'
            # 4.2.7.4 (CIS Baseline Level 1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
            Network_security_Configure_encryption_types_allowed_for_Kerberos                                                = 'AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', 'FUTURE'
            # 4.2.7.5 (CIS Baseline Level 1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' 
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change                                    = 'Enabled'
            # 4.2.7.6 (CIS Baseline Level 1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' 
            Network_security_Force_logoff_when_logon_hours_expire                                                           = 'Enabled'
            # 4.2.7.7 (CIS Baseline Level 1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
            Network_security_LAN_Manager_authentication_level                                                               = 'Send NTLMv2 responses only. Refuse LM & NTLM' 
            # 4.2.7.8 (CIS Baseline Level 1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
            Network_security_LDAP_client_signing_requirements                                                               = 'Negotiate signing' 
            # 4.2.7.9 (CIS Baseline Level 1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients                       = 'Both options checked'
            # 4.2.8.1 (CIS Baseline Level 1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account                                 = 'Enabled'
            # 4.2.8.2 (CIS Baseline Level 1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' 
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode                 = 'Prompt for consent on the secure desktop'
            # 4.2.8.3 (CIS Baseline Level 1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' 
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users                                        = 'Automatically deny elevation request'
            # 4.2.8.4 (CIS Baseline Level 1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' 
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation                                  = 'Enabled'
            # 4.2.8.5 (CIS Baseline Level 1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations                  = 'Enabled'
            # 4.2.8.6 (CIS Baseline Level 1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode                                              = 'Enabled'
            # 4.2.8.7 (CIS Baseline Level 1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' 
            User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation                                  = 'Enabled'
            # 4.2.8.8 (CIS Baseline Level 1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations                          = 'Enabled'
        }

        #  4.1.1 (CIS Baseline Level 1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
        UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity = ''
            Force    = $True
        }
 
        #  4.1.2 (CIS Baseline Level 1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users' (MS only)
        UserRightsAssignment Accessthiscomputerfromthenetwork {
            Policy   = 'Access_this_computer_from_the_network'
            Identity = @('Administrators', 'Authenticated Users')
            Force    = $True
        }
 
 
        #  4.1.3 (CIS Baseline Level 1) Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy   = 'Act_as_part_of_the_operating_system'
            Identity = ''
            Force    = $True
        }
 
        #  4.1.4 (CIS Baseline Level 1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Adjustmemoryquotasforaprocess {
            Policy   = 'Adjust_memory_quotas_for_a_process'
            Identity = @('LOCAL SERVICE', 'NETWORK SERVICE')
            Force    = $True
        }
 
        #  4.1.5 (CIS Baseline Level 1) Ensure 'Allow log on locally' is set to 'Administrators'
        # CceId: CCE-37659-0
        # DataSource: Security Policy
        # Ensure 'Allow log on locally' is set to 'Administrators'
        UserRightsAssignment Allowlogonlocally {
            Policy   = 'Allow_log_on_locally'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.6 (CIS Baseline Level 1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)
        UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
            Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity = @('Administrators', 'Remote Desktop Users')
            Force    = $True
        }
 
        #  4.1.7 (CIS Baseline Level 1) Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy   = 'Back_up_files_and_directories'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.8 (CIS Baseline Level 1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy   = 'Change_the_system_time'
            Identity = @('Administrators', 'LOCAL SERVICE')
            Force    = $True
        }
		
        #  4.1.9 (CIS Baseline Level 1) Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy   = 'Create_a_pagefile'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.10 (CIS Baseline Level 1) Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy   = 'Create_a_token_object'
            Identity = ''
            Force    = $True
        }
 
        #  4.1.11 (CIS Baseline Level 1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy   = 'Create_global_objects'
            Identity = @('Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE') 
            Force    = $True
        }
 
        #  4.1.12 (CIS Baseline Level 1) Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy   = 'Create_permanent_shared_objects'
            Identity = ''
            Force    = $True
        }
 
        #  4.1.13 (CIS Baseline Level 1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)
        UserRightsAssignment Createsymboliclinks {
            Policy   = 'Create_symbolic_links'
            Identity = @('Administrators')
            Force    = $True
        }
 
        #  4.1.14 (CIS Baseline Level 1) Ensure 'Debug programs' is set to 'Administrators'
        UserRightsAssignment Debugprograms {
            Policy   = 'Debug_programs'
            Identity = 'Administrators'
            Force    = $True
        }
        
        #  4.1.16 (CIS Baseline Level 1) Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = 'Guests'
            Force    = $True
        }
 
        #  4.1.17 (CIS Baseline Level 1) Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = 'Guests'
            Force    = $True
        }
 
        #  4.1.18 (CIS Baseline Level 1) Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy   = 'Deny_log_on_locally'
            Identity = @('Guests', 'BladeLogicRSCD')
            Force    = $True
        }
            
        #  4.1.19 (CIS Baseline Level 1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account' (MS only)
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = @('Guests', 'Local account')
            Force    = $True
        }
 
        #  4.1.20 (CIS Baseline Level 1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)
        UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy   = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity = ''
            Force    = $True
        }
 
        #  4.1.21 (CIS Baseline Level 1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy   = 'Force_shutdown_from_a_remote_system'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.22 (CIS Baseline Level 1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy   = 'Generate_security_audits'
            Identity = @('LOCAL SERVICE', 'NETWORK SERVICE')
            Force    = $True
        }
       
        # 4.1.24 (CIS Baseline Level 1) Ensure 'Increase scheduling priority' is set to 'Administrators' and ‘Window Manager\Window Manager Group’
        # CceId: CCE-38326-5
        # DataSource: Security Policy
        
        UserRightsAssignment Increaseschedulingpriority {
            Policy   = 'Increase_scheduling_priority'
            Identity = @('Administrators', 'Window Manager\Window Manager Group')
            Force    = $True
        }
 
        #  4.1.25 (CIS Baseline Level 1) Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy   = 'Load_and_unload_device_drivers'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.26 (CIS Baseline Level 1) Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy   = 'Lock_pages_in_memory'
            Identity = ''
            Force    = $True
        }

        #  4.1.27 (CIS Baseline Level 1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
        UserRightsAssignment Manageauditingandsecuritylog {
            Policy   = 'Manage_auditing_and_security_log'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.28 (CIS Baseline Level 1) Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy   = 'Modify_an_object_label'
            Identity = ''
            Force    = $True
        }
 
        # 4.1.29 (CIS Baseline Level 1) Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy   = 'Modify_firmware_environment_values'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.30 (CIS Baseline Level 1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy   = 'Perform_volume_maintenance_tasks'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.31 (CIS Baseline Level 1) Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy   = 'Profile_single_process'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.32 (CIS Baseline Level 1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy   = 'Profile_system_performance'
            Identity = @('Administrators', 'NT SERVICE\WdiServiceHost', 'LOCAL SERVICE', 'NETWORK SERVICE')
            Force    = $True
        }
 
        #  4.1.33 (CIS Baseline Level 1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy   = 'Replace_a_process_level_token'
            Identity = @('LOCAL SERVICE', 'NETWORK SERVICE')
            Force    = $True
        }
 
        #  4.1.34 (CIS Baseline Level 1) Ensure 'Restore files and directories' is set to 'Administrators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy   = 'Restore_files_and_directories'
            Identity = 'Administrators'
            Force    = $True
        }

        #  4.1.35 (CIS Baseline Level 1) Ensure 'Shut down the system' is set to 'Administrators'
        # CceId: CCE-38328-1
        # DataSource: Security Policy
        # Ensure 'Shut down the system' is set to 'Administrators'
        UserRightsAssignment Shutdownthesystem {
            Policy   = 'Shut_down_the_system'
            Identity = 'Administrators'
            Force    = $True
        }
 
        #  4.1.36 (CIS Baseline Level 1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy   = 'Take_ownership_of_files_or_other_objects'
            Identity = 'Administrators'
            Force    = $True
        }
		
		# 4.2.8.9_Ensure 'Audit Credential Validation'  is set to 'Success and Failure' 
        AuditPolicySubcategory "Audit Credential Validation (Succes)" {
            Name      = 'Credential Validation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory "Audit Credential Validation (Failure)" {
            Name      = 'Credential Validation'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
		
		#  4.2.9.1_Ensure 'Turn off location' is set to 'Enabled'
        Registry 'DisableLocation' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
            ValueName = 'DisableLocation'
            ValueType = 'DWord'
            ValueData = '1'
        }
 
        #  4.2.11.1 (CIS Baseline Level 2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'
        Registry 'fDisableCcm' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCcm'
            ValueType = 'DWord'
            ValueData = '1'
        }
 
        #  4.2.11.2 (CIS Baseline Level 1) Ensure 'Do not allow drive redirection' is set to 'Enabled'
        Registry 'fDisableCdm' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCdm'
            ValueType = 'DWord'
            ValueData = '1'
        }
 
        #  4.2.11.3 (CIS Baseline Level 2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
        Registry 'fDisableLPT' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableLPT'
            ValueType = 'DWord'
            ValueData = '1'
        }
 
        #  4.2.11.4 (CIS Baseline Level 2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
        Registry 'fDisablePNPRedir' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisablePNPRedir'
            ValueType = 'DWord'
            ValueData = '1'
        }
 
        #  4.2.12.1 (CIS Baseline Level 1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'
        Registry 'fPromptForPassword' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'DWord'
            ValueData = '1'
        }
 
        #  4.2.12.2 (CIS Baseline Level 1) Ensure 'Require secure RPC communication' is set to 'Enabled'
        Registry 'fEncryptRPCTraffic' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'DWord'
            ValueData = '1'
        }
 
        #  4.2.12.3 (CIS Baseline Level 1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'
        Registry 'SecurityLayer' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'SecurityLayer'
            ValueType = 'DWord'
            ValueData = '2'
        }
       
        #  4.2.12.4 (CIS Baseline Level 1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
        Registry 'UserAuthentication' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'UserAuthentication'
            ValueType = 'DWord'
            ValueData = '1'
        }
 
        #  4.2.12.5 (CIS Baseline Level 1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
        Registry 'MinEncryptionLevel' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'DWord'
            ValueData = '3'
        }
 
        #  4.2.13.1 (CIS Baseline Level 2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
        Registry 'NoGenTicket' {
            Force     = $True
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
            ValueName = 'NoGenTicket'
            ValueType = 'DWord'
            ValueData = '1'
        }
		
		#####################################################################################################################################################
		#	Registry Settings from SOE-2016 																							#
		#####################################################################################################################################################
		 
        WindowsFeature SNMPService
        {
                Name = "SNMP-Service"
                Ensure = "Present"
        }
        WindowsFeature SNMPServiceRSAT
        {
                Name = "RSAT-SNMP"
                Ensure = "Present"
        }
        Registry SNMPTrapconfigg3cprivate
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\TrapConfiguration\g3cpublic"
            ValueName   = ""
            ValueData   = ""
            Force       = $true
        }
        Registry SNMPTrapg3cpublic1
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\TrapConfiguration\g3cpublic"
            ValueName   = "1"
            ValueData   = "msvmon1"
            Force       = $true
            DependsOn   = "[Registry]SNMPTrapconfigg3cprivate"
        }
        Registry SNMPTrapg3cpublic2
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\TrapConfiguration\g3cpublic"
            ValueName   = "2"
            ValueData   = "localhost"
            Force       = $true
            DependsOn   = "[Registry]SNMPTrapconfigg3cprivate"
        }
        Registry SNMPTrapg3cpublic3
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\TrapConfiguration\g3cpublic"
            ValueName   = "3"
            ValueData   = "orion"
            Force       = $true
        }
        Registry SNMPEnableAuthenticationTraps
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\"
            ValueName   = "EnableAuthenticationTraps"
            ValueData   = "0"
            Force       = $true
        }
        Registry SNMPNameResolutionRetries
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\"
            ValueName   = "NameResolutionRetries"
            ValueData   = "10"
            Force       = $true
        }
        Registry SNMPPermittedManagers1
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\PermittedManagers"
            ValueName   = "1"
            ValueData   = "localhost"
            Force       = $true
        }
        Registry SNMPPermittedManagers2
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\PermittedManagers"
            ValueName   = "2"
            ValueData   = "msvmon1"
            Force       = $true
        }
        Registry SNMPPermittedManagers3
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\PermittedManagers"
            ValueName   = "3"
            ValueData   = "orion"
            Force       = $true
        }
        Registry SNMPsyscontact
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\RFC1156Agent"
            ValueName   = "syscontact"
            ValueData   = "Server Services"
            Force       = $true
        }
        Registry SNMPsysLocation
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\RFC1156Agent"
            ValueName   = "sysLocation"
            ValueData   = "Azure"
            Force       = $true
        }
        Registry SNMPsysServices
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\RFC1156Agent"
            ValueName   = "sysServices"
            ValueData   = "77"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SNMPValidCommunities1
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\ValidCommunities"
            ValueName   = "g3cpublic"
            ValueData   = "4"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SNMPValidCommunities2
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentCOntrolSet\Services\SNMP\Parameters\ValidCommunities"
            ValueName   = "g3cprivate"
            ValueData   = "8"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry OnlyAllowLocalUserProfiles
        {
            Ensure      = "Present"
            Key         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            ValueName   = "LocalProfile"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry Kerberostokensize
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
            ValueName   = "MAxTokenSize"
            ValueData   = "65535"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry ServerManagerInitialConfigTasks
        {
            Ensure      = "Present"
            Key         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\InitialConfigurationTasks"
            ValueName   = "DoNotOpenAtLogon"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry ServerManagerDoNotOpenAtLogon
        {
            Ensure      = "Present"
            Key         = "HKLM:\Software\Policies\Microsoft\Windows\Server\ServerManager"
            ValueName   = "DoNotOpenAtLogon"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry Donotdisplayservermanageronlogon
        {
            Ensure      = "Present"
            Key         = "HKLM:\Software\Microsoft\ServerManager"
            ValueName   = "DoNotOpenServerManagerAtLogon"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry ShutdownEventTrackerEnabled
        {
            Ensure      = "Present"
            Key         = "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability"
            ValueName   = "ShutdownReasonOn"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry ShutdownEventTrackerAlways
        {
            Ensure      = "Present"
            Key         = "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability"
            ValueName   = "ShutdownReasonUI"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry Searchpreviewpanelocation
        {
            Ensure      = "Present"
            Key         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName   = "PreviewPaneLocation"
            ValueData   = "0"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SearchPreventIndexingMicrosoftOutlook
        {
            Ensure      = "Present"
            Key         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName   = "PreventIndexingOutlook"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SearchPreventIndexingemailattachments
        {
            Ensure      = "Present"
            Key         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName   = "PreventIndexingEmailAttachments"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SearchIndexDataLocation
        {
            Ensure      = "Present"
            Key         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName   = "DataDirectory"
            ValueData   = "D:\WindowsSearchIndex"
            ValueType   = "String"
            Force       = $true
        }
        Registry SearchDoNotAllowWebSearch
        {
            Ensure      = "Present"
            Key         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName   = "DisableWebSearch"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SearchDisableIndexBackoff
        {
            Ensure      = "Present"
            Key         = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            ValueName   = "DisableBackoff"
            ValueData   = "1"
            ValueType   = "Dword"
            Force       = $true
        }
        Service WindowsSearch
        {
            Name        = "WSearch"
            StartupType = "Automatic"
            State       = "Running"
        }
        Registry SecuritylogRetention
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
            ValueName   = "Retention"
            ValueData   = "0"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SecuritylogMaxSize
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
            ValueName   = "MaxSize"
            ValueData   = "5242880"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry ApplicationlogRetention
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"
            ValueName   = "Retention"
            ValueData   = "0"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry ApplicationlogMaxSize
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"
            ValueName   = "MaxSize"
            ValueData   = "5242880"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SystemlogRetention
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System"
            ValueName   = "Retention"
            ValueData   = "0"
            ValueType   = "Dword"
            Force       = $true
        }
        Registry SystemlogMaxSize
        {
            Ensure      = "Present"
            Key         = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System"
            ValueName   = "MaxSize"
            ValueData   = "5242880"
            ValueType   = "Dword"
            Force       = $true
        }
		#Disable automatic updates
        Registry AUOptionsNAU
        {
            Ensure 		= "Present"
            Key 		= "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName 	= "NoAutoUpdate"
            ValueType 	= "DWord"
            ValueData 	= "1"
			Force		= $true
        }
		#Disable automatic updates
        Registry AUOptions
        {
            Ensure 		= "Present"
            Key 		= "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName 	= "AUOptions"
            ValueType 	= "DWord"
            ValueData 	= "2"
			Force		= $true
        }
		
          
       
        Script DisableFirewall {
            SetScript = {
                $firewallprofiles = Get-NetFirewallProfile
                foreach ($fw in $firewallprofiles) {
                    If ($fw.Enabled -ne $false) {
                        Set-NetFirewallProfile -Name $fw.Name -Enabled False
                    }
                }
            }
            GetScript = {
                $getscripttestfirewallprofiles = Get-NetFirewallProfile
            }
            TestScript = {
                $testfirewallprofiles = Get-NetFirewallProfile
                foreach ($fw in $testfirewallprofiles) {
                    If ($fw.Enabled -eq $True) {
                        return $false
                    }
                return $true
                }
            }
          
        }   
        
        ######################################################################################################################################################
		#	Additional Registry Settings from 2016 SOE																  											 #
		######################################################################################################################################################

        Registry iCountry
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iCountry"
            ValueData   = "61"
            ValueType   = "String"
            Force       = $true
        }
        Registry iCurrDigits
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iCurrDigits"
            ValueData   = "2"
            ValueType   = "String"
            Force       = $true
        }
        Registry iCurrency
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iCurrency"
            ValueData   = "0"
            ValueType   = "String"
            Force       = $true
        }
        Registry iDate
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iDate"
            ValueData   = "1"
            ValueType   = "String"
            Force       = $true
        }
        Registry iDigits
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iDigits"
            ValueData   = "2"
            ValueType   = "String"
            Force       = $true
        }
        Registry iLZero
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iLZero"
            ValueData   = "1"
            ValueType   = "String"
            Force       = $true
        }
        Registry iMeasure
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iMeasure"
            ValueData   = "0"
            ValueType   = "String"
            Force       = $true
        }
        Registry iNegCurr
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iNegCurr"
            ValueData   = "1"
            ValueType   = "String"
            Force       = $true
        }
        Registry iTime
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iTime"
            ValueData   = "1"
            ValueType   = "String"
            Force       = $true
        }
        Registry iTLZero
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iTLZero"
            ValueData   = "1"
            ValueType   = "String"
            Force       = $true
        }
        Registry Locale
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "Locale"
            ValueData   = "00000C09"
            ValueType   = "String"
            Force       = $true
        }
        Registry s1159
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "s1159"
            ValueData   = "AM"
            ValueType   = "String"
            Force       = $true
        }
        Registry s2359
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "s2359"
            ValueData   = "PM"
            ValueType   = "String"
            Force       = $true
        }
        Registry sCountry
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sCountry"
            ValueData   = "Australia"
            ValueType   = "String"
            Force       = $true
        }
        Registry sDate
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sDate"
            ValueData   = "/"
            ValueType   = "String"
            Force       = $true
        }
        Registry sDecimal
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sDecimal"
            ValueData   = "."
            ValueType   = "String"
            Force       = $true
        }
        Registry sLanguage
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sLanguage"
            ValueData   = "ENA"
            ValueType   = "String"
            Force       = $true
        }
        Registry sList
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sList"
            ValueData   = ","
            ValueType   = "String"
            Force       = $true
        }
        Registry sLongDate
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sLongDate"
            ValueData   = "dddd, d MMMM yyyy"
            ValueType   = "String"
            Force       = $true
        }
        Registry sShortDate
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sShortDate"
            ValueData   = "dd/MM/yyyy"
            ValueType   = "String"
            Force       = $true
        }
        Registry sThousand
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sThousand"
            ValueData   = ","
            ValueType   = "String"
            Force       = $true
        }
        Registry sTime
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sTime"
            ValueData   = ":"
            ValueType   = "String"
            Force       = $true
        }
        Registry sTimeFormat
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sTimeFormat"
            ValueData   = "HH:mm:ss"
            ValueType   = "String"
            Force       = $true
        }
        Registry sShortTime
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sShortTime"
            ValueData   = "HH:mm:ss"
            ValueType   = "String"
            Force       = $true
        }
        Registry iTimePrefix
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iTimePrefix"
            ValueData   = "0"
            ValueType   = "String"
            Force       = $true
        }
        Registry sMonDecimalSep
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sMonDecimalSep"
            ValueData   = "."
            ValueType   = "String"
            Force       = $true
        }
        Registry sMonThousandSep
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sMonThousandSep"
            ValueData   = ","
            ValueType   = "String"
            Force       = $true
        }
        Registry iNegNumber
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iNegNumber"
            ValueData   = "1"
            ValueType   = "String"
            Force       = $true
        }
        Registry sNativeDigits
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sNativeDigits"
            ValueData   = "0123456789"
            ValueType   = "String"
            Force       = $true
        }
        Registry NumShape
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "NumShape"
            ValueData   = "1"
            ValueType   = "String"
            Force       = $true
        }
        Registry iCalendarType
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iCalendarType"
            ValueData   = "1"
            ValueType   = "String"
            Force       = $true
        }
        Registry iFirstDayOfWeek
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iFirstDayOfWeek"
            ValueData   = "0"
            ValueType   = "String"
            Force       = $true
        }
        Registry iFirstWeekOfYear
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "iFirstWeekOfYear"
            ValueData   = "0"
            ValueType   = "String"
            Force       = $true
        }
        Registry sGrouping
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sGrouping"
            ValueData   = "3;0"
            ValueType   = "String"
            Force       = $true
        }
        Registry sMonGrouping
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sMonGrouping"
            ValueData   = "3;0"
            ValueType   = "String"
            Force       = $true
        }
        Registry sPositiveSign
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sPositiveSign"
            ValueData   = ""
            ValueType   = "String"
            Force       = $true
        }
        Registry sNegativeSign
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International"
            ValueName   = "sNegativeSign"
            ValueData   = "-"
            ValueType   = "String"
            Force       = $true
        }
        Registry Nation
        {
            Ensure      = "Present"
            Key         = "HKEY_USERS\.DEFAULT\Control Panel\International\Geo"
            ValueName   = "Nation"
            ValueData   = "12"
            ValueType   = "String"
            Force       = $true
        }
    }  
} DemoImageConfv1
