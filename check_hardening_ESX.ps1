#Set-ExecutionPolicy remoteSigned
$vCenter = Read-Host "Enter the vCenter server name"
$User = Read-Host "Enter the User name"
$Password = Read-Host "Enter the Password"
Connect-VIServer $vCenter -User $User -Password $Password
Write-Output "1.1 Keep ESXi system properly patched (Scored): [ NOT CHECK ]
"
################################### Check VIB Acceptance Levels ###################################
$VMHost = Get-VMHost
$ESXCli = Get-EsxCli -VMHost $VMHost;
$checkLevel = $ESXCli.software.vib.list() | Where { ($_.AcceptanceLevel -ne "VMwareCertified") -and 
($_.AcceptanceLevel -ne "VMwareAccepted") -and ($_.AcceptanceLevel -ne "PartnerSupported") }| Measure-Object
if ($checkLevel.Count -eq 0){
	Write-Output "1.2 Verify Image Profile and VIB Acceptance Levels (Scored): [ OK ]
"}
else{
	Write-Output "1.2 Verify Image Profile and VIB Acceptance Levels (Scored): [ NOT OK ]
Fix: `$ESXCli.software.acceptance.Set(`"PartnerSupported`") }  
"}

################################ Check unauthorized kernel modules ################################
$checkUnsigned=$ESXCli.system.module.list() | Foreach { 
$ESXCli.system.module.get($_.Name) }| Where {($_.SignedStatus -eq "Unsigned")} | Measure-Object
if ($checkUnsigned.Count -eq 0){
	Write-Output "1.3 Verify no unauthorized kernel modules are loaded on the host (Scored): [ OK ]"}
else{
	Write-Output "1.3 Verify no unauthorized kernel modules are loaded on the host (Scored): [ NOT OK ]
Fix: `$ESXCli.system.module.set(`$false, `$false, `"Module`")
Find Module: 
	`$ESXCli.system.module.list() | Foreach { 
	`$ESXCli.system.module.get(`$_.Name) }| Where `{(`$_.SignedStatus -eq `"Unsigned`")`} `|Select Module}  
"}

####################################### Check configure NTP  #######################################
$checkNTP = Get-VMHostNtpServer | Measure-Object
if ($checkNTP.Count -eq 0){
	Write-Output "2.1 Configure NTP time synchronization (Scored): [ NOT OK ]
Fix: Add-VmHostNtpServer `"pool.ntp.org`
"}
else{
	Write-Output "2.1 Configure NTP time synchronization (Scored): [ OK ]
"}

######################################## Check configure FW #########################################
$checkFW=Get-VMHostFirewallException | Where {$_.Enabled -and ($_.ExtensionData.AllowedHosts.AllIP)} | Measure-Object
if ($checkFW.Count -eq 0){
	Write-Output "2.2 Configure the ESXi host firewall to restrict access to services running on the host (Scored): [ OK ]
"}
else{
	Write-Output "2.2 Configure the ESXi host firewall to restrict access to services running on the host (Scored): [ NOT OK ]
Note: Limit IP connect to services on ESXi server.
Fix: Go to `"Manage`" - `"Settings`" - `"System`" - `"Security Profile`" and Edit	
"}

######################################## Check configure MOB ########################################
$countMOB=.\plink.exe -ssh -noagent $VMHost -l $User -pw $Password 'vim-cmd proxysvc/service_list |grep mob |wc -l'
if ($countMOB -eq 0){
	Write-Output "2.3 Disable Managed Object Browser (MOB) (Scored): [ OK ]
"}
else{
	Write-Output "2.3 Disable Managed Object Browser (MOB) (Scored): [ NOT OK ]
Fix: vim-cmd proxysvc`/remove_service `"/mob`" `"httpsWithRedirect`" 
"}

Write-Output "2.4 Do not use default self-signed certificates for ESXi communication (Scored): [ NOT CHECK ]
"

####################################### Check configure SNMP ########################################
$checkSNMP=Get-VMHostSnmp |where {$_.Enabled} | Measure-Object
if ($checkSNMP.Count -eq 0){
	Write-Output "2.5 Ensure proper SNMP configuration (Not Scored): [ OK ]
"}
else{
	$configSNMP=Get-VMHostSnmp |select ReadOnlyCommunities | ft -hidetableheaders | Out-String
	if ($configSNMP){
		Write-Output "2.5 Ensure proper SNMP configuration (Not Scored): [ OK ]
	"}
	else{
		Write-Output "2.5 Ensure proper SNMP configuration (Not Scored): [ NOT OK ]
Fix: Get-VmHostSNMP | Set-VMHostSNMP -Enabled:`$true -ReadOnlyCommunity `'`<secret`>`' 
	"}
}

####################################### Check configure APIs ########################################
$checkAPIs=Get-VMHostAdvancedConfiguration Net.DVFilterBindIpAddress | Select -ExpandProperty Values
if ($checkAPIs){
	Write-Output "2.6 Prevent unintended use of dvfilter network APIs (Scored): [ NOT OK ]
Fix: Get-VMHost `| Foreach { Set-VMHostAdvancedConfiguration -VMHost `$_ -Name Net.DVFilterBindIpAddress -Value `"`" } 
"}
else{
	Write-Output "2.6 Prevent unintended use of dvfilter network APIs (Scored): [ OK ]
"}
Write-Output "2.7 Remove expired or revoked SSL certificates from the ESXi server (Not Scored): [ NOT CHECK ]
"

##################################### Check configure CoreDump ######################################
$countCoreDumps=.\plink.exe -ssh -noagent $VMHost -l $User -pw $Password 'esxcli system coredump network get |grep Enabled |grep true |wc -l'
if ($countCoreDumps -eq 0){
	Write-Output "3.1 Configure a centralized location to collect ESXi host core dumps (Scored): [ NOT OK ]
Fix: esxcli system coredump network set -v `[VMK`#`] -i `[DUMP_SERVER`] -o `[PORT`]
	 esxcli system coredump network set -e true 
"}
else{
	Write-Output "3.1 Configure a centralized location to collect ESXi host core dumps (Scored): [ OK ]
"}

###################################### Check persistent Log ######################################## 
$checkPersistent=Get-VMHostAdvancedConfiguration Syslog.global.logDir | Select -ExpandProperty Values
if ($checkPersistent){
	if ($checkPersistent -Match "scratch"){
		Write-Output "3.2 Configure persistent logging for all ESXi host (Scored): [ NOT OK ]
Fix: Get-VMHost | Foreach `{ Set-VMHostAdvancedConfiguration -VMHost `$_ -Name Syslog.global.logDir -Value `"<NewLocation>`" } 
	"}
	else{
		Write-Output "3.2 Configure persistent logging for all ESXi host (Scored): [ OK ]
	"}
}
else{
	Write-Output "3.2 Configure persistent logging for all ESXi host (Scored): [ NOT OK ]
Fix: Get-VMHost | Foreach `{ Set-VMHostAdvancedConfiguration -VMHost `$_ -Name Syslog.global.logDir -Value `"<NewLocation>`" } 
"}

###################################### Check remote Logging ########################################
$checkLogDir=Get-VMHostAdvancedConfiguration Syslog.global.logHost | Select -ExpandProperty Values
if ($checkLogDir){
	Write-Output "3.3 Configure remote logging for ESXi hosts (Scored): [ OK ]
"}
else{
	Write-Output "3.3 Configure remote logging for ESXi hosts (Scored): [ NOT OK ]
Fix: Get-VMHost | Foreach { Set-VMHostAdvancedConfiguration -VMHost `$_ -Name Syslog.global.logHost -Value `"<NewLocation>`" } 
"}	

###################################### Check lengh password ########################################
Write-Output "4.1 Create a non-root user account for local admin access (Scored): [ NOT CHECK ]
"

$checkPass=.\plink.exe -ssh -noagent $VMHost -l $User -pw $Password 'cat /etc/pam.d/passwd |grep password |grep requisite |grep "disabled,disabled,disabled,disabled,14" |wc -l'
if ($checkPass -eq 0){
	Write-Output "4.2 Establish a password policy for password complexity (Scored): [ NOT OK ]
Fix: Edit /etc/pam.d/passwd
password requisite /lib/security/`$ISA/pam_passwdqc.so retry=3 min=disabled,disabled,disabled,disabled,14
"}
else{
	Write-Output "4.2 Establish a password policy for password complexity (Scored): [ OK ]
"}

Write-Output "4.3 Use Active Directory for local user authentication (Scored): [ NOT CHECK ]
"
Write-Output "4.4 Verify Active Directory group membership for the `"ESX Admins`" group (Not Scored): [ NOT CHECK ]
"

########################################### Check DCUI #############################################
$checkDCUI=Get-VMHostService | Where { $_.key -eq "DCUI" } | WHere { $_.Policy -eq "on"} | Measure-Object
if ($checkDCUI.Count -eq 0){
	Write-Output "5.1 Disable DCUI to prevent local administrative control (Scored): [ OK ]
"}
else{
	Write-Output "5.1 Disable DCUI to prevent local administrative control (Scored): [ NOT OK ]
Fix: Get-VMHost `| Get-VMHostService `| Where `{ `$_.key -eq `"DCUI`" `} `| Set-VMHostService -Policy Off 
"}

######################################### Check ESXi Shell ###########################################
$checkDCUI=Get-VMHostService | Where { $_.key -eq "TSM" } | WHere { $_.Policy -eq "on"} | Measure-Object
if ($checkDCUI.Count -eq 0){
	Write-Output "5.2 Disable ESXi Shell unless needed for diagnostics or troubleshooting (Scored): [ OK ]
"}
else{
	Write-Output "5.2 Disable ESXi Shell unless needed for diagnostics or troubleshooting (Scored): [ NOT OK ]
Fix: Get-VMHost `| Get-VMHostService `| Where `{ `$_.key -eq `"TSM`" `} `| Set-VMHostService -Policy Off 
"}

######################################### Check CIM Access ###########################################
$all_user=VMHostAccount
Write-Output "5.4 Limit CIM Access (Not Scored): [ MANUAL ]
List User: $all_user
"

########################################## Check LOCKDOWN ############################################
$checkLockdown=.\plink.exe -ssh -noagent $VMHost -l $User -pw $Password 'vim-cmd -U dcui vimsvc/auth/lockdown_is_enabled |grep false |wc -l'
if ($checkLockdown -eq 0){
	Write-Output "5.5 Enable lockdown mode to restrict remote access (Scored): [ OK ]
"}
else{
	Write-Output "5.5 Enable lockdown mode to restrict remote access (Scored): [ NOT OK ]
Fix: Get-VMHost `| Foreach { `$_.EnterLockdownMode() } 
"}

######################################### Check SSH KEY AUTH ##########################################
$checkKey=.\plink.exe -ssh -noagent $VMHost -l $User -pw $Password 'cat /etc/ssh/keys-root/authorized_keys |wc -l'
if ($checkKey -eq 0){
	Write-Output "5.6 Remove keys from SSH authorized_keys file (Scored): [ OK ]
"}
else{
	Write-Output "5.6 Remove keys from SSH authorized_keys file (Scored): [ NOT OK ]
Fix: echo `" `" > /etc/ssh/keys-root/authorized_keys
"}

######################################### Check SSH TIMEOUT ###########################################
$checkTimeOut=Get-VMHostAdvancedConfiguration UserVars.ESXiShellInteractiveTimeOut | Select -ExpandProperty Values
if ($checkTimeOut -lt 300){
	Write-Output "5.7 Set a timeout to automatically terminate idle ESXi Shell and SSH sessions (Scored): [ NOT OK ]
Fix: Get-VMHost | Foreach { Set-VMHostAdvancedConfiguration -VMHost `$_ -Name UserVars.ESXiShellInteractiveTimeOut -Value 300 } 
"}
else{
	Write-Output "5.7 Set a timeout to automatically terminate idle ESXi Shell and SSH sessions (Scored): [ OK ]
"}

######################################### Check SHELL TIMEOUT ##########################################
$checkShellTimeOut=Get-VMHostAdvancedConfiguration UserVars.ESXiShellTimeOut | Select -ExpandProperty Values
if ($checkShellTimeOut -lt 3600){
	Write-Output "5.8 Set a timeout for Shell Services (Scored): [ NOT OK ]
Fix: Get-VMHost | Foreach { Set-VMHostAdvancedConfiguration -VMHost `$_ -Name UserVars.ESXiShellTimeOut -Value 3600 }  
"}
else{
	Write-Output "5.8 Set a timeout for Shell Services (Scored): [ OK ]
"}

######################################### Check USER LOCKDƠWN ##########################################
$userLockdown=Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Select -ExpandProperty Value
Write-Output "5.9 Set DCUI.Access to allow trusted users to override lockdown mode (Not Scored): [MANUAL]
List User: $userLockdown
"
Write-Output "5.10 Verify contents of exposed configuration files (Not Scored): [NOT CHECK]
"
Write-Output "6.1 Enable bidirectional CHAP authentication for iSCSI traffic. (Scored): [NOT CHECK]
"
Write-Output "6.2 Ensure uniqueness of CHAP authentication secrets (Not Scored): [NOT CHECK]
"
Write-Output "6.3 Mask and zone SAN resources appropriately (Not Scored): [NOT CHECK]
"
Write-Output "6.4 Zero out VMDK files prior to deletion (Not Scored): [NOT CHECK]
"

###################################### Check VSWITCH FORDEDTRANS #######################################
$vSwitch=Get-VirtualSwitch -Standard
if ($vSwitch.ExtensionData.Spec.Policy.Security.ForgedTransmits){
	Write-Output "7.1 Ensure that the vSwitch Forged Transmits policy is set to reject (Scored): [NOT OK ]
Fix: esxcli network vswitch standard policy security set -v vSwitch[] -f false 
"}
else{
	Write-Output "7.1 Ensure that the vSwitch Forged Transmits policy is set to reject (Scored): [ OK ]
"}

########################################## Check VSWITCH MAC ##########################################
if ($vSwitch.ExtensionData.Spec.Policy.Security.MacChanges){
	Write-Output "7.2 Ensure that the vSwitch MAC Address Change policy is set to reject (Scored): [NOT OK ]
Fix: esxcli network vswitch standard policy security set -v vSwitch0 -m false 
"}
else{
	Write-Output "7.2 Ensure that the vSwitch MAC Address Change policy is set to reject (Scored): [ OK ]
"}

######################################## Check Promiscuous MAC #########################################
if ($vSwitch.ExtensionData.Spec.Policy.Security.AllowPromiscuous){
	Write-Output "7.3 Ensure that the vSwitch Promiscuous Mode policy is set to reject (Scored): [ NOT OK ]
Fix: esxcli network vswitch standard policy security set -v vSwitch0 -p false 
"}
else{
	Write-Output "7.3 Ensure that the vSwitch Promiscuous Mode policy is set to reject (Scored): [ OK ]
"}

########################################## Check NATIVE VLAN ###########################################
Foreach ($port in Get-VirtualPortGroup -Standard | Select -ExpandProperty VlanID ){
	if ($port -eq 1) {
		Write-Output "7.4 Ensure that port groups are not configured to the value of the native VLAN (Scored): [ NOT OK ]
		"
		$checkstatus=0
		break}	
}
if ($checkstatus -ne 0){
		Write-Output "7.4 Ensure that port groups are not configured to the value of the native VLAN (Scored): [ OK ]
"}

######################################### Check CONFIGURE VLAN ###########################################
$listPort=Get-VirtualPortGroup -Standard | Select -ExpandProperty VlanID
Write-Output "7.5 Ensure that port groups are not configured to VLAN values reserved by upstream physical switches (Not Scored): [ MANUAL ]
ListVLANID: $listPort
"

############################################ Check VLAN 4095 #############################################
Foreach ($port1 in Get-VirtualPortGroup -Standard | Select -ExpandProperty VlanID ){
	if ($port1 -eq 4095) {
		Write-Output "7.6 Ensure that port groups are not configured to VLAN 4095 except for Virtual Guest Tagging (VGT) (Scored): [ NOT OK ]
		"
		$checkstatus1=0
		break}	
}
if ($checkstatus1 -ne 0){
		Write-Output "7.6 Ensure that port groups are not configured to VLAN 4095 except for Virtual Guest Tagging (VGT) (Scored): [ OK ]
"}

############################################ Check LIMIT INFO #############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkSize=Get-VM $hostVM | Get-AdvancedSetting -Name "tools.setInfo.sizeLimit" | Select -ExpandProperty Value
	if ($checkSize -ne 1048576){
		Write-Output "8.1.1 Limit informational messages from the VM to the VMX file (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"tools.setInfo.sizeLimit`" -value 1048576 
		"
		$checkstatus2=0
		break}	
}
if ($checkstatus2 -ne 0){
		Write-Output "8.1.1 Limit informational messages from the VM to the VMX file (Scored): [ OK ]
"}

########################################## Check LIMIT SHARING ############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkSize=Get-VM $hostVM | Get-AdvancedSetting -Name "RemoteDisplay.maxConnections" | Select -ExpandProperty Value
	if ($checkSize -ne 1){
		Write-Output "8.1.2 Limit sharing of console connections (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"RemoteDisplay.maxConnections`" -value 1 
		"
		$checkstatus2=0
		break}	
}
if ($checkstatus2 -ne 0){
		Write-Output "8.1.2 Limit sharing of console connections (Scored): [ OK ]
"}

########################################## Check Floppy Devices ###########################################
Write-Output "8.2.1 Disconnect unauthorized devices - Floppy Devices (Scored): [ Manual ]
List:
"
Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState 

########################################## Check CD/DVD Devices ###########################################
Write-Output "8.2.2 Disconnect unauthorized devices - CD/DVD Devices (Scored): [ Manual ]
List:
"
Get-VM | Get-CDDrive

##################################### Check Parallel Serial Devices #########################################
Write-Output "8.2.3 Disconnect unauthorized devices - Parallel Devices (Scored): [ NOT CHECK ]
"
Write-Output "8.2.4 Disconnect unauthorized devices - Serial Devices (Scored): [NOT CHECK]
"

########################################### Check USB Devices ###############################################
Write-Output "8.2.5 Disconnect unauthorized devices - USB Devices (Scored): [ Manual]
List:
"
Get-VM | Get-USBDevice

###################################### Check UnAuth Remove Devices ###########################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkDeviceAuth=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.device.edit.disable" | Select -ExpandProperty Value
	if (-Not $checkDeviceAuth){
		Write-Output "8.2.6 Prevent unauthorized removal and modification of devices. (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.device.edit.disable`" -value `$true 
		"
		$checkstatus3=0
		break}	
}
if ($checkstatus3 -ne 0){
		Write-Output "8.2.6 Prevent unauthorized removal and modification of devices. (Scored): [ OK ]
"}

##################################### Check UnAuth Connect Devices ##########################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkDeviceConn=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.device.connectable.disable" | Select -ExpandProperty Value
	if (-Not $checkDeviceConn){
		Write-Output "8.2.7 Prevent unauthorized connection of devices. (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.device.connectable.disable`" -value `$true 
		"
		$checkstatus4=0
		break}	
}
if ($checkstatus4 -ne 0){
		Write-Output "8.2.7 Prevent unauthorized connection of devices (Scored): [ OK ]
"}

Write-Output "8.3.1 Disable unnecessary or superfluous functions inside VMs (Not Scored): [ NOT CHECK]
"
Write-Output "8.3.2 Minimize use of the VM console (Not Scored): [ NOT CHECK]
"
Write-Output "8.3.3 Use secure protocols for virtual serial port access (Not Scored): [ NOT CHECK]
"
Write-Output "8.3.4 Use templates to deploy VMs whenever possible (Not Scored): [ NOT CHECK]
"   
Write-Output "8.4.1 Control access to VMs through the dvfilter network APIs (Not Scored): [ NOT CHECK]
"
Write-Output "8.4.2 Control VMsafe Agent Address (Not Scored): [ NOT CHECK]
"
Write-Output "8.4.3 Control VMsafe Agent Port (Not Scored): [ NOT CHECK]
"
Write-Output "8.4.4 Control VMsafe Agent Configuration (Not Scored): [ NOT CHECK]
"
########################################## Check AutoLogon ###############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkAutoLogon=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.ghi.autologon.disable" | Select -ExpandProperty Value
	if (-Not $checkAutoLogon){
		Write-Output "8.4.5 Disable Autologon (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.ghi.autologon.disable`" -value `$true 
		"
		$checkstatus5=0
		break}	
}
if ($checkstatus5 -ne 0){
		Write-Output "8.4.5 Disable Autologon (Scored): [ OK ]
"}

########################################## Check BIOS BSS ###############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkBIOS=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.bios.bbs.disable" | Select -ExpandProperty Value
	if (-Not $checkBIOS){
		Write-Output "8.4.6 Disable BIOS BBS (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.bios.bbs.disable`" -value `$true 
		"
		$checkstatus6=0
		break}	
}
if ($checkstatus6 -ne 0){
		Write-Output "8.4.6 Disable BIOS BBS (Scored): [ OK ]
"}

######################################## Check protocolhandler ###########################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkprotocolhandler=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.ghi.protocolhandler.info.disable" | Select -ExpandProperty Value
	if (-Not $checkprotocolhandler){
		Write-Output "8.4.7 Disable Guest Host Interaction Protocol Handler (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.ghi.protocolhandler.info.disable`" -value `$true 
		"
		$checkstatus7=0
		break}	
}
if ($checkstatus7 -ne 0){
		Write-Output "8.4.7 Disable Guest Host Interaction Protocol Handler (Scored): [ OK ]
"}

########################################## Check Taskbar ################################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkTaskbar=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.unity.taskbar.disable" | Select -ExpandProperty Value
	if (-Not $checkTaskbar){
		Write-Output "8.4.8 Disable Unity Taskbar (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.unity.taskbar.disable`" -value `$true 
		"
		$checkstatus8=0
		break}	
}
if ($checkstatus8 -ne 0){
		Write-Output "8.4.8 Disable Unity Taskbar (Scored): [ OK ]
"}

######################################## Check unityActive ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkunityActive=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.unityActive.disable" | Select -ExpandProperty Value
	if (-Not $checkunityActive){
		Write-Output "8.4.9 Disable Unity Active (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.unityActive.disable`" -value `$true 
		"
		$checkstatus9=0
		break}	
}
if ($checkstatus9 -ne 0){
		Write-Output "8.4.9 Disable Unity Active (Scored): [ OK ]
"}

###################################### Check windowContents #############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkwindowContents=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.unity.windowContents.disable" | Select -ExpandProperty Value
	if (-Not $checkwindowContents){
		Write-Output "8.4.10 Disable Unity Window Contents (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.unity.windowContents.disable`" -value `$true 
		"
		$checkstatus10=0
		break}	
}
if ($checkstatus10 -ne 0){
		Write-Output "8.4.10 Disable Unity Window Contents (Scored): [ OK ]
"}

###################################### Check Unity Update ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkUnityUpdate=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.unity.push.update.disable" | Select -ExpandProperty Value
	if (-Not $checkUnityUpdate){
		Write-Output "8.4.11 Disable Unity Push Update (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.unity.push.update.disable`" -value `$true 
		"
		$checkstatus11=0
		break}	
}
if ($checkstatus11 -ne 0){
		Write-Output "8.4.11 Disable Unity Push Update (Scored): [ OK ]
"}

#################################### Check vmxDnDVersionGet ############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkvmxDnDVersionGet=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.vmxDnDVersionGet.disable" | Select -ExpandProperty Value
	if (-Not $checkvmxDnDVersionGet){
		Write-Output "8.4.12 Disable Drag and Drop Version Get (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.vmxDnDVersionGet.disable`" -value `$true 
		"
		$checkstatus12=0
		break}	
}
if ($checkstatus12 -ne 0){
		Write-Output "8.4.12 Disable Drag and Drop Version Get (Scored): [ OK ]
"}

#################################### Check guestDnDVersionSet ###########################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkguestDnDVersionSet=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.guestDnDVersionSet.disable" | Select -ExpandProperty Value
	if (-Not $checkguestDnDVersionSet){
		Write-Output "8.4.13 Disable Drag and Drop Version Set (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.guestDnDVersionSet.disable`" -value `$true 
		"
		$checkstatus13=0
		break}	
}
if ($checkstatus13 -ne 0){
		Write-Output "8.4.13 Disable Drag and Drop Version Set (Scored): [ OK ]
"}

#################################### Check shellAction ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkshellAction=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.ghi.host.shellAction.disable" | Select -ExpandProperty Value
	if (-Not $checkshellAction){
		Write-Output "8.4.14 Disable Shell Action (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.ghi.host.shellAction.disable`" -value `$true 
		"
		$checkstatus14=0
		break}	
}
if ($checkstatus14 -ne 0){
		Write-Output "8.4.14 Disable Shell Action (Scored): [ OK ]
"}

#################################### Check dispTopoRequest ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkdispTopoRequest=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.dispTopoRequest.disable" | Select -ExpandProperty Value
	if (-Not $checkdispTopoRequest){
		Write-Output "8.4.15 Disable Request Disk Topology (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.dispTopoRequest.disable`" -value `$true 
		"
		$checkstatus15=0
		break}	
}
if ($checkstatus15 -ne 0){
		Write-Output "8.4.15 Disable Request Disk Topology (Scored): [ OK ]
"}

#################################### Check trashFolderState #############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checktrashFolderState=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.trashFolderState.disable" | Select -ExpandProperty Value
	if (-Not $checktrashFolderState){
		Write-Output "8.4.16 Disable Trash Folder State (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.trashFolderState.disable`" -value `$true 
		"
		$checkstatus16=0
		break}	
}
if ($checkstatus16 -ne 0){
		Write-Output "8.4.16 Disable Trash Folder State (Scored): [ OK ]
"}

######################################## Check trayicon ################################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checktrayicon=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.ghi.trayicon.disable" | Select -ExpandProperty Value
	if (-Not $checktrayicon){
		Write-Output "8.4.17 Disable Guest Host Interaction Tray Icon (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.ghi.trayicon.disable`" -value `$true 
		"
		$checkstatus17=0
		break}	
}
if ($checkstatus17 -ne 0){
		Write-Output "8.4.17 Disable Guest Host Interaction Tray Icon (Scored): [ OK ]
"}

########################################## Check unity #################################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkunity=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.unity.disable" | Select -ExpandProperty Value
	if (-Not $checkunity){
		Write-Output "8.4.18 Disable Unity (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.unity.disable`" -value `$true 
		"
		$checkstatus18=0
		break}	
}
if ($checkstatus18 -ne 0){
		Write-Output "8.4.18 Disable Unity (Scored): [ OK ]
"}

################################ Check unityInterlockOperation ########################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkunityInterlockOperation=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.unityInterlockOperation.disable" | Select -ExpandProperty Value
	if (-Not $checkunityInterlockOperation){
		Write-Output "8.4.19 Disable Unity Interlock (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.unityInterlockOperation.disable`" -value `$true 
		"
		$checkstatus19=0
		break}	
}
if ($checkstatus19 -ne 0){
		Write-Output "8.4.19 Disable Unity Interlock (Scored): [ OK ]
"}

######################################## Check getCreds ###############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkgetCreds=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.getCreds.disable" | Select -ExpandProperty Value
	if (-Not $checkgetCreds){
		Write-Output "8.4.20 Disable GetCreds (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.getCreds.disable`" -value `$true 
		"
		$checkstatus20=0
		break}	
}
if ($checkstatus20 -ne 0){
		Write-Output "8.4.20 Disable GetCreds (Scored): [ OK ]
"}

##################################### Check hgfsServerSet #############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkhgfsServerSet=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.hgfsServerSet.disable" | Select -ExpandProperty Value
	if (-Not $checkhgfsServerSet){
		Write-Output "8.4.21 Disable Host Guest File System Server (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.hgfsServerSet.disable`" -value `$true 
		"
		$checkstatus21=0
		break}	
}
if ($checkstatus21 -ne 0){
		Write-Output "8.4.21 Disable Host Guest File System Server (Scored): [ OK ]
"}

###################################### Check launchmenu ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checklaunchmenu=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.ghi.launchmenu.change" | Select -ExpandProperty Value
	if (-Not $checklaunchmenu){
		Write-Output "8.4.22 Disable Guest Host Interaction Launch Menu (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.ghi.launchmenu.change`" -value `$true 
		"
		$checkstatus22=0
		break}	
}
if ($checkstatus22 -ne 0){
		Write-Output "8.4.22 Disable Guest Host Interaction Launch Menu (Scored): [ OK ]
"}

################################ Check memSchedFakeSampleStats ########################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkmemSchedFakeSampleStats=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.memSchedFakeSampleStats.disable" | Select -ExpandProperty Value
	if (-Not $checkmemSchedFakeSampleStats){
		Write-Output "8.4.23 Disable memSchedFakeSampleStats (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.memSchedFakeSampleStats.disable`" -value `$true 
		"
		$checkstatus23=0
		break}	
}
if ($checkstatus23 -ne 0){
		Write-Output "8.4.23 Disable memSchedFakeSampleStats (Scored): [ OK ]
"}

###################################### Check tools copy ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkcopy=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.copy.disable" | Select -ExpandProperty Value
	if (-Not $checkcopy){
		Write-Output "8.4.24 Disable VM Console Copy operations (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.copy.disable`" -value `$true 
		"
		$checkstatus24=0
		break}	
}
if ($checkstatus24 -ne 0){
		Write-Output "8.4.24 Disable VM Console Copy operations (Scored): [ OK ]
"}

###################################### Check tools dnd ###############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkdnd=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.dnd.disable" | Select -ExpandProperty Value
	if (-Not $checkdnd){
		Write-Output "8.4.25 Disable VM Console Drag and Drop operations (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.dnd.disable`" -value `$true 
		"
		$checkstatus25=0
		break}	
}
if ($checkstatus25 -ne 0){
		Write-Output "8.4.25 Disable VM Console Drag and Drop operations (Scored): [ OK ]
"}

#################################### Check setGUIOptions #############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checksetGUIOptions=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.setGUIOptions.enable" | Select -ExpandProperty Value
	if (-Not $checksetGUIOptions){
		Write-Output "8.4.26 Disable VM Console GUI Options (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.setGUIOptions.enable`" -value `$true 
		"
		$checkstatus26=0
		break}	
}
if ($checkstatus26 -ne 0){
		Write-Output "8.4.26 Disable VM Console GUI Options (Scored): [ OK ]
"}

##################################### Check tool paste ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkpaste=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.paste.disable" | Select -ExpandProperty Value
	if (-Not $checkpaste){
		Write-Output "8.4.27 Disable VM Console Paste operations (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.paste.disable`" -value `$true 
		"
		$checkstatus27=0
		break}	
}
if ($checkstatus27 -ne 0){
		Write-Output "8.4.27 Disable VM Console Paste operations (Scored): [ OK ]
"}

#################################### Check RemoteDisplay ###########################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkRemoteDisplay=Get-VM $hostVM | Get-AdvancedSetting -Name "RemoteDisplay.vnc.enabled" | Select -ExpandProperty Value
	if ($checkRemoteDisplay){
		Write-Output "8.4.28 Control access to VM console via VNC protocol (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"RemoteDisplay.vnc.enabled`" -value `$false 
		"
		$checkstatus28=0
		break}	
}
if ($checkstatus28 -ne 0){
		Write-Output "8.4.28 Control access to VM console via VNC protocol (Scored): [ OK ]
"}

###################################### Check vgaOnly ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkvgaOnly=Get-VM $hostVM | Get-AdvancedSetting -Name "svga.vgaOnly" | Select -ExpandProperty Value
	if (-Not $checkvgaOnly){
		Write-Output "8.4.29 Disable all but VGA mode on virtual machines. (Not Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"svga.vgaOnly`" -value `$true 
		"
		$checkstatus29=0
		break}	
}
if ($checkstatus29 -ne 0){
		Write-Output "8.4.29 Disable all but VGA mode on virtual machines. (Not Scored): [ OK ]
"}

############################## Check VMResourceConfiguration ######################################
Write-Output "8.5.1 Prevent virtual machines from taking over resources (Not Scored): [ MANUAL ]
List all resources:
"
Get-VM | Get-VMResourceConfiguration

#################################### Check Persistent #############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkPersistence=Get-VM $hostVM | Get-HardDisk | Select -ExpandProperty Persistence
	if ($checkPersistence -ne "Persistent"){
		Write-Output "8.6.1 Avoid using nonpersistent disks (Scored): [ NOT OK ]
Fix: Get-VM | Get-HardDisk | Set-HardDisk 
		"
		$checkstatus30=0
		break}	
}
if ($checkstatus30 -ne 0){
		Write-Output "8.6.1 Avoid using nonpersistent disks (Scored): [ OK ]
"}

###################################### Check diskShrink ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkdiskShrink=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.diskShrink.disable" | Select -ExpandProperty Value
	if (-Not $checkdiskShrink){
		Write-Output "8.6.2 Disable virtual disk shrinking (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.diskShrink.disable`" -value `$true 
		"
		$checkstatus31=0
		break}
}
if ($checkstatus31 -ne 0){
		Write-Output "8.6.2 Disable virtual disk shrinking (Scored): [ OK ]
"}

###################################### Check diskWiper ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkdiskWiper=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.diskWiper.disable" | Select -ExpandProperty Value
	if (-Not $checkdiskWiper){
		Write-Output "8.6.3 Disable virtual disk wiping (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.diskWiper.disable`" -value `$true 
		"
		$checkstatus32=0
		break}
}
if ($checkstatus32 -ne 0){
		Write-Output "8.6.3 Disable virtual disk wiping (Scored): [ OK ]
"}

###################################### Check vixMessage ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkvixMessage=Get-VM $hostVM | Get-AdvancedSetting -Name "isolation.tools.vixMessage.disable" | Select -ExpandProperty Value
	if (-Not $checkvixMessage){
		Write-Output "8.7.1 Disable VIX messages from the VM (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"isolation.tools.vixMessage.disable`" -value `$true 
		"
		$checkstatus33=0
		break}
}
if ($checkstatus33 -ne 0){
		Write-Output "8.7.1 Disable VIX messages from the VM (Scored): [ OK ]
"}

###################################### Check log Old ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checklogOld=Get-VM $hostVM | Get-AdvancedSetting -Name "log.keepOld" | Select -ExpandProperty Value
	if (-Not $checklogOld){
		Write-Output "8.7.2 Limit number of VM log files (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"log.keepOld`" -value `"10`"  
		"
		$checkstatus34=0
		break}
}
if ($checkstatus34 -ne 0){
	Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
		$checklogOld1=Get-VM $hostVM | Get-AdvancedSetting -Name "log.keepOld" | Select -ExpandProperty Value
		if ($checklogOld1 -ne 10){
				Write-Output "8.7.2 Limit number of VM log files (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"log.keepOld`" -value `"10`" 
		"
		$checkstatus35=0
		break}
	}
	if ($checkstatus35 -ne 0){
		Write-Output "8.7.2 Limit number of VM log files (Scored): [ OK ]
"}
}

###################################### Check guestlib ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkguestlib=Get-VM $hostVM | Get-AdvancedSetting -Name "tools.guestlib.enableHostInfo" | Select -ExpandProperty Value
	if ($checkguestlib){
		Write-Output "8.7.3 Do not send host information to guests (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"tools.guestlib.enableHostInfo`" -value `$false 
		"
		$checkstatus36=0
		break}
}
if ($checkstatus36 -ne 0){
		Write-Output "8.7.3 Do not send host information to guests (Scored): [ OK ]
"}

###################################### Check log Rotate ##############################################
Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
	$checkrotateSize=Get-VM $hostVM | Get-AdvancedSetting -Name "log.rotateSize" | Select -ExpandProperty Value
	if (-Not $checkrotateSize){
		Write-Output "8.7.4 Limit VM log file size (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"log.rotateSize`" -value `"1024000`"  
		"
		$checkstatus37=0
		break}
}
if ($checkstatus37 -ne 0){
	Foreach ($hostVM in Get-VM | Select -ExpandProperty Name){
		$checkrotateSize1=Get-VM $hostVM | Get-AdvancedSetting -Name "log.rotateSize" | Select -ExpandProperty Value
		if ($checkrotateSize1 -ne 1024000){
				Write-Output "8.7.4 Limit VM log file size (Scored): [ NOT OK ]
Fix: Get-VM | New-AdvancedSetting -Name `"log.rotateSize`" -value `"1024000`" 
		"
		$checkstatus38=0
		break}
	}
	if ($checkstatus38 -ne 0){
		Write-Output "8.7.4 Limit VM log file size (Scored): [ OK ]
"}
}

