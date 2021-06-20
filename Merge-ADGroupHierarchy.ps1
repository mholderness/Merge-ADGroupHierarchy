
<#PSScriptInfo

.VERSION 1.0
.GUID b8162e57-ef1f-43df-9fee-f1049f2c6af5
.AUTHOR Mark Holderness
.PROJECTURI https://github.com/mholderness/Merge-ADGroupHierarchy
#>

<# 

.DESCRIPTION 
 One-way synchronisation of indirect members of a group to direct members of a group.
 Use where you have separated groups that contain people (role groups) from groups used to apply resource permissions but the resource in question does not support group nesting.
 More information on separating role and resource groups can be found in the "Separating People and Resources" section of the following article: https://ss64.com/nt/syntax-groups.html
  1. Using the Get-ADGroupMembers inner function:
     a. Find direct members of a group.
     b. Find indirect members of a group.
  2. Compare the direct and indirect lists and calculate what AD objects need to be added or removed as direct members. 

.SYNOPSIS
 One-way synchronisation of indirect members of a group to  direct members of a group.

#>
[cmdletbinding(SupportsShouldProcess=$True)]
Param(
	<#	Specifies an Active Directory group object.  See the requirements of the Identity parameter of Get-ADGroup for more information:
		'Get-Help -Name Get-ADGroup -Parameter Identity'
	#>
	[Parameter(Mandatory,Position=0,ValueFromPipeline)]$Identity,
	<#	Specified properties to return from AD Group members.  
	#>
	[string[]]$MemberProperties = @("Name","Title","Department","Company"),
	<#	Specifies whether to skip the group if it doesn't contain any direct member groups.
		Used to skip resource groups that only contain people and membership is not comprised of role groups.
	#>
	[switch]$SkipGroupWithNoNestedGroup,
	<#	Specifies whether to skip group if it doesn't contain any indirect members.
		Used if the role groups that comprise the membership of a role group are empty (accidently or intentionally) and you'd prefer to manually clear direct members (or fix the role groups).
	#>
	[switch]$SkipGroupWithNoIndirectMember,
	<#	Specifies whether to log the scripts output to file.  A transcript is started and the output is converted to and recorded in an HTML file.
	#>
	[switch]$IncludeCurrentMembersInLog,
	<#	Specifies whether current direct and indirect members are included in the HTML logs (if LogToFile or LogToEmail) are specified.  Depending on the size of the group, the output could be large.
		By default, how many direct and indirect members are included in the HTML but the members are not.  Direct and indirect members are included in the output of the script regardless.
	#>
	[switch]$LogToFile,
	<#	Specifies how many days to retain the scripts log files.  Set to 0 to disable log file cleanup.
	#>
	[int]$LogFileRetention = 30,
	<#	Specifies whether to e-mail the scripts output.  The e-mail content matches the HTML log file content.  The e-mail content can be influenced by LogToEmailInconsistentGroupsOnly parameter.
	#>
	[switch]$LogToEmail,
	<#	If LogToEmail is provided, LogToEmailTriggerOnChange specifies whether e-mails are generated only if an attempt has been made to add or remove members.
		All groups processed will be represented in the e-mail.  This can be influenced by the LogToEmailInconsistentGroupsOnly parameter.
	#>
	[switch]$LogToEmailTriggerOnChange,
	<#	If LogToEmail is provided, LogToEmailInconsistentGroupsOnly specifies whether e-mails are generated for groups only where the direct and indirect members are not equal.
		If SkipGroupWithNoNestedGroup or SkipGroupWithNoIndirectMember are specified membership may remain intentionally inconsistent for some groups.
		Groups skipped due to to the indirect membership bypasses will always be represented in the e-mail content but will not trigger an e-mail if LogToEmailTriggerOnChange is provided.
		By default, all groups processed will be represented in the output.
	#>
	[switch]$LogToEmailInconsistentGroupsOnly,
	<#	Specifies the SMTP server used by Send-MailMessage (if LogToEmail is specified).
	#>
	[string]$SmtpServer = "smtp.domain.tld",
	<#	Specifies the From address used by Send-MailMessage (if LogToEmail is specified).
	#>
	[string]$EmailFrom = "GroupManagement@domain.tld",
	<#	Specifies the To address used by Send-MailMessage (if LogToEmail is specified).
	#>
	[string]$EmailTo = "GroupManagement@domain.tld",
	<#	Specifies the subject used by Send-MailMessage (if LogToEmail is specified).
	#>
	[string]$EmailSubject = "Merge AD Group Hierarchy"
)
Begin {
	$ScriptFileName = $MyInvocation.MyCommand.Name.Replace(".ps1","")
	Function Get-ADGroupMembers
	{	
		<#
		.DESCRIPTION 
		Get-ADGroupMembers supporting large groups.
		Returns ADObjects
		Avoids:
			msds-memberTransitive (limited in query results to 4500) and a subsequent call to AD to return AD object properties for each distinguishedName in the results.
			Get-ADGroupMember -Recursive (default Active Directory Web Services MaxGroupOrMemberEntries limit of 5000) ... and a subsequent call to Get-ADObject if the ADPrincipal object properties are not sufficient.
			LDAP_MATCHING_RULE_IN_CHAIN (which has none of the shortcomings of the above approaches but) can be very slow.
		
		.SYNOPSIS
		Get-ADGroupMembers supporting large groups (< 5000)
		.OUTPUTS
		ADObject https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management.adobject?view=activedirectory-management-10.0
		.EXAMPLE
		$DirectMembersOfBigGroup = Get-ADGroupMembers 'BigGroup' -Verbose
		.EXAMPLE
		$IndirectMembersOfBigGroup = Get-ADGroupMembers 'BigGroup' -Indirect -Verbose
		.EXAMPLE
		$RecursiveMembersOfBigGroup = Get-ADGroup 'BigGroup' | Get-ADGroupMembers -Recursive -Verbose
		#>
		[cmdletbinding(DefaultParameterSetName="GetDirectMember")]
		Param(
			<#	Specifies an Active Directory group object.  See the requirements of the Identity parameter of Get-ADGroup for more information:
					'Get-Help -Name Get-ADGroup -Parameter Identity'
			#>
			[Parameter(Mandatory,Position=0,ValueFromPipeline)]$Identity,
			<#	Specifies whether to include ADObjects with objectClass -eq group.  Groups are not returned by default.
			#>
			[switch]$IncludeGroups,
			<#	Specifies to get all members in the hierarchy of a group that do not contain child objects.
			#>
			[Parameter(ParameterSetName='GetRecursiveMember')][switch]$Recursive,
			<#	Specifies to get all indirect members in the hierarchy of a group that do not contain child objects.  In other words, return all members of directly nested groups of a group.
			#>
			[Parameter(ParameterSetName='GetIndirectMember')][switch]$Indirect,
			<#	Specifies the properties to return for each group member.
			#>
			[string[]]$MemberProperties = @("distinguishedName","name","objectClass")
		)
		Begin {

			#Hash Table used by the Get-ADObjectMemberOfGroup inner function to avoid infinite recursion.
			$ADGroupProcessed = @{}
			#Hash Table used by the Get-ADObjectMemberOfGroup inner function to returning duplicate objects.
			$ADGroupMemberSeen = @{}
			$GetADObjectMemberOfGroup = @{}
			$GetADObjectMemberOfGroup.MemberProperties = $MemberProperties
			If($IncludeGroups) {
				$GetADObjectMemberOfGroup.IncludeGroups = $IncludeGroups
			}

			Function Get-ADObjectMemberOfGroup
			{	
				[cmdletbinding()]
				Param(
					[Parameter(Mandatory,Position=0,ValueFromPipeline)]$Identity,
					[string[]]$MemberProperties = @("distinguishedName","name","objectClass"),
					[switch]$Recursive,
					[switch]$IncludeGroups
				)
				Begin {
					If($Recursive) {
						If(!$ADGroupProcessed){
							Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Create ADGroupsProcessed hash table to track process group to avoid infinite recursion."
							$ADGroupProcessed = @{}
						}
						If(!$ADGroupMemberSeen){
							Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Create ADGroupMembersSeen hash table to avoid returning duplicate members."
							$ADGroupMemberSeen = @{}
						}
						If(-Not $MemberProperties -Contains "objectClass"){
							#objectClass required to trigger recursive function calls for member groups.
							$MemberProperties += "objectClass"
						}
						$GetADObjectMemberOfGroupSplat = @{}
						$GetADObjectMemberOfGroupSplat.MemberProperties = $MemberProperties
						If($IncludeGroups) {
							$GetADObjectMemberOfGroup.IncludeGroups = $IncludeGroups
						}
					}
					$GetADObjectSplat = @{}
					$GetADObjectSplat.Properties = $MemberProperties
				}
				Process {
					ForEach($Group in $Identity){
						Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : $Group"
						[array]$ADGroup = Get-ADGroup $Group
						If($ADGroup.Count -eq 1) {
							$ADGroupIdentity = $ADGroup.distinguishedName
							If($ADGroupProcessed.ContainsKey($ADGroupIdentity)) {
								Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Skipping group to avoid infinite recursion: $($ADGroup.distinguishedName)"
							}
							Else {
								$ADGroupProcessed.Add($ADGroupIdentity,"")
								If($Recursive) {
									$Member = Get-ADObject -LDAPFilter "(&(memberOf=$($ADGroup.distinguishedName)))" @GetADObjectSplat
									#Return members that are not groups and haven't previously been returned (where an object is a member of more than one group in the hierarchy)
									$Member | ForEach-Object {
										If($ADGroupMemberSeen.ContainsKey($PSItem.distinguishedName)) {
											Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Skipping ADObject to avoid returning duplicates: $($PSItem.distinguishedName)"
										}
										Else {
											$ADGroupMemberSeen.Add($PSItem.distinguishedName,"")
											If($PSItem.objectClass -eq 'group' -And -Not $IncludeGroups) {
												Write-Verbose "$(Get-Date) | Get-ADObjectMemberOfGroup : Skipping ADObject.  objectClass -eq group and IncludeGroups -eq $IncludeGroups : $($PSItem.distinguishedName)"
											}
											Else {
												$PSItem
											}
										}
									}
									[array]$MemberGroup = $Member | Where-Object { $PSItem.objectClass -eq 'group' }
									If($MemberGroup.Count -ge 1){
										Get-ADObjectMemberOfGroup $MemberGroup @GetADObjectMemberOfGroupSplat -Recursive
									}
								}
								Else {
									If($IncludeGroups) {
										Get-ADObject -LDAPFilter "(&(memberOf=$($ADGroup.distinguishedName)))" @GetADObjectSplat
									}
									Else {
										Get-ADObject -LDAPFilter "(&(memberOf=$($ADGroup.distinguishedName))(!(objectClass=group)))" @GetADObjectSplat
									}
								}
							}
						}
					}
				}
			}

		}
		Process {
			ForEach($Group in $Identity){
				Write-Verbose "$(Get-Date) | Get-ADGroupMembers : $Group"
				[array]$ADGroup = Get-ADGroup $Group
				If($ADGroup.Count -eq 1) {
					If($Indirect) {
						Write-Verbose "$(Get-Date) | Get-ADGroupMembers : $($ADGroup.Name) : Indirect : Searching for direct members with objectClass -eq group and returning transitive members of each."
						[array]$MemberGroup = Get-ADObject -LDAPFilter "(&(memberOf=$($ADGroup.distinguishedName))(objectClass=group))"
						If($MemberGroup.Count -ge 1) {
							Get-ADObjectMemberOfGroup $MemberGroup @GetADObjectMemberOfGroup -Recursive
						}
					}
					ElseIf($Recursive) {
						Write-Verbose "$(Get-Date) | Get-ADGroupMembers : $($ADGroup.Name) : Recursive : Searching for transitive members."  
						Get-ADObjectMemberOfGroup $ADGroup.distinguishedName @GetADObjectMemberOfGroup -Recursive
					}
					Else {
						Write-Verbose "$(Get-Date) | Get-ADGroupMembers : $($ADGroup.Name) : Searching for direct members."  
						Get-ADObjectMemberOfGroup $ADGroup.distinguishedName @GetADObjectMemberOfGroup
					}
				}
				Else {
					Write-Warning "$(Get-Date) | Get-ADGroup $Group returned none or more than one."
				}
			}
		}
	}
	
	Function Get-SelectProperties
	{	
		<#
		.DESCRIPTION
		 Returns an array of selectable properties from an object or an array of objects so Export-* cmdLets return everything and not just the properties that exist on the first object passed down the pipeline.
		#>
		[cmdletbinding()]
		Param(
			[Parameter(Mandatory,Position=0,ValueFromPipeline)]$Object,
			[string[]]$PropertyOrderPreference,
			[string[]]$ExcludeProperty
		)
		Begin {
			$SelectProperties = @()
			$ObjectProperties = @{}
			If(!$ExcludeProperty) { $ExcludeProperty = @() }
		}
		Process {
			$Object | ForEach-Object {$_.PSObject.Properties.Name} | Select-Object -Unique | ForEach-Object {
				If($ObjectProperties.ContainsKey($PSItem)) {
					Write-Verbose "$(Get-Date) | Get-SelectProperties : $Property already processed by a previous object."
				}
				Else {
					$ObjectProperties.Add($PSItem,"")
				}
			}
		}
		End {
			$ObjectProperties = $ObjectProperties.Keys
			If($PropertyOrderPreference)
			{	ForEach($Property in $PropertyOrderPreference)
				{	If($ObjectProperties -Contains $Property)
					{	If($ExcludeProperty -Contains $Property)
						{	Write-Verbose "$(Get-Date) | Get-SelectProperties : $Property excluded due to ExcludeProperty."
						}
						Else
						{	$SelectProperties += @{ "Name" = $Property; "Expression" = [scriptblock]::Create("`$`_.`"$Property`"")}
						}
					}
				}
			}
			ForEach($Property in $ObjectProperties)
			{	If($SelectProperties.Name -Contains $Property)
				{	Write-Verbose "$(Get-Date) | Get-SelectProperties : $Property already processed due to PropertyOrderPreference."
				}
				ElseIf($ExcludeProperty -Contains $Property)
				{	Write-Verbose "$(Get-Date) | Get-SelectProperties : $Property excluded due to ExcludeProperty."
				}
				Else
				{	Write-Verbose "$(Get-Date) | Get-SelectProperties : $Property to be added to the SelectProperties object."
					$Hash = @{}
					$Hash.Add("Name",$Property)
					$Hash.Add("Expression",[scriptblock]::Create("`$`_.`"$Property`""))
					$SelectProperties += $Hash
				}
			}
			$SelectProperties
		}
	}

	Function Write-Transcript
	{	
		[cmdletbinding()]
		Param(
			[string]$Message,
			[switch]$IncludeTimestamp,
			[ValidateSet("Host","Warning","Verbose")][String]$WriteType = "Host",
			[System.Management.Automation.ActionPreference]$VerbosePreference
		)
		If($VerbosePreference -eq 'Continue' -And $WriteType -eq "Host") {
			$WriteType = "Verbose"
		}
		If($IncludeTimestamp) {
			$Message = "$(Get-Date) | $Message"
		}
		switch ($WriteType) {
			"Host"		{ If($LogToFile) { Write-Host $Message } }
			"Verbose"	{ Write-Verbose $Message }
			"Warning"	{ Write-Warning $Message }
		}
	}
	$WriteTranscriptSplat = @{}
	$WriteTranscriptSplat.IncludeTimestamp = $True
	If($VerbosePreference -eq 'Continue') {
		$WriteTranscriptSplat.VerbosePreference = $VerbosePreference
	}

	If($LogToFile -Or $LogToEmail) {
		$Output = @()
		Write-Transcript "MemberProperties may change (to include distinguishedName and objectClass).  Build SelectMemberProperties now (used by Select-Object in the End block) to avoid unexpected properties in the HTML logs (file or e-mail)." @WriteTranscriptSplat -WriteType "Verbose"
		$SelectMemberProperties = @()
		ForEach($Property in $MemberProperties) {
			$SelectMemberProperties += @{ "Name" = $Property; "Expression" = [scriptblock]::Create("`$`_.`"$Property`"")}
		}
		$StartDate = Get-Date -format g
		$Head = "<Style>" + `
			"BODY{font-size:12px;font-family:`"Segoe UI`",`"Calibri`",Tahoma,sans-serif;color:navy;font-weight:normal;}" + `
			"TABLE{width:100%;border-width:1px;cellpadding=10;border-style:solid;border-color:navy;border-collapse:collapse;}" + `
			"TH{font-size:14px;color:white;border-width:1px;padding:10px;border-style:solid;border-color:navy;background-color:navy}" + `
			"TD{font-size:12px;border-width:1px;padding:10px;border-style:solid;border-color:navy;vertical-align:top;}" + `
			".title1 {font-size:20px;font-style:bold;}" + `
			".title2 {font-size:14px;font-style:italic}" + `
			"ul{padding:0;margin:0;}" + `
			"li{margin-left:15px;}" + `
			"</Style>"
		If($LogToFile) {
			$Now = Get-Date
			$Today = $Now.Date
			Write-Transcript "ScriptFileName : $ScriptFileName" @WriteTranscriptSplat -WriteType "Verbose"
			Write-Transcript "Generating ScriptWorkingDirectory and TranscriptFilePath based on ScriptFileName." @WriteTranscriptSplat -WriteType "Verbose"
			$ScriptWorkingDirectory = ".\$ScriptFileName"
			Write-Transcript "Potential ScriptWorkingDirectory : $ScriptWorkingDirectory" @WriteTranscriptSplat -WriteType "Verbose"
			If(-Not (Test-Path $ScriptWorkingDirectory -PathType Container)) {
				Try {
					New-Item -Path $ScriptWorkingDirectory -ItemType Directory -WhatIf:$False | out-null
				}
				Catch {
					Write-Transcript "Failed to find\create directory $ScriptWorkingDirectory." @WriteTranscriptSplat -WriteType "Warning"
					$ScriptWorkingDirectory = "$($Env:TEMP)\$ScriptFileName"
					New-Item -Path $ScriptWorkingDirectory -ItemType Directory -WhatIf:$False | out-null
				}
			}
			If(-Not (Test-Path $ScriptWorkingDirectory -PathType Container)) {
				Write-Transcript "Failed to create script working directory: $ScriptWorkingDirectory. Defaulting to current working directory.  LogToFile may fail." @WriteTranscriptSplat -WriteType "Warning"
				$ScriptWorkingDirectory = "."
			}
			
			If($WhatIfPreference){
				$TranscriptFileNamePrefix = "$($ScriptFileName)_WhatIf_transcript"
			}
			Else {
				$TranscriptFileNamePrefix = "$($ScriptFileName)_transcript"
			}
			$TranscriptFilePath = "$ScriptWorkingDirectory\$($TranscriptFileNamePrefix)_$($Now.Ticks).log"
			Start-Transcript $TranscriptFilePath -WhatIf:$False | out-null
			Write-Transcript "TranscriptFilePath : $TranscriptFilePath" @WriteTranscriptSplat -WriteType "Verbose"
			If($LogFileRetention -ge 1){
				Write-Transcript "$ScriptFileName : Removing any Transcript Log Files with the filter $TranscriptFileNamePrefix* older than $LogFileRetention days." @WriteTranscriptSplat -WriteType "Verbose"
				Get-ChildItem -File -Path "$ScriptWorkingDirectory\$TranscriptFileNamePrefix*" | Where-Object {
					$PSItem.LastWriteTime -lt $Today.AddDays(-$LogFileRetention)
				} | Remove-Item
			}
		}
		If($LogToEmail) {
			If($LogToEmailTriggerOnChange) {
				Write-Transcript "$ScriptFileName : LogToEmailTriggerOnChange -eq $LogToEmailTriggerOnChange.  Generating LogToEmailTriggerOnChangeFlag." @WriteTranscriptSplat -WriteType "Verbose"
				$LogToEmailTriggerOnChangeFlag = $False
			}
		}
	}

	If(-Not $MemberProperties -Contains "distinguishedName"){
		Write-Transcript "distinguishedName required to Compare-Object between direct members and indirect members." @WriteTranscriptSplat -WriteType "Verbose"
		$MemberProperties += "distinguishedName"
	}
	If(-Not $MemberProperties -Contains "objectClass"){
		Write-Transcript "objectClass required to trigger recursive function calls for member groups." @WriteTranscriptSplat -WriteType "Verbose"
		$MemberProperties += "objectClass"
	}

}
Process {
	ForEach($Group in $Identity){
		Write-Transcript "$ScriptFileName : $Group" @WriteTranscriptSplat
		[array]$ADGroup = Get-ADGroup $Group
		If($ADGroup.Count -eq 1) {
			$ADGroupProperties = [Ordered]@{}
			$ADGroupProperties.GroupName = $ADGroup.Name
			$ADGroupProperties.DistinguishedName = $ADGroup.DistinguishedName
			Write-Transcript "$($ADGroup.Name) | Find direct members and indirect members of the group ready to compare." @WriteTranscriptSplat
			$ADGroupProperties.member = Get-ADGroupMembers $ADGroup -MemberProperties $MemberProperties -IncludeGroups
			$ADGroupProperties.DirectMember = $ADGroupProperties.member | Where-Object { $PSItem.objectClass -ne 'group' } | Sort-Object $MemberProperties
			$ADGroupProperties.DirectMemberCount = ([array]$ADGroupProperties.DirectMember).Count
			Write-Transcript "$($ADGroup.Name) | Direct Member Count : $($ADGroupProperties.DirectMemberCount)" @WriteTranscriptSplat
			$ADGroupProperties.MemberGroup = $ADGroupProperties.member | Where-Object { $PSItem.objectClass -eq 'group' }
			$ADGroupProperties.MemberGroupCount = ([array]$ADGroupProperties.MemberGroup).Count
			Write-Transcript "$($ADGroup.Name) | Member Group Count : $($ADGroupProperties.DirectMemberCount)" @WriteTranscriptSplat
			If($ADGroupProperties.MemberGroupCount -ge 1) {
				$ADGroupProperties.MemberGroupFound = $True
			}
			Else {
				$ADGroupProperties.MemberGroupFound = $False
			}
			$ADGroupProperties.IndirectMember = Get-ADGroupMembers $ADGroup -Indirect -MemberProperties $MemberProperties | Sort-Object $MemberProperties
			$ADGroupProperties.IndirectMemberCount = ([array]$ADGroupProperties.IndirectMember).Count
			Write-Transcript "$($ADGroup.Name) | Indirect Member Count : $($ADGroupProperties.IndirectMemberCount)" @WriteTranscriptSplat
			
			If($ADGroupProperties.DirectMemberCount -gt 0 -And $ADGroupProperties.IndirectMemberCount -gt 0) {
				Write-Transcript "$($ADGroup.Name) | The group has direct members and indirect members.  Compare them to find objects that need to be added or removed as direct members." @WriteTranscriptSplat -WriteType "Verbose"
				$ADGroupProperties.MemberInconsistency = Compare-Object $ADGroupProperties.DirectMember $ADGroupProperties.IndirectMember -Property distinguishedName -PassThru
				$ADGroupProperties.MemberInconsistencyCount = ([array]$ADGroupProperties.MemberInconsistency).Count
				Write-Transcript "$($ADGroup.Name) | Member Inconsistency Count : $($ADGroupProperties.MemberInconsistencyCount)" @WriteTranscriptSplat
				If($ADGroupProperties.MemberInconsistencyCount -ge 1) {
					$ADGroupProperties.MemberInconsistent = $True
					If($ADGroupProperties.MemberInconsistency | Where-Object { $_.SideIndicator -eq "=>" }) {
						$ADGroupProperties.AddMember = $ADGroupProperties.MemberInconsistency | Where-Object { $_.SideIndicator -eq "=>" }
						$ADGroupProperties.AddMemberCount = ([array]$ADGroupProperties.AddMember).Count
						Write-Transcript "$($ADGroup.Name) | Add Member Count : $($ADGroupProperties.AddMemberCount)" @WriteTranscriptSplat
					}
					If($ADGroupProperties.MemberInconsistency | Where-Object { $_.SideIndicator -eq "<=" }) {
						$ADGroupProperties.RemoveMember = $ADGroupProperties.MemberInconsistency | Where-Object { $_.SideIndicator -eq "<=" }
						$ADGroupProperties.RemoveMemberCount = ([array]$ADGroupProperties.RemoveMember).Count
						Write-Transcript "$($ADGroup.Name) | Remove Member Count : $($ADGroupProperties.RemoveMemberCount)" @WriteTranscriptSplat
					}
				}
			}
			ElseIf($ADGroupProperties.DirectMemberCount -gt 0 -Or $ADGroupProperties.IndirectMemberCount -gt 0) {
				$ADGroupProperties.MemberInconsistent = $True
				Write-Transcript "$($ADGroup.Name) | Either the group has no direct members or indirect members.  Adding or removing direct members based on whether the group contains direct or indirect members." @WriteTranscriptSplat -WriteType "Verbose"
				If($ADGroupProperties.DirectMemberCount -gt 0) {
					Write-Transcript "$($ADGroup.Name) | Group has direct members but no indirect members." @WriteTranscriptSplat
					If($SkipGroupWithNoNestedGroup -And $ADGroupProperties.MemberGroupFound -eq $False) {
						Write-Transcript "$($ADGroup.Name) | Skipping group, it does not contain any groups AND SkipGroupWithNoNestedGroup -eq $SkipGroupWithNoNestedGroup." @WriteTranscriptSplat
					}
					ElseIf($SkipGroupWithNoIndirectMember) {
						Write-Transcript "$($ADGroup.Name) | Skipping group, it does not contain any indirect members AND SkipGroupWithNoIndirectMember -eq $SkipGroupWithNoIndirectMember." @WriteTranscriptSplat
					}
					Else {
						Write-Transcript "$($ADGroup.Name) | No indirect members found.  Select all direct members ready to remove." @WriteTranscriptSplat -WriteType "Verbose"
						$ADGroupProperties.RemoveMember = $ADGroupProperties.DirectMember
						$ADGroupProperties.RemoveMemberCount = ([array]$ADGroupProperties.RemoveMember).Count
						Write-Transcript "$($ADGroup.Name) | Remove Member Count : $($ADGroupProperties.RemoveMemberCount)" @WriteTranscriptSplat
					}
				}
				If($ADGroupProperties.IndirectMemberCount -gt 0) {
					Write-Transcript "$($ADGroup.Name) | Group has indirect members but no direct members." @WriteTranscriptSplat
					Write-Transcript "$($ADGroup.Name) | No direct members found.  Select all indirect members ready to add as direct members." @WriteTranscriptSplat -WriteType "Verbose"
					$ADGroupProperties.RemoveMember = $ADGroupProperties.IndirectMember
					$ADGroupProperties.RemoveMemberCount = ([array]$ADGroupProperties.RemoveMember).Count
					Write-Host "$(Get-Date) | $Group | Remove Member Count : $($ADGroupProperties.RemoveMemberCount)"
				}
			}
			Else {
				$ADGroupProperties.MemberInconsistent = $False
			}
			
			If($ADGroupProperties.AddMember) {
				If($LogToEmailTriggerOnChange -eq $True -And $LogToEmailTriggerOnChangeFlag -eq $False) {
					$LogToEmailTriggerOnChangeFlag = $True
					Write-Transcript "$ScriptFileName : LogToEmailTriggerOnChange -eq $LogToEmailTriggerOnChange.  LogToEmailTriggerOnChangeFlag now -eq $LogToEmailTriggerOnChangeFlag." @WriteTranscriptSplat -WriteType "Verbose"
				}
				Try {
					Write-Transcript "$($ADGroup.Name) | Add-ADGroupMember." @WriteTranscriptSplat
					Add-ADGroupMember $ADGroup.DistinguishedName -Members $ADGroupProperties.AddMember
				}
				Catch {
					Write-Transcript "$($ADGroup.Name) | Add-ADGroupMember failed.  $($PSItem.Exception.Message)" @WriteTranscriptSplat -WriteType "Warning"
					$ADGroupProperties.AddMemberError = $PSItem.Exception.Message
				}
			}
			If($ADGroupProperties.RemoveMember) {
				If($LogToEmailTriggerOnChange -eq $True -And $LogToEmailTriggerOnChangeFlag -eq $False) {
					$LogToEmailTriggerOnChangeFlag = $True
					Write-Transcript "$ScriptFileName : LogToEmailTriggerOnChange -eq $LogToEmailTriggerOnChange.  LogToEmailTriggerOnChangeFlag now -eq $LogToEmailTriggerOnChangeFlag." @WriteTranscriptSplat -WriteType "Verbose"
				}
				Try {
					Write-Transcript "$($ADGroup.Name) | Remove-ADGroupMember." @WriteTranscriptSplat
					Remove-ADGroupMember $ADGroup.DistinguishedName -Members $ADGroupProperties.RemoveMember -Confirm:$False
				}
				Catch {
					Write-Transcript "$($ADGroup.Name) | Remove-ADGroupMember failed.  $($PSItem.Exception.Message)" @WriteTranscriptSplat -WriteType "Warning"
					$ADGroupProperties.RemoveMemberError = $PSItem.Exception.Message
				}
			}

			[PSCustomObject]$ADGroupProperties
			If($LogToFile -Or $LogToEmail) {
				$Output += [PSCustomObject]$ADGroupProperties
			}
		}
	}
}
End {
	If($Output.Count -ge 1) {
		If($LogToFile -Or $LogToEmail) {
			Write-Transcript "$ScriptFileName : Sorting output to bring interesting groups to the top of any HTML log files." @WriteTranscriptSplat
			$Output = $Output | Sort MemberGroupFound,MemberInconsistent,AddMemberCount,RemoveMemberCount,DirectMemberCount,GroupName -Desc
			Write-Transcript "$ScriptFileName : Collecting selectable properties ready for ConvertTo-Html." @WriteTranscriptSplat -WriteType "Verbose"
			If($IncludeCurrentMembersInLog) {
				$SelectProperties = Get-SelectProperties $Output -PropertyOrderPreference GroupName,MemberGroup,DirectMemberCount,IndirectMemberCount,DirectMember,IndirectMember,AddMemberCount,RemoveMemberCount,AddMember,RemoveMember,AddMemberError,RemoveMemberError -ExcludeProperty DistinguishedName,member,MemberGroupCount,MemberGroupFound,MemberInconsistency,MemberInconsistencyCount,MemberInconsistent
			}
			Else {
				$SelectProperties = Get-SelectProperties $Output -PropertyOrderPreference GroupName,MemberGroup,DirectMemberCount,IndirectMemberCount,AddMemberCount,RemoveMemberCount,AddMember,RemoveMember,AddMemberError,RemoveMemberError -ExcludeProperty DistinguishedName,member,DirectMember,MemberGroupCount,MemberGroupFound,IndirectMember,MemberInconsistency,MemberInconsistencyCount,MemberInconsistent
			}
			If($SelectProperties | Where-Object { $_.Name -eq 'MemberGroup' }) {
				($SelectProperties | Where-Object { $_.Name -eq 'MemberGroup' }).Expression = [scriptblock]::Create("`"`$((`$`_.MemberGroup.Name `-`Join `'`<br`>`r`n`'))`"")
			}
			If($SelectProperties | Where-Object { $_.Name -eq 'DirectMember' }) {
				($SelectProperties | Where-Object { $_.Name -eq 'DirectMember' }).Expression = [scriptblock]::Create("`"`$(`$`_.DirectMember `| Select`-Object `$SelectMemberProperties `| ConvertTo`-HTML `-Fragment)`"")
			}
			If($SelectProperties | Where-Object { $_.Name -eq 'IndirectMember' }) {
				($SelectProperties | Where-Object { $_.Name -eq 'IndirectMember' }).Expression = [scriptblock]::Create("`"`$(`$`_.IndirectMember `| Select`-Object `$SelectMemberProperties `| ConvertTo`-HTML `-Fragment)`"")
			}
			If($SelectProperties | Where-Object { $_.Name -eq 'AddMember' }) {
				($SelectProperties | Where-Object { $_.Name -eq 'AddMember' }).Expression = [scriptblock]::Create("`"`$(`$`_.AddMember `| Select`-Object `$SelectMemberProperties `| ConvertTo`-HTML `-Fragment)`"")
			}
			If($SelectProperties | Where-Object { $_.Name -eq 'RemoveMember' }) {
				($SelectProperties | Where-Object { $_.Name -eq 'RemoveMember' }).Expression = [scriptblock]::Create("`"`$(`$`_.RemoveMember `| Select`-Object `$SelectMemberProperties `| ConvertTo`-HTML `-Fragment)`"")
			}
			Write-Transcript "$ScriptFileName : Prepending any capital letters each column name with a space for aesthetics." @WriteTranscriptSplat -WriteType "Verbose"
			ForEach($Property in $SelectProperties) {
				$CharReplace = @()
				$Property.Name.ToCharArray() | ForEach-Object {
					If($PSItem -cmatch "[A-Z]") { $CharReplace += $PSItem }
				}
				ForEach($Char in $CharReplace) {
					$Property.Name = $Property.Name.Replace("$Char"," $Char")
				}
				$Property.Name = $Property.Name.TrimStart()
			}
			If($WhatIfPreference) {
				$EmailSubject = "$EmailSubject WhatIf"
			}
			$ConvertToHtmlSplat = @{}
			$ConvertToHtmlSplat.Head = $Head
			$CompleteDate = Get-Date -format g
			$ConvertToHtmlSplat.PreContent = "<p><span class=`"title1`">$EmailSubject</span></p>" + `
				"<p><span class=`"title2`">WhatIf : $WhatIfPreference</span></p>"
			$ConvertToHtmlSplat.PostContent = "<p><span class=`"title2`">Generated From : $($env:computername)</span><br>" + `
				"<span class=`"title2`">Started At : $StartDate</span><br>" + `
				"<span class=`"title2`">Completed At : $CompleteDate</span><br></p>"
			If($LogToEmail) {
				If($LogToEmailTriggerOnChange -eq $True -And $LogToEmailTriggerOnChangeFlag -eq $False) {
					Write-Transcript "$ScriptFileName : LogToEmail requested, LogToEmailTriggerOnChange specified.  LogToEmailTriggerOnChangeFlag -eq $LogToEmailTriggerOnChangeFlag.  Skipping LogToEmail." @WriteTranscriptSplat
				}
				Else {
					Write-Transcript "$ScriptFileName : ConvertToHTML for Send-MailMessage -BodyAsHtml." @WriteTranscriptSplat
					If($LogToEmailInconsistentGroupsOnly) {
						Write-Transcript "$ScriptFileName : Generating e-mail body filtering for inconsistent members." @WriteTranscriptSplat -WriteType "Verbose"
						$EmailBodyHTML = $Output | Where-Object { $PSItem.MemberInconsistent -eq $True } | Select-Object $SelectProperties | ConvertTo-HTML @ConvertToHtmlSplat | Out-String | ForEach-Object {
							$PSItem.Replace("&lt;","<").Replace("&gt;",">").Replace("&;","&").Replace("<ul><li></li></ul>","").Replace("<ul><li>  () </li></ul>","").Replace("&amp;#39;","`'").Replace("<table> </table>","")
						}
					}
					Else {
						Write-Transcript "$ScriptFileName : Generating e-mail body." @WriteTranscriptSplat -WriteType "Verbose"
						$EmailBodyHTML = $Output | Select-Object $SelectProperties | ConvertTo-HTML @ConvertToHtmlSplat | Out-String | ForEach-Object {
							$PSItem.Replace("&lt;","<").Replace("&gt;",">").Replace("&;","&").Replace("<ul><li></li></ul>","").Replace("<ul><li>  () </li></ul>","").Replace("&amp;#39;","`'").Replace("<table> </table>","")
						}
					}
					Write-Transcript "$ScriptFileName : Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $EmailSubject -SmtpServer $SMTPServer" @WriteTranscriptSplat
					Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $EmailSubject -SmtpServer $SMTPServer -BodyAsHtml ($EmailBodyHTML)
				}
			}
			If($LogToFile) {
				Write-Transcript "$ScriptFileName : ConvertToHTML for LogToFile." @WriteTranscriptSplat
				$LogFileHTML = $Output | Select-Object $SelectProperties | ConvertTo-HTML @ConvertToHtmlSplat | Out-String | ForEach-Object {
					$PSItem.Replace("&lt;","<").Replace("&gt;",">").Replace("&;","&").Replace("<ul><li></li></ul>","").Replace("<ul><li>  () </li></ul>","").Replace("&amp;#39;","`'").Replace("<table> </table>","")
				}
				Write-Transcript "$ScriptFileName : Generating LogFilePath." @WriteTranscriptSplat -WriteType "Verbose"
				If($WhatIfPreference){
					$LogFilePrefix = "$($ScriptFileName)_WhatIf_summary"
				}
				Else {
					$LogFilePrefix = "$($ScriptFileName)_summary"
				}
				$LogFilePath = "$ScriptWorkingDirectory\$($LogFilePrefix)_$($Now.Ticks).html"
				If($LogFileRetention -ge 1){
					Write-Transcript "$ScriptFileName : Removing any HTML Log Files with the filter $LogFilePrefix* older than $LogFileRetention days." @WriteTranscriptSplat -WriteType "Verbose"
					Get-ChildItem -File -Path "$ScriptWorkingDirectory\$LogFilePrefix*" | Where-Object {
						$PSItem.LastWriteTime -lt $Today.AddDays(-$LogFileRetention)
					} | Remove-Item
				}
				$LogFileHTML | Out-File $LogFilePath -WhatIf:$False
			}
		}
		Stop-Transcript | out-null
	}
}
