# Merge-ADGroupHierarchy
One-way synchronisation of indirect members to direct members of an Active Directory group.

Use where you have separated groups that contain people (role groups) from groups used to apply resource permissions but the resource in question does not support group nesting.
More information on separating role and resource groups can be found in the "Separating People and Resources" section of the following article: https://ss64.com/nt/syntax-groups.html
  1. Using the Get-ADGroupMembers inner function:
     a. Find direct members of a group.
     b. Find indirect members of a group.
  2. Compare the direct and indirect lists and calculate what AD objects need to be added or removed as direct members. 
