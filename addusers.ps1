$users = Import-Csv -Path C:\Users\Administrator\Downloads\users.csv

foreach($user in $users) {
    $username = $user.Login
    $usernamenumber = 2
    $newusername = $username + $usernamenumber
    $homedir = "\\files\HomeFolders\$UserName"

    if (Get-ADUser -Filter {SamAccountName -eq $username})
    {
        while (Get-ADUser -Filter {SamAccountName -eq $newusername})
        {
            $usernamenumber = $usernamenumber + 1
            $newusername = $username + $usernamenumber
        }

        Write-Warning "$username - An account with that name already exists, user will be renamed to $newusername."

        $UserPrincipalName = $newusername + "@company.com"
        New-ADUser -Name $newusername `
        -SamAccountName $newusername `
        -DisplayName $user.Name `
        -UserPrincipalName $UserPrincipalName `
        -EmailAddress $user.Email `
        -Department $user.Department `
        -Description $user.Description `
        -AccountPassword (ConvertTo-SecureString -AsPlainText "Syp9393" -Force) `
        -Enabled $true `
        -Path "OU=users,OU=site1,DC=internal,DC=marst,DC=com" `
        -HomeDrive H: `
        -HomeDirectory "\\files\folders\$($newusername)"
        Add-ADGroupMember -Identity $user.Department `
        -Members $newusername 
            
    if (-not (Test-Path $homedir)) {
        $acl = (md $homedir).GetAccessControl()
        $perm = ($newusername + "@company.com"),"Modify","ContainerInherit, ObjectInherit","None","Allow"
        $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $perm
            $acl.ResetAccessRule($accessRule)
            $acl|Set-Acl -Path $homedir
            }
    }
    
    else 
    {
    $UserPrincipalName = $username + "@company.com"
        New-ADUser -Name $username `
        -SamAccountName $username `
        -DisplayName $user.Name `
        -UserPrincipalName $UserPrincipalName `
        -EmailAddress $user.Email `
        -Department $user.Department `
        -Description $user.Description `
        -AccountPassword (ConvertTo-SecureString -AsPlainText "Syp9393" -Force) `
        -Enabled $true `
        -Path "OU=users,OU=site1,DC=internal,DC=marst,DC=com" `
        -HomeDrive H: `
        -HomeDirectory "\\files\HomeFolders\$($username)"
        Add-ADGroupMember -Identity $user.Department `
        -Members $username

    if (-not (Test-Path $homedir)) {
        $acl = (md $homedir).GetAccessControl()
        $perm = ($username + "@company.com"),"Modify","ContainerInherit, ObjectInherit","None","Allow"
        $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $perm
            $acl.ResetAccessRule($accessRule)
            $acl|Set-Acl -Path $homedir
            }
    } 
}
