using namespace System;
using namespace System.Security;

$aipath = [Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16");

# MS updated the location recently
$aipath = Get-Item -Path $([IO.Path]::Combine($aipath, 'AI'));

$files2block = Get-ChildItem -Path $aipath -Depth 0 -File | 
? { $_.name -imatch "ai[a-z]*.dll$" -or $_.name -imatch "ai[a-z]*.exe$"};

$sid = [Principal.SecurityIdentifier]::new([Principal.WellKnownSidType]::BuiltinUsersSid, $null);
$FileSystemRights = [AccessControl.FileSystemRights]::ReadAndExecute;
$AccessControlType = [AccessControl.AccessControlType]::Deny;
$AccessRule = [AccessControl.FileSystemAccessRule]::new($sid, $FileSystemRights, $AccessControlType);

Function isBlocked
{
    Param(
        [string]$filepath
    )
    [AccessControl.FileSecurity]$ret = get-acl -Path $filepath;

    [bool]$inludeExplicit = $true;
    [bool]$inludeInherited = $true;

    [AccessControl.AuthorizationRuleCollection]$ret.GetAccessRules($inludeExplicit, $inludeInherited, $sid.GetType());
    $count = ($ret.Access | Where-Object {$_.AccessControlType -eq $AccessControlType -and $_.FileSystemRights -eq $FileSystemRights} | Measure-Object).Count

    return [bool]($count -gt 0);
}

$files2block | % {
    $fp = $_.PSPath;
    if(isBlocked -filepath $fp)
    {
        #Write-Output "blocked!";
    }
    else {
        $acl = Get-Acl -Path $fp;
        $acl.SetAccessRule($AccessRule);
        Set-Acl -AclObject $acl -Path $fp;
    }
}
