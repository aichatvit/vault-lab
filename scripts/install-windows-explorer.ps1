#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Install')]
param(
    [Parameter(Mandatory, ParameterSetName='Install')]
    [string] $Plugin,
    [Parameter(ParameterSetName='Install')]
    [string] $Executable = (Join-Path $PSScriptRoot '..\target\release\vault-lab.exe'),
    [Parameter(Mandatory, ParameterSetName='Remove')]
    [switch] $Uninstall
)
$ErrorActionPreference = 'Stop'
$verbs = 'Software\Classes\SystemFileAssociations\.sbox\shell'
$actions = @(
    @{ Key = "$verbs\VaultLab.mount"; Label = 'Монтировать S-Box'; Arguments = 'mount -- "%1"' }
    @{ Key = "$verbs\VaultLab.unmount"; Label = 'Размонтировать S-Box'; Arguments = 'unmount -- "%1"' }
    @{ Key = 'Software\Classes\Directory\Background\shell\VaultLab.create'; Label = 'Создать контейнер S-Box'; Arguments = 'create --in-folder "%V\."' }
)
$sidebarId = '{7EB19B7D-2E41-4BD4-BFEB-7D78E432FE2C}'
$sidebarClass = "Software\Classes\CLSID\$sidebarId"
$explorerKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer'
$namespaceKey = "$explorerKey\Desktop\NameSpace\$sidebarId"
$desktopIcons = "$explorerKey\HideDesktopIcons\NewStartPanel"
$hkcu = [Microsoft.Win32.RegistryKey]::OpenBaseKey('CurrentUser', 'Registry64')

function Set-SidebarValue($path, $name, $value, [Microsoft.Win32.RegistryValueKind] $kind) {
    $key = $hkcu.CreateSubKey($path)
    try { $key.SetValue($name, $value, $kind) } finally { $key.Dispose() }
}

if ($Uninstall) {
    $hkcu.DeleteSubKeyTree($namespaceKey, $false)
    $hkcu.DeleteSubKeyTree($sidebarClass, $false)
    $key = $hkcu.OpenSubKey($desktopIcons, $true)
    if ($key) { try { $key.DeleteValue($sidebarId, $false) } finally { $key.Dispose() } }
    foreach ($action in $actions) {
        $hkcu.DeleteSubKeyTree($action.Key, $false)
    }
} else {
    # Keep paths to the deployed binaries. The DLL may have vendor dependencies alongside it.
    $exe = (Get-Item -LiteralPath $Executable).FullName
    $dll = (Get-Item -LiteralPath $Plugin).FullName
    if (![IO.File]::Exists($exe) -or [IO.Path]::GetExtension($exe) -ine '.exe' -or
        ![IO.File]::Exists($dll) -or [IO.Path]::GetExtension($dll) -ine '.dll') {
        throw 'Укажите vault-lab.exe и криптоплагин Windows (.dll).'
    }
    $help = & $exe --help
    if ($LASTEXITCODE -ne 0 -or ($help -join "`n") -notmatch 'S-Box Cloud Files provider' -or ($help -join "`n") -notmatch '(?m)^\s+create\s') {
        throw 'Нужна сборка vault-lab.exe с поддержкой CFAPI.'
    }
    $version = & $exe --version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '\s(\d+\.\d+\.\d+)$' -or [version]$Matches[1] -lt [version]'0.1.2') {
        throw 'Для левой панели Проводника нужна версия Vault Lab 0.1.2 или новее.'
    }
    [void][IO.Directory]::CreateDirectory((Join-Path $env:LOCALAPPDATA 'VaultLab\Containers'))
    Set-SidebarValue $sidebarClass '' 'S-Box' String
    Set-SidebarValue $sidebarClass 'System.IsPinnedToNameSpaceTree' 1 DWord
    Set-SidebarValue $sidebarClass 'SortOrderIndex' 66 DWord
    Set-SidebarValue "$sidebarClass\DefaultIcon" '' '%SystemRoot%\System32\imageres.dll,-1043' ExpandString
    Set-SidebarValue "$sidebarClass\InProcServer32" '' '%SystemRoot%\System32\shell32.dll' ExpandString
    Set-SidebarValue "$sidebarClass\Instance" 'CLSID' '{0E5AAE11-A475-4C5B-AB00-C66DE400274E}' String
    Set-SidebarValue "$sidebarClass\Instance\InitPropertyBag" 'Attributes' 17 DWord
    Set-SidebarValue "$sidebarClass\Instance\InitPropertyBag" 'TargetFolderPath' '%LOCALAPPDATA%\VaultLab\Containers' ExpandString
    Set-SidebarValue "$sidebarClass\ShellFolder" 'FolderValueFlags' 40 DWord
    Set-SidebarValue "$sidebarClass\ShellFolder" 'Attributes' 0xF080004D DWord
    Set-SidebarValue $desktopIcons $sidebarId 1 DWord
    Set-SidebarValue $namespaceKey '' 'S-Box' String
    foreach ($action in $actions) {
        $key = $hkcu.CreateSubKey($action.Key)
        try {
            $key.SetValue('MUIVerb', $action.Label)
            $key.SetValue('MultiSelectModel', 'Single')
            $key.SetValue('Icon', ('"{0}",0' -f $exe))
            $cmd = $key.CreateSubKey('command')
            try {
                $cmd.SetValue('', ('"{0}" --explorer --plugin "{1}" {2}' -f $exe, $dll, $action.Arguments))
            } finally { $cmd.Dispose() }
        } finally { $key.Dispose() }
    }
}
if (-not ('VaultLab.Shell' -as [type])) {
    Add-Type -Namespace VaultLab -Name Shell -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("shell32.dll")]
public static extern void SHChangeNotify(uint eventId, uint flags, System.IntPtr item1, System.IntPtr item2);
'@
}
[VaultLab.Shell]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
