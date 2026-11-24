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
$actions = [ordered]@{ mount = 'Монтировать S-Box'; unmount = 'Размонтировать S-Box' }
$hkcu = [Microsoft.Win32.Registry]::CurrentUser

if ($Uninstall) {
    foreach ($action in $actions.Keys) {
        $hkcu.DeleteSubKeyTree("$verbs\VaultLab.$action", $false)
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
    if ($LASTEXITCODE -ne 0 -or ($help -join "`n") -notmatch 'S-Box Cloud Files provider') {
        throw 'Нужна сборка vault-lab.exe с поддержкой CFAPI.'
    }
    foreach ($action in $actions.Keys) {
        $key = $hkcu.CreateSubKey("$verbs\VaultLab.$action")
        try {
            $key.SetValue('MUIVerb', $actions[$action])
            $key.SetValue('MultiSelectModel', 'Single')
            $key.SetValue('Icon', ('"{0}",0' -f $exe))
            $cmd = $key.CreateSubKey('command')
            try {
                $cmd.SetValue('', ('"{0}" --explorer --plugin "{1}" {2} -- "%1"' -f $exe, $dll, $action))
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
