# Optional (DMN-1): start age-agent at logon instead of on first use.
# The plugin already starts the daemon on demand; this only saves the first startup.
#
#   powershell -ExecutionPolicy Bypass -File contrib\install-logon-task.ps1
#   Unregister-ScheduledTask -TaskName age-agent      # to remove it
#
# `age-agent daemon` starts the detached daemon (no console window) and exits, so the
# console it runs in only shows for a moment at logon.

$exe = (Get-Command age-agent.exe -ErrorAction Stop).Source
$action = New-ScheduledTaskAction -Execute $exe -Argument 'daemon'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName 'age-agent' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Write-Host "Registered logon task 'age-agent' for $exe"
