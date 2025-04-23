## To check public/private setting
Get-NetConnectionProfile | Where-Object "InterfaceAlias" -like "Zero*"

## To set all ZeroTier networks to Private
Get-NetConnectionProfile | Where-Object "InterfaceAlias" -like "Zero*" | Set-NetConnectionProfile -NetworkCategory Private

## To check public/private setting
Get-NetConnectionProfile | Where-Object "InterfaceAlias" -like "Zero*"