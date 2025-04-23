#Import into RDCMan
$Path = "C:\Users\Spork\OneDrive\Documents\Remote RDP VNC"
$Text = "full address:s:"
$PathArray = @()
$File = ""
$String = ""
$FinalString = ""

Get-ChildItem $Path -Filter "*.rdp" |
    Where-Object { $_.Attributes -ne "Directory"} |
    ForEach-Object {
        If (Get-Content $_.FullName | Select-String -Pattern $Text) {
            $File = $PathArray += $_.FullName
            $String = Get-Content $File | Where-Object { $_.Contains($Text) }
            $FinalString = $String.substring(15)
    }
}
$FinalString | % {$_} | Out-File "IPs.txt"