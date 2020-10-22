$clear = Read-Host -Prompt 'Clear Chrome Cache [Y,n] ?'

if ($clear -ne "n" -and $clear -ne "no") {
    Write-Host "Clear Cache ..."
    Remove-Item -LiteralPath "C:/temp/chrome/" -Force -Recurse -ErrorAction SilentlyContinue
}
else{
    Write-Host "no clear"
}

Start-Process -FilePath chrome.exe -ArgumentList "--disable-web-security --disable-xss-auditor --ignore-certificate-errors --user-data-dir=C:/temp/chrome/ --proxy-server=127.0.0.1:8080"
