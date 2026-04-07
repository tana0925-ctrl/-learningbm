$env:PATH = [System.Environment]::GetEnvironmentVariable('PATH', 'User') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
Set-Location 'C:\Users\admin\Pictures\Screenshots\Downloads\-learningbm'
npm run deploy 2>&1
