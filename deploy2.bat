@echo off
cd /d "C:\Users\admin\Pictures\Screenshots\Downloads\-learningbm"
echo === Deploy Log === > deploy_log.txt
echo %date% %time% >> deploy_log.txt
echo. >> deploy_log.txt

echo --- git pull --- >> deploy_log.txt
git pull >> deploy_log.txt 2>&1
echo. >> deploy_log.txt

echo --- git apply --- >> deploy_log.txt
git apply --ignore-whitespace changes.patch.txt >> deploy_log.txt 2>&1
if %errorlevel% neq 0 (
    echo --- trying 3way --- >> deploy_log.txt
    git apply --ignore-whitespace --3way changes.patch.txt >> deploy_log.txt 2>&1
)
echo. >> deploy_log.txt

echo --- git add --- >> deploy_log.txt
git add -A >> deploy_log.txt 2>&1
echo. >> deploy_log.txt

echo --- git status --- >> deploy_log.txt
git status >> deploy_log.txt 2>&1
echo. >> deploy_log.txt

echo --- git commit --- >> deploy_log.txt
git commit -m "feat: review rewards, battle fix, weekly tests" >> deploy_log.txt 2>&1
echo. >> deploy_log.txt

echo --- git push --- >> deploy_log.txt
git push >> deploy_log.txt 2>&1
echo. >> deploy_log.txt

echo === Done === >> deploy_log.txt
