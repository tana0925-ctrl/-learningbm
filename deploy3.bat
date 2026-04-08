@echo off
cd /d "C:\Users\admin\Pictures\Screenshots\Downloads\-learningbm"
certutil -decode feature.b64 feature.patch >C:\Users\admin\Desktop\deploy3.txt 2>&1
git apply --ignore-whitespace feature.patch >>C:\Users\admin\Desktop\deploy3.txt 2>&1
git add -A >>C:\Users\admin\Desktop\deploy3.txt 2>&1
git commit -m "feat: review rewards, battle fix, weekly tests" >>C:\Users\admin\Desktop\deploy3.txt 2>&1
git push >>C:\Users\admin\Desktop\deploy3.txt 2>&1
echo DONE >>C:\Users\admin\Desktop\deploy3.txt