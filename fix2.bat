@echo off
cd /d "C:\Users\admin\Pictures\Screenshots\Downloads\-learningbm"
git checkout c30653b -- src/index.tsx >C:\Users\admin\Desktop\r2.txt 2>&1
git add src/index.tsx >>C:\Users\admin\Desktop\r2.txt 2>&1
git commit -m "fix: restore working teacher dashboard" >>C:\Users\admin\Desktop\r2.txt 2>&1
git push >>C:\Users\admin\Desktop\r2.txt 2>&1
echo DONE >>C:\Users\admin\Desktop\r2.txt