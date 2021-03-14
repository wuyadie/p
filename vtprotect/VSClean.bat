@echo Off
del /s /a *.ilk *.sdf *.ipch *.suo *.ncb *.user *.filters *.pdb *.pch *.obj *.netmodule *.aps  2>nul

FOR /R . %%d IN (.) DO rd /s /q "%%d\DeBug" 2>nul
FOR /R . %%d IN (.) DO rd /s /q "%%d\ipch" 2>nul
FOR /R . %%d IN (.) DO rd /s /q "%%d\Release" 2>nul

