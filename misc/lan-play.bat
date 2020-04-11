@echo off
title LAN Play Launcher - https://lesking72.github.io/lan-play.html
color 1f

if not exist "lan-play-win64.exe" (
	if not exist "lan-play-win32.exe" (
		echo.
		echo +--------------------------------------------------+
		echo ^|It looks like you don't have the lan-play client. ^|
		echo ^|This launcher requires lan-play-winXX.exe to be in^|
		echo ^|the same folder as the batch file.                ^|
		echo +--------------------------------------------------+
		pause >nul
		exit
	)
)

if not exist "C:\Program Files\WinPcap\rpcapd.exe" (
	if not exist "C:\Program Files (x86)\WinPcap\rpcapd.exe" (
		echo.
		echo +-----------------------------------------------+
		echo ^|It looks like you don't have WinPcap installed.^|
		echo ^|This program will not work without WinPcap.    ^|
		echo +-----------------------------------------------+
		pause >nul
		exit
	)
)
echo.
echo Address                                    Location        Server Type
echo -----------------------------------------------------------------------
echo 1.  switch.lan-play.com:11451              France          Rust
echo 2.  lanplay.reboot.ms:11451                Netherlands     NodeJS
echo 3.  frog-skins.com:11451                   United States   Rust
echo 4.  lanplay2.reboot.ms                     United Kingdom  Rust
echo 5.  switch-la.nplay.asia:11451             Vietnam         NodeJS
echo 6.  lanplay.r3n3.at:11451                  Austria         Rust
echo 7.  bluehouse.servepics.com:11451          Mexico          Rust
echo 8.  nxlan-w.dentora.ca:11451               United States   Rust
echo 9.  open.t0g3pii.tk:11451                  Germany         Rust
echo 10. nut.r3n3.at:11451                      Austria         Rust
echo 11. aclanplay.servegame.org:11451          United States   Rust
echo 12. switch.0mn1b0x.com:11451               Australia       Rust
echo 13. switch.0mn1b0x.com:11453               Australia       NodeJS
echo 14. switch.jayseateam.nl:11451             Netherlands     Rust
echo 15. switch.jayseateam.nl:11453             Netherlands     NodeJS
echo 16. chasehall.net:11451                    United States   Rust
echo 17. joinsg.net:11451                       United States   NodeJS
echo 18. joinsg.net:11453                       United States   Rust
echo.
echo 0. Custom...
echo.
:1
set /p c="Select a server: "

if %c%==1 set s="switch.lan-play.com:11451" && goto 2
if %c%==2 set s="lanplay.reboot.ms:11451" && goto 2
if %c%==3 set s="frog-skins.com:11451" && goto 2
if %c%==4 set s="lanplay2.reboot.ms" && goto 2
if %c%==5 set s="switch-la.nplay.asia:11451" && goto 2
if %c%==6 set s="lanplay.r3n3.at:11451" && goto 2
if %c%==7 set s="bluehouse.servepics.com:11451" && goto 2
if %c%==8 set s="nxlan-w.dentora.ca:11451" && goto 2
if %c%==9 set s="open.t0g3pii.tk:11451" && goto 2
if %c%==10 set s="nut.r3n3.at:11451" && goto 2
if %c%==11 set s="aclanplay.servegame.org:11451" && goto 2
if %c%==12 set s="switch.0mn1b0x.com:11451" && goto 2
if %c%==13 set s="switch.0mn1b0x.com:11453" && goto 2
if %c%==14 set s="switch.jayseateam.nl:11451" && goto 2
if %c%==15 set s="switch.jayseateam.nl:11453" && goto 2
if %c%==16 set s="chasehall.net:11451" && goto 2
if %c%==17 set s="joinsg.net:11451" && goto 2
if %c%==18 set s="joinsg.net:11453" && goto 2


if %c%==0 set /p s="Address: " && goto 2

echo Please make a valid selection from the list.
echo.
goto 1

:2
cls
title LAN Play - %s%
if exist "lan-play-win64.exe" (
	lan-play-win64.exe --relay-server-addr %s% --pmtu 500 >nul
)
else (
	lan-play-win32.exe --relay-server-addr %s% --pmtu 500 >nul
)
echo.
echo Disconnected. Press any key to exit.
pause >nul