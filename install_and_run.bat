@echo off
title DPI Engine - Setup & Run
color 0A
cls

echo ============================================
echo    DPI ENGINE - Java Deep Packet Inspector
echo    Auto Setup Script
echo ============================================
echo.

:: ── Check Java ──────────────────────────────
echo [1/3] Checking Java...
java -version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo  ERROR: Java is NOT installed!
    echo.
    echo  Please install Java 17 from:
    echo  https://adoptium.net/temurin/releases/?version=17
    echo.
    echo  Download: Windows x64 .msi installer
    echo  Install karo, phir yeh file dobara chalao.
    echo.
    pause
    start https://adoptium.net/temurin/releases/?version=17
    exit /b 1
)
echo  Java found!

:: ── Download Maven if not present ────────────
echo [2/3] Checking Maven...
where mvn >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo  Maven found in PATH!
    SET MVN_CMD=mvn
    GOTO BUILD
)

:: Try mvnw.cmd
IF EXIST "%~dp0mvnw.cmd" (
    echo  Using Maven Wrapper (mvnw.cmd)
    SET MVN_CMD="%~dp0mvnw.cmd"
    GOTO BUILD
)

:: Download Maven manually
echo  Maven not found. Downloading Maven 3.9.6...
SET MAVEN_ZIP=%TEMP%\apache-maven-3.9.6-bin.zip
SET MAVEN_DIR=%USERPROFILE%\.dpi-maven\apache-maven-3.9.6

IF NOT EXIST "%MAVEN_DIR%\bin\mvn.cmd" (
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip' -OutFile '%MAVEN_ZIP%'}"
    powershell -Command "Expand-Archive -LiteralPath '%MAVEN_ZIP%' -DestinationPath '%USERPROFILE%\.dpi-maven' -Force"
    echo  Maven downloaded!
) ELSE (
    echo  Maven already cached!
)
SET MVN_CMD="%MAVEN_DIR%\bin\mvn.cmd"

:BUILD
:: ── Build ────────────────────────────────────
echo [3/3] Building project (first time may take 2-3 mins)...
echo.
cd /d "%~dp0"
%MVN_CMD% clean package -DskipTests -q
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo  BUILD FAILED! Check errors above.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   BUILD SUCCESSFUL!
echo   Starting DPI Engine on port 8080...
echo ============================================
echo.
echo   Browser mein kholo:  http://localhost:8080
echo   Rokne ke liye:       Ctrl+C
echo.

:: ── Run ─────────────────────────────────────
%MVN_CMD% spring-boot:run
pause
