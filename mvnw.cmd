@REM ----------------------------------------------------------------------------
@REM Maven Wrapper startup batch script
@REM ----------------------------------------------------------------------------
@IF "%__MVNW_ARG0_NAME__%"=="" (SET __MVNW_ARG0_NAME__=%~nx0)
@SET DP0=%~dp0
@SET MAVEN_PROJECTBASEDIR=%DP0%

@SET DOWNLOAD_URL=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip
@SET MAVEN_HOME=%USERPROFILE%\.m2\wrapper\dists\apache-maven-3.9.6

IF EXIST "%MAVEN_HOME%\bin\mvn.cmd" GOTO run

ECHO Downloading Maven 3.9.6...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url='%DOWNLOAD_URL%'; $out='%USERPROFILE%\.m2\wrapper\apache-maven-3.9.6-bin.zip'; New-Item -ItemType Directory -Force -Path '%USERPROFILE%\.m2\wrapper\dists' | Out-Null; Invoke-WebRequest -Uri $url -OutFile $out; Expand-Archive -LiteralPath $out -DestinationPath '%USERPROFILE%\.m2\wrapper\dists' -Force; Rename-Item -Path '%USERPROFILE%\.m2\wrapper\dists\apache-maven-3.9.6' -NewName 'apache-maven-3.9.6' -ErrorAction SilentlyContinue}"

:run
"%MAVEN_HOME%\bin\mvn.cmd" %*
