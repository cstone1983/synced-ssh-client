; Inno Setup script for the Windows build.
; Build the app first (flutter build windows --release), then:
;   iscc /DAppVersion=0.1.0 app\installer\sshsync.iss
; CI passes the version (the windows-v tag, or pubspec's version).
; The app's built-in updater runs this installer with /SILENT /UPDATE=1: it
; upgrades the existing install in place and starts the app again.
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{6B1D0C55-6E0F-4E0B-9C1A-5F3C7A2B91D4}
AppName=SSH Sync
AppVersion={#AppVersion}
AppPublisher=Personal build
DefaultDirName={autopf}\SSH Sync
DefaultGroupName=SSH Sync
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\build\installer
OutputBaseFilename=sshsync-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
UninstallDisplayName=SSH Sync

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\SSH Sync"; Filename: "{app}\sshsync.exe"
Name: "{autodesktop}\SSH Sync"; Filename: "{app}\sshsync.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\sshsync.exe"; Description: "Start SSH Sync"; Flags: nowait postinstall skipifsilent
Filename: "{app}\sshsync.exe"; Flags: nowait runasoriginaluser; Check: IsAppUpdate

[Code]
function IsAppUpdate: Boolean;
begin
  Result := WizardSilent and (ExpandConstant('{param:UPDATE|0}') = '1');
end;
