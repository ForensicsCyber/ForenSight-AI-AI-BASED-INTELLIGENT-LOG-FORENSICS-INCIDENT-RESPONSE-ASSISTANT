#define MyAppName "ForenSight AI"
#define MyAppVersion "1.0"
#define MyAppPublisher "VulneraScope"
#define MyAppExeName "ForenSightAI.exe"

[Setup]
AppId={{BCC7A743-04F8-4552-AA9A-1A363ED4E936}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequired=admin
OutputDir=C:\Users\vishu\Downloads\ForenSight AI\installer
OutputBaseFilename=ForenSightAI_Setup
SetupIconFile=C:\Users\vishu\Downloads\ForenSight AI\assets\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "C:\Users\vishu\Downloads\ForenSight AI\dist\ForenSightAI\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent