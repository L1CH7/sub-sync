Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
repoDir = fso.GetParentFolderName(fso.GetParentFolderName(fso.GetParentFolderName(scriptDir)))

If Not fso.FileExists(repoDir & "\main.py") Then
    If fso.FileExists(WshShell.CurrentDirectory & "\main.py") Then
        repoDir = WshShell.CurrentDirectory
    End If
End If

WshShell.CurrentDirectory = repoDir

' Ensure user local bin is in PATH for uv
userProfile = WshShell.ExpandEnvironmentStrings("%USERPROFILE%")
localBin = userProfile & "\.local\bin"
currentPath = WshShell.Environment("PROCESS")("PATH")
WshShell.Environment("PROCESS")("PATH") = localBin & ";" & currentPath

cmd = "cmd /c uv run main.py proxy"
WshShell.Run cmd, 0, False
