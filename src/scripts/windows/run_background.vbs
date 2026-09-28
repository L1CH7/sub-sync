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

' Prefer pythonw from .venv for true silent execution without cmd wrapper
pythonwExe = repoDir & "\.venv\Scripts\pythonw.exe"
If fso.FileExists(pythonwExe) Then
    cmd = """" & pythonwExe & """ main.py proxy"
Else
    userProfile = WshShell.ExpandEnvironmentStrings("%USERPROFILE%")
    localBin = userProfile & "\.local\bin"
    currentPath = WshShell.Environment("PROCESS")("PATH")
    WshShell.Environment("PROCESS")("PATH") = localBin & ";" & currentPath
    cmd = "cmd /c uv run main.py proxy"
End If

WshShell.Run cmd, 0, False
