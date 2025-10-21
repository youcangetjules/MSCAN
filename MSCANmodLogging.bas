Attribute VB_Name = "MSCANmodLogging"
Option Explicit

Private mPath As String

Public Function logPath() As String
    If Len(mPath) = 0 Then
        Dim base As String
        base = Environ$("LOCALAPPDATA")
        If Len(base) = 0 Then base = Environ$("TEMP")
        If Len(base) = 0 Then base = "C:\"
        Dim folder As String
        folder = base & "\GeoFooter\Logs"
        EnsureFolderSimple base & "\GeoFooter"
        EnsureFolderSimple folder
        mPath = folder & "\VBA_Log.txt"
    End If
    logPath = mPath
End Function

Public Sub WriteLog(ByVal msg As String)
    On Error GoTo EH
    Dim f As Integer: f = FreeFile
    Open logPath For Append As #f
    Print #f, Format$(Now, "yyyy-mm-dd HH:nn:ss"); " | "; msg
    Close #f
    Exit Sub
EH:
    Debug.Print "WriteLog failed: " & Err.Number & " - " & Err.Description
End Sub

Private Sub EnsureFolderSimple(ByVal p As String)
    On Error Resume Next
    If Len(Dir$(p, vbDirectory)) = 0 Then MkDir p
End Sub

Public Sub OpenLog()
    Shell "notepad.exe " & Chr$(34) & logPath & Chr$(34), vbNormalFocus
End Sub

Public Sub Test_Logging()
    WriteLog "Diagnostics: Test_Logging start"
    WriteLog "Diagnostics: Test_Logging done"
    OpenLog
End Sub
