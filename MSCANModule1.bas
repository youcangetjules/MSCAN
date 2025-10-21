Attribute VB_Name = "MSCANModule1"
'===============================================================================
' Module1
' Core processing logic for geolocation footer
'===============================================================================

Option Explicit

'===============================================================================
' CONFIGURATION
'===============================================================================
Private Const PYTHON_EXE As String = "C:\Python313\python.exe"
Private Const PYTHON_SCRIPT As String = "C:\CursorAI\geolocate_headers.py"
'===============================================================================


'===============================================================================
' Returns a writable base directory. Forces the path to C:\GeoFooter.
'===============================================================================
Private Function GetBaseDir() As String
    Const FORCED_BASE_PATH As String = "C:\GeoFooter"

    If EnsureFolderExists(FORCED_BASE_PATH) Then
        GetBaseDir = FORCED_BASE_PATH
    Else
        MsgBox "CRITICAL LOGGING ERROR:" & vbCrLf & vbCrLf & _
               "Could not create or access the required directory: " & vbCrLf & FORCED_BASE_PATH & vbCrLf & vbCrLf & _
               "Please create this folder manually and ensure you have write permissions.", _
               vbCritical, "GeoFooter Add-in Error"
        GetBaseDir = ""
    End If
End Function


'===============================================================================
' Logging
'===============================================================================
Public Sub WriteLog(msg As String)
    On Error Resume Next

    Dim baseDir As String: baseDir = GetBaseDir()
    If Len(baseDir) = 0 Then Exit Sub

    Dim logFolder As String: logFolder = baseDir & "\Logs"
    Call EnsureFolderExists(logFolder)

    Dim logFile As String: logFile = logFolder & "\VBA_Log.txt"
    Dim fso As Object, ts As Object

    Set fso = CreateObject("Scripting.FileSystemObject")
    Set ts = fso.OpenTextFile(logFile, 8, True)
    ts.WriteLine Format$(Now, "yyyy-mm-dd hh:nn:ss") & " - " & msg
    ts.Close

    Debug.Print "LOG: " & msg
End Sub


'===============================================================================
' Main entry point
'===============================================================================
Public Sub ProcessEmailSecurity(mail As Outlook.MailItem)
    On Error GoTo ErrHandler

    WriteLog "ProcessEmailSecurity: Starting process for subject=" & SafeSubject(mail)

    Dim headers As String
    headers = GetInternetHeaders(mail)
    If Len(headers) = 0 Then
        WriteLog "ProcessEmailSecurity: No headers found. Skipping footer insertion."
        Exit Sub
    End If

    Dim headerFile As String
    headerFile = GetBaseDir() & "\headers\headers_" & _
                 Format$(Now, "yyyymmdd_hhnnss_") & _
                 CStr(Fix(Timer * 1000) Mod 1000) & ".txt"

    WriteHeadersToFile headers, headerFile

    Dim footerPath As String
    footerPath = RunGeolocationPythonScript(headerFile)
    If Len(footerPath) = 0 Then
        WriteLog "ProcessEmailSecurity: Python script did not produce an output file. Skipping footer insertion."
        Exit Sub
    End If

    InsertFooterIntoMail mail, footerPath
    Exit Sub

ErrHandler:
    WriteLog "ProcessEmailSecurity error: " & Err.Number & " - " & Err.Description
End Sub


'===============================================================================
' Extract Internet headers
'===============================================================================
Public Function GetInternetHeaders(mail As Outlook.MailItem) As String
    On Error GoTo ErrHandler

    Const PR_TRANSPORT_MESSAGE_HEADERS As String = _
        "http://schemas.microsoft.com/mapi/proptag/0x007D001E"

    Dim propAccessor As Outlook.PropertyAccessor
    Set propAccessor = mail.PropertyAccessor

    Dim headers As String
    headers = CStr(propAccessor.GetProperty(PR_TRANSPORT_MESSAGE_HEADERS))

    If Len(headers) = 0 Then
        WriteLog "GetInternetHeaders: No headers found on mail with subject: " & SafeSubject(mail)
    Else
        WriteLog "GetInternetHeaders: Retrieved headers of length " & Len(headers)
    End If

    GetInternetHeaders = headers
    Exit Function

ErrHandler:
    WriteLog "GetInternetHeaders error: " & Err.Number & " - " & Err.Description
    GetInternetHeaders = ""
End Function


'===============================================================================
' Folder utilities
'===============================================================================
Private Function EnsureFolderExists(ByVal folderPath As String) As Boolean
    On Error GoTo EH

    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")

    If Len(folderPath) = 0 Then
        EnsureFolderExists = False
        Exit Function
    End If

    If Not fso.FolderExists(folderPath) Then fso.CreateFolder folderPath
    EnsureFolderExists = True
    Exit Function

EH:
    Debug.Print "EnsureFolderExists error: " & Err.Number & " - " & Err.Description & " (" & folderPath & ")"
    EnsureFolderExists = False
End Function


'===============================================================================
' Write header file
'===============================================================================
Private Sub WriteHeadersToFile(headers As String, filePath As String)
    On Error GoTo ErrHandler

    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")
    Dim parent As String: parent = fso.GetParentFolderName(filePath)

    If Len(parent) > 0 Then Call EnsureFolderExists(parent)
    WriteTextUtf8 filePath, headers
    Exit Sub

ErrHandler:
    WriteLog "WriteHeadersToFile error: " & Err.Number & " - " & Err.Description
End Sub


'===============================================================================
' Run Python script and return footer path
'===============================================================================
Private Function RunGeolocationPythonScript(headerFilePath As String) As String
    On Error GoTo ErrHandler

    Dim baseDir As String: baseDir = GetBaseDir()
    Dim outputFolder As String: outputFolder = baseDir & "\output"
    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")

    Call EnsureFolderExists(outputFolder)

    ' Check Python executable
    If Not fso.FileExists(PYTHON_EXE) Then
        WriteLog "RunGeolocationPythonScript: Python executable not found at " & PYTHON_EXE
        RunGeolocationPythonScript = ""
        Exit Function
    End If

    ' Check Python script
    If Not fso.FileExists(PYTHON_SCRIPT) Then
        WriteLog "RunGeolocationPythonScript: Python script not found at " & PYTHON_SCRIPT
        RunGeolocationPythonScript = ""
        Exit Function
    End If

    Dim uniqueFooterPath As String
    uniqueFooterPath = outputFolder & "\footer_" & _
                       Format$(Now, "yyyymmdd_hhnnss_") & _
                       CStr(Fix(Timer * 1000) Mod 1000) & ".html"

    Dim sh As Object, cmd As String, rc As Long
    Set sh = CreateObject("WScript.Shell")

    Dim pythonErrLog As String
    pythonErrLog = outputFolder & "\python_error.log"

    cmd = """" & PYTHON_EXE & """ """ & PYTHON_SCRIPT & """ """ & headerFilePath & """ 2> """ & pythonErrLog & """"
    WriteLog "Running Python command: " & cmd

    rc = sh.Run(cmd, 0, True)
    WriteLog "Python script finished with exit code: " & CStr(rc)

    If rc <> 0 Then
        WriteLog "RunGeolocationPythonScript: Python failed. See " & pythonErrLog & " for details."
        RunGeolocationPythonScript = ""
        Exit Function
    End If

    Dim masterReportPath As String
    masterReportPath = outputFolder & "\output_report.html"

    If Not fso.FileExists(masterReportPath) Then
        WriteLog "RunGeolocationPythonScript: Expected master output file not found: " & masterReportPath
        RunGeolocationPythonScript = ""
        Exit Function
    End If

    fso.CopyFile masterReportPath, uniqueFooterPath, True
    WriteLog "Footer successfully created and copied to: " & uniqueFooterPath

    RunGeolocationPythonScript = uniqueFooterPath
    Exit Function

ErrHandler:
    WriteLog "RunGeolocationPythonScript error: " & Err.Number & " - " & Err.Description
    RunGeolocationPythonScript = ""
End Function


'===============================================================================
' Insert generated footer into email
'===============================================================================
Private Sub InsertFooterIntoMail(mail As Outlook.MailItem, footerPath As String)
    On Error GoTo ErrHandler

    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")

    If Not fso.FileExists(footerPath) Then
        WriteLog "InsertFooterIntoMail: Footer file not found: " & footerPath
        Exit Sub
    End If

    Dim footerHtml As String: footerHtml = ReadTextUtf8(footerPath)
    If Len(footerHtml) = 0 Then
        WriteLog "InsertFooterIntoMail: Footer file is empty or could not be read: " & footerPath
        Exit Sub
    End If

    If mail.BodyFormat <> olFormatHTML Then mail.BodyFormat = olFormatHTML

    Dim bodyHtml As String, pos As Long
    bodyHtml = mail.HTMLBody
    pos = InStrRev(LCase$(bodyHtml), "</body>")

    If pos > 0 Then
        mail.HTMLBody = left$(bodyHtml, pos - 1) & footerHtml & Mid$(bodyHtml, pos)
    Else
        mail.HTMLBody = bodyHtml & "<hr>" & footerHtml
    End If

    mail.Save
    WriteLog "Footer inserted successfully into email with subject: " & SafeSubject(mail)
    Exit Sub

ErrHandler:
    WriteLog "InsertFooterIntoMail error: " & Err.Number & " - " & Err.Description
End Sub


'===============================================================================
' Helpers
'===============================================================================
Private Function SafeSubject(mail As Outlook.MailItem) As String
    On Error Resume Next
    SafeSubject = mail.Subject
    If Err.Number <> 0 Then SafeSubject = "[No Subject]"
End Function


'===============================================================================
' UTF-8 Read/Write Utilities
'===============================================================================
Private Function SupportsADODBStream() As Boolean
    On Error Resume Next
    Dim o As Object: Set o = CreateObject("ADODB.Stream")
    SupportsADODBStream = Not (o Is Nothing)
End Function


Private Sub WriteTextUtf8(ByVal filePath As String, ByVal content As String)
    If SupportsADODBStream() Then
        WriteTextUtf8_ADO filePath, content
    Else
        WriteLog "ADODB.Stream not found. Falling back to PowerShell for UTF-8 writing."
        WriteTextUtf8_PS filePath, content
    End If
End Sub


Private Function ReadTextUtf8(ByVal filePath As String) As String
    If SupportsADODBStream() Then
        ReadTextUtf8 = ReadTextUtf8_ADO(filePath)
    Else
        WriteLog "ADODB.Stream not found. Falling back to PowerShell for UTF-8 reading."
        ReadTextUtf8 = ReadTextUtf8_PS(filePath)
    End If
End Function


Private Sub WriteTextUtf8_ADO(ByVal filePath As String, ByVal content As String)
    On Error GoTo EH
    Dim stm As Object: Set stm = CreateObject("ADODB.Stream")
    stm.Type = 2
    stm.Charset = "utf-8"
    stm.Open
    stm.WriteText content
    stm.SaveToFile filePath, 2
    stm.Close
    Exit Sub
EH:
    WriteLog "WriteTextUtf8_ADO error: " & Err.Number & " - " & Err.Description
End Sub


Private Function ReadTextUtf8_ADO(ByVal filePath As String) As String
    On Error GoTo EH
    Dim stm As Object: Set stm = CreateObject("ADODB.Stream")
    stm.Type = 2
    stm.Charset = "utf-8"
    stm.Open
    stm.LoadFromFile filePath
    ReadTextUtf8_ADO = stm.ReadText(-1)
    stm.Close
    Exit Function
EH:
    WriteLog "ReadTextUtf8_ADO error: " & Err.Number & " - " & Err.Description
    ReadTextUtf8_ADO = ""
End Function


'===============================================================================
' PowerShell Fallbacks
'===============================================================================
Private Function PS_Quote(ByVal s As String) As String
    PS_Quote = "'" & Replace(s, "'", "''") & "'"
End Function


Private Function RunPS(ByVal command As String) As Boolean
    On Error GoTo EH
    Dim sh As Object: Set sh = CreateObject("WScript.Shell")
    Dim exe As String: exe = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
    Dim rc As Long: rc = sh.Run(exe & command, 0, True)
    RunPS = (rc = 0)
    If Not RunPS Then WriteLog "RunPS failed with exit code " & CStr(rc) & " for command: " & command
    Exit Function
EH:
    WriteLog "RunPS error: " & Err.Number & " - " & Err.Description
    RunPS = False
End Function


Private Sub WriteTextUtf8_PS(ByVal filePath As String, ByVal content As String)
    Dim psCmd As String
    psCmd = "$content = " & PS_Quote(content) & "; $content | Out-File -LiteralPath " & _
             PS_Quote(filePath) & " -Encoding utf8 -NoNewline"
    If Not RunPS(psCmd) Then WriteLog "WriteTextUtf8_PS failed for: " & filePath
End Sub


Private Function ReadTextUtf8_PS(ByVal filePath As String) As String
    On Error GoTo EH
    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")
    If Not fso.FileExists(filePath) Then Exit Function

    Dim tempFile As String: tempFile = fso.GetSpecialFolder(2) & "\" & fso.GetTempName
    Dim psCmd As String
    psCmd = "Get-Content -LiteralPath " & PS_Quote(filePath) & _
            " -Raw -Encoding utf8 | Out-File -LiteralPath " & PS_Quote(tempFile)

    If RunPS(psCmd) Then
        ReadTextUtf8_PS = fso.OpenTextFile(tempFile, 1).ReadAll
        fso.DeleteFile tempFile
    Else
        WriteLog "ReadTextUtf8_PS transcode failed for: " & filePath
    End If
    Exit Function

EH:
    WriteLog "ReadTextUtf8_PS error: " & Err.Number & " - " & Err.Description
    ReadTextUtf8_PS = ""
End Function


