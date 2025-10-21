Attribute VB_Name = "MSCANDiagnostics"
Option Explicit

' Public test macros (run via Alt+F8)
Public Sub Test_Logging()
    MSCANmodLogging.WriteLog "Diagnostics: Test_Logging start"
    MSCANmodLogging.WriteLog "Diagnostics: Test_Logging done"
    MSCANmodLogging.OpenLog
End Sub

Public Sub Test_Dialog()
    On Error GoTo EH
    Dim frm As Object
    Set frm = New MSCANSecurityRatingForm

    Dim hasCmb As Boolean, hasOk As Boolean, hasCancel As Boolean
    Dim i As Long
    For i = 0 To frm.Controls.Count - 1
        Select Case LCase$(frm.Controls(i).Name)
            Case "cmbrating": hasCmb = True
            Case "cmdok":     hasOk = True
            Case "cmdcancel": hasCancel = True
        End Select
    Next i

    If Not hasCmb Or Not hasOk Or Not hasCancel Then
        MsgBox "MSCANSecurityRatingForm is missing required controls:" & vbCrLf & _
               "cmbRating=" & hasCmb & ", cmdOK=" & hasOk & ", cmdCancel=" & hasCancel, _
               vbExclamation, "Test_Dialog"
        Unload frm
        Exit Sub
    End If

    Dim r As String
    r = MSCANModule2.ShowSecurityRatingDialog("Diagnostics: classification dialog test")
    If Len(Trim$(r)) = 0 Then
        MsgBox "Dialog shown: you cancelled or didn't select a classification.", vbInformation, "Test_Dialog"
    Else
        MsgBox "Dialog OK. You selected: " & r, vbInformation, "Test_Dialog"
    End If
    Exit Sub
EH:
    MsgBox "Test_Dialog error: " & Err.Number & " - " & Err.Description, vbCritical
End Sub

Public Sub Test_UTF8()
    On Error GoTo EH

    Dim base As String
    Dim testFolder As String
    Dim testFile As String
    Dim content As String
    Dim back As String

    base = GetBase_DX()
    EnsureFolder_DX base
    testFolder = base & "\diag"
    EnsureFolder_DX testFolder

    testFile = testFolder & "\utf8_test.txt"
    content = "UTF-8 test -- " & Format$(Now, "yyyy-mm-dd HH:nn:ss")

    If Not WriteUtf8_PS_DX(testFile, content) Then
        MsgBox "Write failed at: " & testFile, vbExclamation, "Test_UTF8"
        Exit Sub
    End If

    back = ReadUtf8_PS_DX(testFile)
    If back = content Then
        MsgBox "UTF-8 I/O OK: " & testFile, vbInformation, "Test_UTF8"
    Else
        MsgBox "UTF-8 I/O mismatch." & vbCrLf & _
               "Expected: " & content & vbCrLf & _
               "Got:      " & back, vbExclamation, "Test_UTF8"
    End If
    Exit Sub
EH:
    MsgBox "Test_UTF8 error: " & Err.Number & " - " & Err.Description, vbCritical, "Test_UTF8"
End Sub

Public Sub Test_Python()
    On Error GoTo EH
    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")

    ' Update these paths if needed
    Dim py As String: py = "C:\Users\julia\AppData\Local\Programs\Python\Python313\python.exe"
    Dim script As String: script = "C:\CursorAI\geolocate_headers.py"

    Dim msg As String
    If fso.FileExists(py) Then
        msg = "Python found: " & py
    Else
        msg = "Python NOT found: " & py
    End If
    If fso.FileExists(script) Then
        msg = msg & vbCrLf & "Script found: " & script
    Else
        msg = msg & vbCrLf & "Script NOT found: " & script
    End If
    MsgBox msg, IIf(InStr(msg, "NOT") > 0, vbExclamation, vbInformation), "Test_Python"
    Exit Sub
EH:
    MsgBox "Test_Python error: " & Err.Number & " - " & Err.Description, vbCritical
End Sub

Public Sub Test_SQLite()
    On Error GoTo EH
    Dim db As String
    db = GuessBaseDir_DX() & "\guri_records.db"
    Dim cs As String: cs = ProbeSQLiteCS_Auto_DX(db)
    If cs <> "" Then
        MsgBox "SQLite ODBC driver detected and connection OK." & vbCrLf & cs, vbInformation, "Test_SQLite"
    Else
        MsgBox "SQLite ODBC driver NOT detected for this Outlook bitness, or connection failed." & vbCrLf & _
               "Run Test_SQLite_Detailed2 (in your other module) for specifics.", vbExclamation, "Test_SQLite"
    End If
    Exit Sub
EH:
    MsgBox "Test_SQLite error: " & Err.Number & " - " & Err.Description, vbCritical
End Sub

Public Sub SQLite_SmokeTest()
    On Error GoTo EH
    Dim db As String: db = GuessBaseDir_DX() & "\guri_records.db"
    Dim cs As String: cs = ProbeSQLiteCS_Auto_DX(db)
    If cs = "" Then
        MsgBox "No working SQLite ODBC connection. Run your detailed test.", vbExclamation
        Exit Sub
    End If

    Dim cn As Object, cmd As Object
    Set cn = CreateObject("ADODB.Connection")
    Set cmd = CreateObject("ADODB.Command")
    cn.Open cs
    Set cmd.ActiveConnection = cn

    cmd.CommandText = "CREATE TABLE IF NOT EXISTS diag_test (id INTEGER PRIMARY KEY, ts TEXT)"
    cmd.Execute

    cmd.CommandText = "INSERT INTO diag_test (ts) VALUES (datetime('now'))"
    cmd.Execute

    Dim rs As Object
    Set rs = cn.Execute("SELECT id, ts FROM diag_test ORDER BY id DESC LIMIT 1")
    If Not rs.EOF Then
        MsgBox "SQLite write/read OK. Last row: id=" & rs.Fields(0).Value & " ts=" & rs.Fields(1).Value, vbInformation
    Else
        MsgBox "SQLite read returned no rows.", vbExclamation
    End If
    rs.Close: cn.Close
    Exit Sub
EH:
    MsgBox "SQLite_SmokeTest error: " & Err.Number & " - " & Err.Description, vbCritical
End Sub

' ----------------- Private helpers (DX-suffixed to avoid name clashes) -----------------

Private Function GetBase_DX() As String
    Dim p As String
    p = Environ$("LOCALAPPDATA") & "\GeoFooter"
    If EnsureFolder_DX(p) Then GetBase_DX = p: Exit Function
    p = "C:\GeoFooter"
    If EnsureFolder_DX(p) Then GetBase_DX = p: Exit Function
    p = Environ$("TEMP") & "\GeoFooter"
    EnsureFolder_DX p
    GetBase_DX = p
End Function

Private Function EnsureFolder_DX(ByVal path As String) As Boolean
    On Error Resume Next
    If Len(path) = 0 Then EnsureFolder_DX = False: Exit Function
    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")
    If Not fso.FolderExists(path) Then fso.CreateFolder path
    EnsureFolder_DX = (Err.Number = 0)
End Function

Private Function WriteUtf8_PS_DX(ByVal filePath As String, ByVal content As String) As Boolean
    On Error GoTo EH
    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")
    Dim tempDir As String: tempDir = Environ$("TEMP")
    If Len(tempDir) = 0 Then tempDir = "C:\Windows\Temp"
    Dim tmp As String: tmp = fso.BuildPath(tempDir, "gf_utf16_" & CStr(Int(Rnd() * 1000000)) & ".txt")

    Dim ts As Object
    Set ts = fso.CreateTextFile(tmp, True, True) ' Unicode (UTF-16)
    ts.Write content
    ts.Close

    Dim ps As String
    ps = "$c = Get-Content -LiteralPath " & PS_Quote_DX(tmp) & " -Raw -Encoding Unicode; " & _
         "Set-Content -LiteralPath " & PS_Quote_DX(filePath) & " -Value $c -Encoding utf8 -NoNewline"
    WriteUtf8_PS_DX = RunPS_DX(ps)

    On Error Resume Next
    If fso.FileExists(tmp) Then fso.DeleteFile tmp, True
    Exit Function
EH:
    WriteUtf8_PS_DX = False
End Function

Private Function ReadUtf8_PS_DX(ByVal filePath As String) As String
    On Error GoTo EH
    Dim fso As Object: Set fso = CreateObject("Scripting.FileSystemObject")
    If Not fso.FileExists(filePath) Then ReadUtf8_PS_DX = "": Exit Function

    Dim tempDir As String: tempDir = Environ$("TEMP")
    If Len(tempDir) = 0 Then tempDir = "C:\Windows\Temp"
    Dim tmp As String: tmp = fso.BuildPath(tempDir, "gf_from_utf8_" & CStr(Int(Rnd() * 1000000)) & ".txt")

    Dim ps As String
    ps = "$c = Get-Content -LiteralPath " & PS_Quote_DX(filePath) & " -Raw -Encoding utf8; " & _
         "Set-Content -LiteralPath " & PS_Quote_DX(tmp) & " -Value $c -Encoding Unicode -NoNewline"
    If Not RunPS_DX(ps) Then ReadUtf8_PS_DX = "": Exit Function

    Const ForReading As Long = 1
    Const TristateTrue As Long = -1 ' Unicode
    Dim ts As Object
    Set ts = fso.OpenTextFile(tmp, ForReading, False, TristateTrue)
    ReadUtf8_PS_DX = ts.ReadAll
    ts.Close

    On Error Resume Next
    If fso.FileExists(tmp) Then fso.DeleteFile tmp, True
    Exit Function
EH:
    ReadUtf8_PS_DX = ""
End Function

Private Function PS_Quote_DX(ByVal s As String) As String
    PS_Quote_DX = "'" & Replace(s, "'", "''") & "'"
End Function

Private Function RunPS_DX(ByVal command As String) As Boolean
    On Error GoTo EH
    Dim sh As Object: Set sh = CreateObject("WScript.Shell")
    Dim rc As Long
    rc = sh.Run("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command " & command, 0, True)
    RunPS_DX = (rc = 0)
    Exit Function
EH:
    RunPS_DX = False
End Function

Private Function GuessBaseDir_DX() As String
    If EnsureFolder_DX(Environ$("LOCALAPPDATA") & "\GeoFooter") Then
        GuessBaseDir_DX = Environ$("LOCALAPPDATA") & "\GeoFooter"
        Exit Function
    End If
    If EnsureFolder_DX("C:\GeoFooter") Then
        GuessBaseDir_DX = "C:\GeoFooter"
        Exit Function
    End If
    GuessBaseDir_DX = Environ$("TEMP") & "\GeoFooter"
    EnsureFolder_DX GuessBaseDir_DX
End Function

Private Function ProbeSQLiteCS_Auto_DX(dbPath As String) As String
    On Error Resume Next
    Dim driversCSV As String: driversCSV = Dx_ListOdbcDriversCSV_DX()
    If Len(driversCSV) = 0 Then Exit Function

    Dim candidates As Variant
    candidates = Array( _
        "SQLite3 ODBC Driver", _
        "SQLite ODBC Driver", _
        "SQLite3 ODBC (Unicode)", _
        "SQLite ODBC (Unicode)", _
        "SQLite ODBC 3.8 Driver", _
        "SQLite ODBC 3.7 Driver" _
    )

    Dim i As Long
    For i = LBound(candidates) To UBound(candidates)
        If Dx_DriverPresent_DX(driversCSV, CStr(candidates(i))) Then
            Dim cn As Object: Set cn = CreateObject("ADODB.Connection")
            Dim cs As String
            cs = "Driver={" & candidates(i) & "};Database=" & dbPath & ";"
            cn.Open cs
            If Err.Number = 0 Then
                cn.Close
                ProbeSQLiteCS_Auto_DX = cs
                Exit Function
            End If
            Err.Clear
        End If
    Next i
End Function

Private Function Dx_ListOdbcDriversCSV_DX() As String
    Const HKLM As Long = &H80000002
    Dim reg As Object: Set reg = GetObject("winmgmts:!root\default:StdRegProv")

    Dim v1 As Variant, t1 As Variant, v2 As Variant, t2 As Variant
    On Error Resume Next
    reg.EnumValues HKLM, "SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers", v1, t1
    reg.EnumValues HKLM, "SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI\ODBC Drivers", v2, t2
    On Error GoTo 0

    Dim dict As Object: Set dict = CreateObject("Scripting.Dictionary")
    dict.CompareMode = 1 ' TextCompare

    Dim i As Long
    If IsArray(v1) Then
        For i = LBound(v1) To UBound(v1)
            If Len(Trim$(CStr(v1(i)))) > 0 Then dict(CStr(v1(i))) = True
        Next
    End If
    If IsArray(v2) Then
        For i = LBound(v2) To UBound(v2)
            If Len(Trim$(CStr(v2(i)))) > 0 Then dict(CStr(v2(i))) = True
        Next
    End If

    If dict.Count = 0 Then
        Dx_ListOdbcDriversCSV_DX = ""
        Exit Function
    End If

    Dim k As Variant, parts() As String
    ReDim parts(0 To dict.Count - 1)
    i = 0
    For Each k In dict.Keys
        parts(i) = CStr(k)
        i = i + 1
    Next
    Dx_ListOdbcDriversCSV_DX = Join(parts, ", ")
End Function

Private Function Dx_DriverPresent_DX(listCSV As String, driverName As String) As Boolean
    Dx_DriverPresent_DX = (InStr(1, listCSV, driverName, vbTextCompare) > 0)
End Function

