Attribute VB_Name = "MSCANModuleHeaders"
Option Explicit

' Deprecated: use MSCANModule1.GetInternetHeaders instead.
Public Function GetInternetHeaders_Legacy(mail As Outlook.MailItem) As String
    On Error GoTo ErrorHandler
    Dim tag As String
    tag = "http://schemas.microsoft.com/mapi/proptag/0x007D001E"
    GetInternetHeaders_Legacy = CStr(mail.PropertyAccessor.GetProperty(tag))
    Exit Function

ErrorHandler:
    GetInternetHeaders_Legacy = ""
End Function
