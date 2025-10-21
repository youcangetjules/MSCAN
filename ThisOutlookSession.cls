' ThisOutlookSession
' Watches all Inboxes for incoming mail (for footer insertion)
' Prompts for Security Classification ONLY for outgoing mail via Aliniant account

Option Explicit

Private gWatchers As Collection
Private Const ALINIANT_ACCOUNT_ADDRESS As String = "julian.garrett@aliniant.com" ' change if needed

' ----------------------------
' Startup: Initialize watchers
' ----------------------------
Private Sub Application_Startup()
    LogMessage "Application_Startup event fired � initializing watchers for all accounts."
    On Error GoTo ErrHandler

    Set gWatchers = New Collection

    Dim acc As Outlook.Account
    Dim store As Outlook.store
    Dim inboxFolder As Outlook.folder
    Dim watcher As MSCANclsEmailWatcher

    For Each acc In Application.Session.Accounts
        On Error Resume Next
        Set store = acc.DeliveryStore
        If Not store Is Nothing Then
            Set inboxFolder = store.GetDefaultFolder(olFolderInbox)
            If Not inboxFolder Is Nothing Then
                Set watcher = New MSCANclsEmailWatcher
                watcher.Init inboxFolder.items
                gWatchers.Add watcher, inboxFolder.folderPath
                LogMessage "Watcher created for: " & acc.DisplayName & " | Folder: " & inboxFolder.folderPath
            End If
        End If
        Err.Clear
        On Error GoTo 0
    Next acc

    LogMessage "Startup complete � " & gWatchers.Count & " inboxes monitored."
    Exit Sub

ErrHandler:
    LogMessage "Startup error: " & Err.Number & " - " & Err.Description
End Sub

' ----------------------------
' Quit: Clean up watchers
' ----------------------------
Private Sub Application_Quit()
    On Error Resume Next
    Dim i As Long
    For i = 1 To gWatchers.Count
        Set gWatchers.item(i) = Nothing
    Next i
    Set gWatchers = Nothing
    LogMessage "Quit: All watchers terminated."
End Sub

' ----------------------------
' Outgoing mail handler
' ----------------------------
Private Sub Application_ItemSend(ByVal item As Object, Cancel As Boolean)
    On Error GoTo ErrHandler
    
    ' Check if item is a mail item
    If Not TypeOf item Is Outlook.MailItem Then GoTo Skip
    
    Dim mail As Outlook.MailItem
    Set mail = item
    
    ' Check if sending account is set
    On Error Resume Next
    Dim senderAddress As String
    senderAddress = ""
    If Not mail.SendUsingAccount Is Nothing Then
        senderAddress = mail.SendUsingAccount.SmtpAddress
    End If
    On Error GoTo ErrHandler
    
    ' Only apply to Aliniant account
    If Len(senderAddress) = 0 Then GoTo Skip
    If LCase$(senderAddress) <> LCase$(ALINIANT_ACCOUNT_ADDRESS) Then GoTo Skip
    
    LogMessage "Processing outgoing email from Aliniant account: " & mail.Subject
    
    ' Detect existing classification tag
    Dim currentTag As String
    On Error Resume Next
        currentTag = MSCANModule2.DetectSecurityTag(mail.Subject)
    If Err.Number <> 0 Then
        LogMessage "DetectSecurityTag error: " & Err.Description
        currentTag = ""
        Err.Clear
    End If
    On Error GoTo ErrHandler
    
    Dim newSubject As String
    newSubject = mail.Subject
    
    ' Prompt only if no existing classification
    If Len(currentTag) = 0 Then
        On Error Resume Next
        newSubject = MSCANModule2.ShowSecurityRatingDialog(mail.Subject)
        If Err.Number <> 0 Then
            LogMessage "ShowSecurityRatingDialog error: " & Err.Description
            Cancel = True
            MsgBox "Error showing security dialog: " & Err.Description & vbCrLf & vbCrLf & "Email send cancelled.", vbCritical, "Classification Error"
            Err.Clear
            Exit Sub
        End If
        On Error GoTo ErrHandler
        
        If Len(Trim$(newSubject)) = 0 Then
            Cancel = True
            MsgBox "Sending cancelled. A security classification is required.", vbExclamation, "Classification Required"
            LogMessage "User cancelled - no classification selected"
            Exit Sub
        End If
        
        ' Update the subject with the new classification
        mail.Subject = newSubject
    End If
    
    ' Add footer
    On Error Resume Next
    MSCANModule2.AddFooter mail
    If Err.Number <> 0 Then
        LogMessage "AddFooter error: " & Err.Description
        Err.Clear
    End If
    On Error GoTo ErrHandler
    
    ' Save changes
    On Error Resume Next
    mail.Save
    If Err.Number <> 0 Then
        LogMessage "Save error: " & Err.Description
        Err.Clear
    End If
    On Error GoTo ErrHandler
    
    LogMessage "Email processed successfully: " & mail.Subject

Skip:
    Exit Sub

ErrHandler:
    LogMessage "Application_ItemSend error: " & Err.Number & " - " & Err.Description
    Cancel = True
    MsgBox "An error occurred while processing this email: " & Err.Description & vbCrLf & vbCrLf & "Email send cancelled.", vbCritical, "Send Error"
End Sub

' ----------------------------
' Logging helper
' ----------------------------
Public Sub LogMessage(ByVal msg As String)
    On Error Resume Next
    
    ' Try to call MSCANModule1.WriteLog if available
    MSCANModule1.WriteLog msg
    If Err.Number <> 0 Then
        ' If MSCANModule1.WriteLog fails, use simple debug output
        Debug.Print "LOG: " & Format$(Now, "yyyy-mm-dd hh:nn:ss") & " - " & msg
        Err.Clear
    End If
End Sub

' ----------------------------
' Reset all watchers manually
' ----------------------------
Public Sub ResetWatcher()
    On Error GoTo EH
    Application_Quit
    Application_Startup
    MsgBox "All email watchers have been reset.", vbInformation
    LogMessage "ResetWatcher: Watchers manually re-initialized."
    Exit Sub
EH:
    LogMessage "ResetWatcher error: " & Err.Number & " - " & Err.Description
End Sub

