' Class module: clsEmailWatcher
' Watches an Outlook folder for new items.

Option Explicit

' Declare the Items collection WithEvents to handle its events
Private WithEvents WatchedItems As Outlook.Items
Private mFolderPath As String

' Initializes the watcher to monitor a specific folder's Items collection.
Public Sub Init(ByVal Items As Outlook.Items)
    On Error GoTo EH
    If Items Is Nothing Then
        MSCANModule1.WriteLog "clsEmailWatcher.Init error: Items collection is Nothing"
        Exit Sub
    End If
    Set WatchedItems = Items
    If Not WatchedItems.parent Is Nothing Then
        mFolderPath = WatchedItems.parent.folderPath
        MSCANModule1.WriteLog "clsEmailWatcher.Init: Now watching folder " & mFolderPath
    Else
        MSCANModule1.WriteLog "clsEmailWatcher.Init error: Parent folder is Nothing"
    End If
    Exit Sub
EH:
    MSCANModule1.WriteLog "clsEmailWatcher.Init error: " & Err.Number & " - " & Err.Description
End Sub

Private Sub WatchedItems_ItemAdd(ByVal item As Object)
    On Error GoTo EH
    If TypeOf item Is Outlook.MailItem Then
        MSCANModule1.WriteLog "clsEmailWatcher: New MailItem received. Subject: " & item.Subject
        MSCANModule1.ProcessEmailSecurity item
    End If
    Exit Sub
EH:
    MSCANModule1.WriteLog "clsEmailWatcher.ItemAdd error: " & Err.Number & " - " & Err.Description
End Sub
