unit transwebsync;

{  Copyright (C) 2026

    License:
    This code is licensed under MIT License, see the file License.txt
    or https://spdx.org/licenses/MIT.html  SPDX short identifier: MIT

  ------------------

  A unit that does the file transfer side of a Sync operation against any
  server implementing the Tomboy Web Sync API 1.0 (OAuth 1.0a + REST) - this
  covers Grauphel, Rainy, and Puddle (a self-hosted rewrite of Rainy, see
  ~/development/Puddle) interchangeably, since they all speak the same wire
  protocol - the same protocol Tomdroid's "tomboy-web" sync option and
  original desktop Tomboy's WebSyncService addin use, so an existing
  Tomdroid/Grauphel setup should be able to point straight at this without
  changing anything on the Android/server side.

  HISTORY
  2026-xx-xx  First working version.

  ===================== Notes on this transport's design ===================

  Unlike transfile/transmisty (a manifest.xml the whole repo shares) there is
  no "manifest" concept in this protocol at all - every note-changes PUT is
  self-contained and atomically bumps the server's revision counter by one.
  So DoRemoteManifest() is a no-op here: TSync will still call it (see
  sync.pas's WriteRemoteManifest(), which builds and passes a local
  manifest.xml file path we simply ignore), since this transport is
  deliberately NOT special-cased in sync.pas the way SyncGithub/SyncMisty
  are - it follows the same "each abstract method does its own real network
  I/O, no engine-level exemptions" pattern transfile.pas uses. That costs a
  little chattiness (DeleteNote does one PUT per deleted note rather than
  batching every change from a sync into one call) but keeps this a true
  drop-in transport requiring no changes to the shared sync engine beyond
  the one unavoidable construction case in TSync.SetTransport.

  Wire field names/shapes are not re-derived from the REST spec doc. One
  detail worth flagging since it's easy to get backwards: "note-content" on
  the wire is the *unwrapped inner* content of a note (what would go
  between <note-content version="...">...</note-content>), NOT the fragment
  including those tags itself - confirmed empirically against a real
  desktop Tomboy client's PUT body (as stored verbatim by Puddle, which does
  no wrapping/unwrapping of its own). The full-note reconstruction on
  download re-adds the <note-content version="0.1"> wrapper itself, matching
  the shape tomboy-ng's own savenote.pas Header()/Footer() produce.

  OAuth connect flow (ConnectViaOAuth) opens the system browser and waits on
  a local loopback listener for the redirect, matching how desktop Tomboy's
  own WebSyncPreferencesWidget.cs and Tomdroid both do it - not the
  "unattended" username+password shortcut some servers (including Puddle)
  also support, since no real client actually uses that path and it would
  mean routing the user's password through more code than necessary.
  ConnectViaOAuth BLOCKS until the browser round-trip completes or times
  out - call it from a worker thread once wired to a "Connect" button, not
  directly on the GUI thread.
}

{$mode objfpc}{$H+}
{$WARN 5024 off : Parameter "$1" not used}

interface

uses
    Classes, SysUtils, trans, SyncUtils, tb_utils, oauth1client;

type

    { TWebSyncTrans }

    TWebSyncTrans = Class(TTomboyTrans)
    private
        FAccessToken, FAccessTokenSecret: string;
        FNotesApiUrl: string;                  // discovered fresh each TestTransport call

        function TokenFilePath: string;
        function LoadAccessToken: boolean;
        procedure SaveAccessToken;

                    // Does a signed GET, returns response body, '' and ErrorString set on failure.
        function SignedGet(const URL: string; const ExtraParam: string = ''): string;
                    // Does a signed PUT with a JSON body, returns response body, '' and ErrorString set on failure.
        function SignedPut(const URL, JsonBody: string): string;

    public
        function SetTransport(): TSyncAvailable; override;
        function TestTransport(const WriteNewServerID : boolean = False) : TSyncAvailable; override;
        function GetRemoteNotes(const NoteMeta : TNoteInfoList; const GetLCD : boolean) : boolean; override;
        function DownloadNotes(const DownLoads : TNoteInfoList) : boolean; override;
        function DeleteNote(const ID : string; const ExistRev : integer) : boolean; override;
        function UploadNotes(const Uploads : TStringList) : boolean; override;
        function DoRemoteManifest(const RemoteManifest : string; MetaData : TNoteInfoList = nil) : boolean; override;
        function DownLoadNote(const ID : string; const RevNo : Integer) : string; Override;

                    { Opens the system browser to authorize this app against RemoteAddress,
                      waits (blocking - see unit header) on a local loopback listener for the
                      redirect, then exchanges the verifier for a permanent access token and
                      persists it to ConfigDir. Call once per server; TestTransport reuses the
                      persisted token on every subsequent sync. }
        function ConnectViaOAuth(out ErrMsg: string): boolean;
                    { True once we have a persisted access token - the UI can use this to
                      decide whether to show "Connect" or just proceed straight to syncing. }
        function IsConnected: boolean;

        constructor Create(PP : TProgressProcedure = nil);
    end;


implementation

uses fphttpclient, fphttpserver, httpdefs, httpprotocol, LazLogger, LazFileUtils, FileUtil,
    jsontools, StrUtils, DateUtils, ResourceStr {$ifdef LCL}, LCLIntf{$endif};

type
    { Holds state for a single OAuth loopback-callback wait - a plain nested
      procedure can't be assigned to TFPHTTPServer.OnRequest (an "of object"
      method type), so this is the smallest way to give the handler somewhere
      to stash the verifier it receives. }
    TOAuthCallbackCatcher = class
    public
        Verifier: string;
        Got: boolean;
        Server: TFPHTTPServer;
        procedure HandleRequest(Sender: TObject; var ARequest: TFPHTTPConnectionRequest;
            var AResponse: TFPHTTPConnectionResponse);
    end;

procedure TOAuthCallbackCatcher.HandleRequest(Sender: TObject; var ARequest: TFPHTTPConnectionRequest;
    var AResponse: TFPHTTPConnectionResponse);
begin
    Verifier := ARequest.QueryFields.Values['oauth_verifier'];
    Got := True;
    AResponse.Code := 200;
    AResponse.Content := '<html><body><h3>Authorization complete</h3>'
        + '<p>You can close this tab and return to tomboy-ng.</p></body></html>';
    AResponse.SendContent;
    Server.Active := False;
end;

const
    TokenFileName = 'access_token.dat';
    OAuthCallbackPort = 8090;      // fixed loopback port; matches no other localhost service in practice

{ ----------------------------- small local helpers ----------------------------- }

function AppendSlash(const URL : string) : string;
begin
    if URL.EndsWith('/') then Result := URL else Result := URL + '/';
end;

    // Nil-safe JSON field readers - defensive against a server (Grauphel/Rainy,
    // not just Puddle) omitting a field our own server always includes.
function JsonStr(Node: TJsonNode; const Key, Default: string): string;
var Child: TJsonNode;
begin
    if Node = nil then exit(Default);
    Child := Node.Find(Key);
    if Child = nil then Result := Default else Result := Child.AsString;
end;

function JsonBool(Node: TJsonNode; const Key: string; Default: boolean): boolean;
var Child: TJsonNode;
begin
    if Node = nil then exit(Default);
    Child := Node.Find(Key);
    if Child = nil then Result := Default else Result := Child.AsBoolean;
end;

function JsonNum(Node: TJsonNode; const Key: string; Default: double): double;
var Child: TJsonNode;
begin
    if Node = nil then exit(Default);
    Child := Node.Find(Key);
    if Child = nil then Result := Default else Result := Child.AsNumber;
end;

procedure SaveStringToFile(const S, FFName: string);
var
    F: TextFile;
begin
    AssignFile(F, FFName);
    try
        Rewrite(F);
        Write(F, S);
    finally
        CloseFile(F);
    end;
end;

function LoadStringFromFile(const FFName: string): string;
var
    L: TStringList;
begin
    L := TStringList.Create;
    try
        L.LoadFromFile(FFName);
        Result := L.Text;
    finally
        L.Free;
    end;
end;

    // Extracts the inner text of the FIRST occurrence of <TagName ...>...</TagName>,
    // skipping over any attributes on the opening tag. '' if not found.
function ExtractXmlField(const RawXml, TagName: string): string;
var
    P1, P2: integer;
begin
    Result := '';
    P1 := Pos('<' + TagName, RawXml);
    if P1 = 0 then exit;
    P1 := PosEx('>', RawXml, P1);
    if P1 = 0 then exit;
    inc(P1);
    P2 := PosEx('</' + TagName + '>', RawXml, P1);
    if P2 = 0 then exit;
    Result := copy(RawXml, P1, P2 - P1);
end;

    // Real Tomboy Web Sync clients send "note-content" as the body only -
    // the title is never repeated as content's first line on the wire (see
    // unit header). But locally, a .note file's note-content buffer always
    // starts with the title itself followed by a blank line (matching
    // savenote.pas's own Header()/Footer() convention - see a freshly
    // created note for the exact shape). Strip that prefix here so what we
    // upload matches what every other real client sends.
function StripTitlePrefix(const ContentFragment, Title: string): string;
begin
    Result := ContentFragment;
    if (Title <> '') and (Pos(Title, Result) = 1) then
        Result := copy(Result, Length(Title) + 1, MaxInt);
    while (copy(Result, 1, Length(LineEnding)) = LineEnding) do
        Result := copy(Result, Length(LineEnding) + 1, MaxInt);
end;

    // Returns a JSON array literal, eg ["system:notebook:Foo","system:template"],
    // built from the <tags><tag>...</tag>...</tags> block of a local .note file.
function ExtractTagsJsonArray(const RawXml: string): string;
var
    TagsStart, TagsEnd, P1, P2: integer;
    Segment, TagVal: string;
    List: TStringList;
    I: integer;
begin
    List := TStringList.Create;
    try
        TagsStart := Pos('<tags>', RawXml);
        if TagsStart > 0 then begin
            TagsEnd := PosEx('</tags>', RawXml, TagsStart);
            if TagsEnd > 0 then begin
                Segment := copy(RawXml, TagsStart, TagsEnd - TagsStart);
                P1 := Pos('<tag>', Segment);
                while P1 > 0 do begin
                    P1 := P1 + Length('<tag>');
                    P2 := PosEx('</tag>', Segment, P1);
                    if P2 = 0 then break;
                    TagVal := copy(Segment, P1, P2 - P1);
                    List.Add(TagVal);
                    P1 := PosEx('<tag>', Segment, P2);
                end;
            end;
        end;
        Result := '[';
        for I := 0 to List.Count - 1 do begin
            if I > 0 then Result := Result + ',';
            Result := Result + JsonStringEncode(List[I]);
        end;
        Result := Result + ']';
    finally
        List.Free;
    end;
end;

    // Builds a full, valid .note XML document from one JSON note object (as
    // found in a "notes"/"note" array), matching the shape savenote.pas's
    // Header()/Footer() produce.
function BuildNoteXmlFromJson(NoteNode: TJsonNode): string;
var
    Title, ContentFragment, ChangeDate, MetaChangeDate, CreateDate, TagLines: string;
    TagsNode, ATag: TJsonNode;
begin
    // Some real clients (e.g. desktop Tomboy) send the title already
    // XML-entity-escaped rather than as plain text (matching what they
    // happen to store locally) - decode any such entities first, or
    // RemoveBadXMLCharacters below would double-escape the '&' and leave a
    // literal "&apos;" etc. visible in the rebuilt title.
    Title := RemoveBadXMLCharacters(RestoreBadXMLChar(JsonStr(NoteNode, 'title', '')));
    ContentFragment := JsonStr(NoteNode, 'note-content', '');
    ChangeDate := JsonStr(NoteNode, 'last-change-date', '');
    MetaChangeDate := JsonStr(NoteNode, 'last-metadata-change-date', '');
    CreateDate := JsonStr(NoteNode, 'create-date', '');
    if ChangeDate = '' then ChangeDate := TB_GetLocalTime();
    if MetaChangeDate = '' then MetaChangeDate := ChangeDate;
    if CreateDate = '' then CreateDate := ChangeDate;

    TagLines := '';
    if NoteNode <> nil then begin
        TagsNode := NoteNode.Find('tags');
        if (TagsNode <> nil) and (TagsNode.Kind = nkArray) then
            for ATag in TagsNode do
                TagLines := TagLines + '    <tag>' + RemoveBadXMLCharacters(RestoreBadXMLChar(ATag.AsString)) + '</tag>' + LineEnding;
    end;

    Result :=
        '<?xml version="1.0" encoding="utf-8"?>' + LineEnding +
        '<note version="0.3" xmlns:link="http://beatniksoftware.com/tomboy/link" xmlns:size="http://beatniksoftware.com/tomboy/size" xmlns="http://beatniksoftware.com/tomboy">' + LineEnding +
        '  <title>' + Title + '</title>' + LineEnding +
        '  <text xml:space="preserve"><note-content version="0.1">' + Title + LineEnding + LineEnding + ContentFragment + '</note-content></text>' + LineEnding +
        '  <last-change-date>' + ChangeDate + '</last-change-date>' + LineEnding +
        '  <last-metadata-change-date>' + MetaChangeDate + '</last-metadata-change-date>' + LineEnding +
        '  <create-date>' + CreateDate + '</create-date>' + LineEnding +
        '  <cursor-position>1</cursor-position>' + LineEnding +
        '  <selection-bound-position>1</selection-bound-position>' + LineEnding +
        '  <width>0</width>' + LineEnding +
        '  <height>0</height>' + LineEnding +
        '  <x>0</x>' + LineEnding +
        '  <y>0</y>' + LineEnding +
        '  <tags>' + LineEnding + TagLines + '  </tags>' + LineEnding +
        '  <open-on-startup>' + BoolToStr(JsonBool(NoteNode, 'open-on-startup', False), 'true', 'false') + '</open-on-startup>' + LineEnding +
        '  <pinned>' + BoolToStr(JsonBool(NoteNode, 'pinned', False), 'true', 'false') + '</pinned>' + LineEnding +
        '</note>';
end;

    // Parses a form-encoded body (oauth_token=...&oauth_token_secret=...) -
    // the OAuth token endpoints' response shape, NOT JSON.
function ExtractFormValue(const Body, Key: string): string;
var
    SearchKey: string;
    P, E: integer;
begin
    Result := '';
    SearchKey := Key + '=';
    P := Pos(SearchKey, Body);
    while (P > 1) and not (Body[P - 1] in ['&', '?']) do begin
        P := PosEx(SearchKey, Body, P + 1);
        if P = 0 then exit;
    end;
    if P = 0 then exit;
    P := P + Length(SearchKey);
    E := PosEx('&', Body, P);
    if E = 0 then E := Length(Body) + 1;
    Result := HTTPDecode(copy(Body, P, E - P));
end;

{ TWebSyncTrans }

constructor TWebSyncTrans.Create(PP : TProgressProcedure = nil);
begin
    ProgressProcedure := PP;
end;

function TWebSyncTrans.TokenFilePath: string;
begin
    Result := AppendSlash(ConfigDir) + TokenFileName;
end;

function TWebSyncTrans.LoadAccessToken: boolean;
var
    F: TStringList;
begin
    Result := False;
    if not FileExists(TokenFilePath) then exit;
    F := TStringList.Create;
    try
        F.LoadFromFile(TokenFilePath);
        if F.Count < 2 then exit;
        FAccessToken := F[0];
        FAccessTokenSecret := F[1];
        Result := (FAccessToken <> '') and (FAccessTokenSecret <> '');
    finally
        F.Free;
    end;
end;

procedure TWebSyncTrans.SaveAccessToken;
var
    F: TStringList;
begin
    if not DirectoryExists(ConfigDir) then ForceDirectoriesUTF8(ConfigDir);
    F := TStringList.Create;
    try
        F.Add(FAccessToken);
        F.Add(FAccessTokenSecret);
        F.SaveToFile(TokenFilePath);
    finally
        F.Free;
    end;
end;

function TWebSyncTrans.IsConnected: boolean;
begin
    if FAccessToken = '' then LoadAccessToken;
    Result := FAccessToken <> '';
end;

function TWebSyncTrans.SignedGet(const URL: string; const ExtraParam: string = ''): string;
var
    Client: TFPHttpClient;
    Params: TOAuthParams;
    NameVal: TStringArray;
begin
    Result := '';
    Params := TOAuthParams.Create;
    Client := TFPHttpClient.Create(nil);
    try
        if ExtraParam <> '' then begin
            NameVal := ExtraParam.Split(['=']);
            if Length(NameVal) = 2 then Params.AddParam(NameVal[0], NameVal[1]);
        end;
        OAuthSignRequest('GET', URL, Params, FAccessToken, FAccessTokenSecret);

        Client.AddHeader('User-Agent', 'Mozilla/5.0 (compatible; fpweb)');
        Client.AddHeader('Authorization', OAuthAuthHeader(Params));
        Client.AllowRedirect := True;
        Client.ConnectTimeout := 8000;
        Client.IOTimeout := 8000;
        try
            Result := Client.Get(URL);
        except
            on E: Exception do begin
                ErrorString := 'TWebSyncTrans.SignedGet - ' + E.Message + ' (' + URL + ')';
                DebugLn(ErrorString);
                exit('');
            end;
        end;
        if Client.ResponseStatusCode <> 200 then begin
            ErrorString := 'TWebSyncTrans.SignedGet - server returned '
                + IntToStr(Client.ResponseStatusCode) + ' for ' + URL + ' : ' + Result;
            DebugLn(ErrorString);
            exit('');
        end;
    finally
        Client.Free;
        Params.Free;
    end;
end;

function TWebSyncTrans.SignedPut(const URL, JsonBody: string): string;
var
    Client: TFPHttpClient;
    Params: TOAuthParams;
    ResponseStream: TStringStream;
begin
    Result := '';
    Params := TOAuthParams.Create;
    Client := TFPHttpClient.Create(nil);
    ResponseStream := TStringStream.Create('');
    try
        OAuthSignRequest('PUT', URL, Params, FAccessToken, FAccessTokenSecret);
        Client.AddHeader('User-Agent', 'Mozilla/5.0 (compatible; fpweb)');
        Client.AddHeader('Authorization', OAuthAuthHeader(Params));
        Client.AddHeader('Content-Type', 'application/json; charset=UTF-8');
        Client.AllowRedirect := True;
        Client.ConnectTimeout := 8000;
        Client.IOTimeout := 8000;
        Client.RequestBody := TRawByteStringStream.Create(JsonBody);
        try
            try
                Client.HTTPMethod('PUT', URL, ResponseStream, []);
            except
                on E: Exception do begin
                    ErrorString := 'TWebSyncTrans.SignedPut - ' + E.Message + ' (' + URL + ')';
                    DebugLn(ErrorString);
                    exit('');
                end;
            end;
        finally
            Client.RequestBody.Free;
            Client.RequestBody := nil;
        end;
        if Client.ResponseStatusCode <> 200 then begin
            ErrorString := 'TWebSyncTrans.SignedPut - server returned '
                + IntToStr(Client.ResponseStatusCode) + ' for ' + URL + ' : ' + ResponseStream.DataString;
            DebugLn(ErrorString);
            exit('');
        end;
        Result := ResponseStream.DataString;
    finally
        Client.Free;
        Params.Free;
        ResponseStream.Free;
    end;
end;

function TWebSyncTrans.SetTransport(): TSyncAvailable;
var
    Probe: string;
    Client: TFPHttpClient;
begin
    RemoteAddress := AppendSlash(RemoteAddress);
    // Thin, unauthenticated reachability check only - the real credential
    // check happens in TestTransport, which needs a persisted access token.
    Probe := '';
    Client := TFPHttpClient.Create(nil);
    try
        Client.AddHeader('User-Agent', 'Mozilla/5.0 (compatible; fpweb)');
        Client.ConnectTimeout := 5000;
        Client.IOTimeout := 5000;
        try
            Probe := Client.Get(RemoteAddress + 'api/1.0');
        except
            on E: Exception do begin
                ErrorString := 'TWebSyncTrans.SetTransport - ' + E.Message;
                exit(SyncNetworkError);
            end;
        end;
    finally
        Client.Free;
    end;
    if Pos('oauth_request_token_url', Probe) = 0 then begin
        ErrorString := 'TWebSyncTrans.SetTransport - server at ' + RemoteAddress
            + ' does not look like a Tomboy Web Sync server';
        exit(SyncNetworkError);
    end;
    Result := SyncReady;
end;

function TWebSyncTrans.TestTransport(const WriteNewServerID: boolean = False): TSyncAvailable;
var
    DiscoveryJson, UserJson: string;
    Root: TJsonNode;
    UserApiUrl: string;
begin
    Result := SyncNotYet;
    ErrorString := '';
    if not IsConnected then begin
        ErrorString := 'Not yet connected - use Connect to authorize this app against the server.';
        exit(SyncCredentialError);
    end;

    DiscoveryJson := SignedGet(AppendSlash(RemoteAddress) + 'api/1.0');
    if DiscoveryJson = '' then exit(SyncNetworkError);   // ErrorString set by SignedGet

    Root := TJsonNode.Create;
    try
        if not Root.TryParse(DiscoveryJson) then begin
            ErrorString := 'TWebSyncTrans.TestTransport - invalid discovery JSON';
            exit(SyncBadError);
        end;
        if Root.Find('user-ref') = nil then begin
            ErrorString := 'TWebSyncTrans.TestTransport - server did not recognise our access token';
            exit(SyncCredentialError);
        end;
        UserApiUrl := JsonStr(Root.Find('user-ref'), 'api-ref', '');
    finally
        Root.Free;
    end;
    if UserApiUrl = '' then begin
        ErrorString := 'TWebSyncTrans.TestTransport - missing user-ref api-ref';
        exit(SyncBadError);
    end;

    UserJson := SignedGet(UserApiUrl);
    if UserJson = '' then exit(SyncNetworkError);

    Root := TJsonNode.Create;
    try
        if not Root.TryParse(UserJson) then begin
            ErrorString := 'TWebSyncTrans.TestTransport - invalid user JSON';
            exit(SyncBadError);
        end;
        FNotesApiUrl := JsonStr(Root.Find('notes-ref'), 'api-ref', '');
        ServerID := JsonStr(Root, 'current-sync-guid', '');
        RemoteServerRev := Round(JsonNum(Root, 'latest-sync-revision', -1));
    finally
        Root.Free;
    end;

    if FNotesApiUrl = '' then begin
        ErrorString := 'TWebSyncTrans.TestTransport - missing notes-ref';
        exit(SyncBadError);
    end;
    if not IDLooksOK(ServerID) then begin
        ErrorString := 'Invalid ServerID from server [' + ServerID + ']';
        exit(SyncXMLError);
    end;
    Result := SyncReady;
end;

function TWebSyncTrans.GetRemoteNotes(const NoteMeta: TNoteInfoList; const GetLCD: boolean): boolean;
var
    ResponseJson: string;
    Root, NotesArray, ANode: TJsonNode;
    NoteInfo: PNoteInfo;
begin
    Result := False;
    if NoteMeta = nil then begin
        ErrorString := 'TWebSyncTrans.GetRemoteNotes - passed a nil list';
        exit;
    end;
    // include_notes=false - only metadata here; DownloadNotes fetches full
    // content per-note later. LCD (last-change-date) comes back regardless -
    // this protocol has no separate "just the LCD" toggle, unlike GetLCD's name.
    ResponseJson := SignedGet(FNotesApiUrl, 'include_notes=false');
    if ResponseJson = '' then exit(False);

    Root := TJsonNode.Create;
    try
        if not Root.TryParse(ResponseJson) then begin
            ErrorString := 'TWebSyncTrans.GetRemoteNotes - invalid JSON from server';
            exit(False);
        end;
        NotesArray := Root.Find('notes');
        if NotesArray = nil then begin
            ErrorString := 'TWebSyncTrans.GetRemoteNotes - missing notes array';
            exit(False);
        end;
        for ANode in NotesArray do begin
            new(NoteInfo);
            NoteInfo^.ForceUpload := False;
            NoteInfo^.Action := SyUnset;
            NoteInfo^.Deleted := False;
            NoteInfo^.ID := JsonStr(ANode, 'guid', '');
            NoteInfo^.Rev := Round(JsonNum(ANode, 'last-sync-revision', -1));
            NoteInfo^.Title := JsonStr(ANode, 'title', '');
            NoteInfo^.LastChange := JsonStr(ANode, 'last-change-date', '');
            if NoteInfo^.LastChange <> '' then
                NoteInfo^.LastChangeGMT := TB_GetGMTFromStr(NoteInfo^.LastChange);
            NoteInfo^.CreateDate := JsonStr(ANode, 'create-date', '');
            NoteMeta.Add(NoteInfo);
        end;
    finally
        Root.Free;
    end;
    Result := True;
end;

function TWebSyncTrans.DownloadNotes(const DownLoads: TNoteInfoList): boolean;
var
    I, DownCount: integer;
    ResponseJson, NoteXml: string;
    Root, NoteArr: TJsonNode;
begin
    Result := True;
    if ProgressProcedure <> nil then ProgressProcedure(rsDownloadNotes);
    if not DirectoryExists(NotesDir + 'Backup') then
        if not ForceDirectory(NotesDir + 'Backup') then begin
            ErrorString := 'Failed to create Backup directory.';
            exit(False);
        end;
    DownCount := 0;
    for I := 0 to DownLoads.Count - 1 do begin
        if DownLoads.Items[I]^.Action = SyDownLoad then begin
            ResponseJson := SignedGet(FNotesApiUrl + '/' + DownLoads.Items[I]^.ID);
            if ResponseJson = '' then exit(False);

            Root := TJsonNode.Create;
            try
                if not Root.TryParse(ResponseJson) then begin
                    ErrorString := 'TWebSyncTrans.DownloadNotes - invalid JSON for ' + DownLoads.Items[I]^.ID;
                    exit(False);
                end;
                NoteArr := Root.Find('note');
                if (NoteArr = nil) or (NoteArr.Count < 1) then begin
                    ErrorString := 'TWebSyncTrans.DownloadNotes - no note in response for ' + DownLoads.Items[I]^.ID;
                    exit(False);
                end;
                NoteXml := BuildNoteXmlFromJson(NoteArr.Child(0));
            finally
                Root.Free;
            end;

            if FileExists(NotesDir + DownLoads.Items[I]^.ID + '.note') then
                if not CopyFile(NotesDir + DownLoads.Items[I]^.ID + '.note',
                        NotesDir + 'Backup' + PathDelim + DownLoads.Items[I]^.ID + '.note') then begin
                    ErrorString := 'Failed to copy file to Backup ' + NotesDir + DownLoads.Items[I]^.ID + '.note';
                    exit(False);
                end;
            SaveStringToFile(NoteXml, NotesDir + DownLoads.Items[I]^.ID + '.note');

            inc(DownCount);
            if (DownCount mod 5 = 0) and (ProgressProcedure <> nil) then
                ProgressProcedure(rsDownLoaded + ' ' + IntToStr(DownCount) + ' notes');
        end;
    end;
end;

function TWebSyncTrans.DeleteNote(const ID: string; const ExistRev: integer): boolean;
var
    Body: string;
begin
    Body := '{"latest-sync-revision":' + IntToStr(RemoteServerRev + 1)
        + ',"note-changes":[{"guid":' + JsonStringEncode(ID) + ',"command":"delete"}]}';
    Result := SignedPut(FNotesApiUrl, Body) <> '';
    if not Result then
        DebugLn('TWebSyncTrans.DeleteNote - failed to delete ' + ID + ' : ' + ErrorString);
end;

function TWebSyncTrans.UploadNotes(const Uploads: TStringList): boolean;
var
    Index, UpCount: integer;
    Body, RawXml, ID, Title, ContentFragment, ChangeDate, MetaChangeDate, CreateDate, TagsJson: string;
begin
    Result := True;
    if Uploads.Count = 0 then exit(True);
    if ProgressProcedure <> nil then ProgressProcedure('Uploading ' + IntToStr(Uploads.Count) + ' notes');

    Body := '{"latest-sync-revision":' + IntToStr(RemoteServerRev + 1) + ',"note-changes":[';
    UpCount := 0;
    for Index := 0 to Uploads.Count - 1 do begin
        ID := Uploads[Index];
        if not FileExists(NotesDir + ID + '.note') then begin
            ErrorString := 'TWebSyncTrans.UploadNotes - local note missing : ' + ID;
            exit(False);
        end;
        RawXml := LoadStringFromFile(NotesDir + ID + '.note');
        Title := ExtractXmlField(RawXml, 'title');
        ContentFragment := ExtractXmlField(RawXml, 'note-content');
        if ContentFragment = '' then begin
            ErrorString := 'TWebSyncTrans.UploadNotes - failed to extract note-content : ' + ID;
            exit(False);
        end;
        ContentFragment := StripTitlePrefix(ContentFragment, Title);
        ChangeDate := ExtractXmlField(RawXml, 'last-change-date');
        MetaChangeDate := ExtractXmlField(RawXml, 'last-metadata-change-date');
        CreateDate := ExtractXmlField(RawXml, 'create-date');
        TagsJson := ExtractTagsJsonArray(RawXml);

        if Index > 0 then Body := Body + ',';
        Body := Body
            + '{"guid":' + JsonStringEncode(ID)
            + ',"title":' + JsonStringEncode(Title)
            + ',"note-content":' + JsonStringEncode(ContentFragment)
            + ',"create-date":' + JsonStringEncode(CreateDate)
            + ',"last-change-date":' + JsonStringEncode(ChangeDate)
            + ',"last-metadata-change-date":' + JsonStringEncode(MetaChangeDate)
            + ',"tags":' + TagsJson
            + '}';

        inc(UpCount);
        if (UpCount mod 5 = 0) and (ProgressProcedure <> nil) then
            ProgressProcedure(rsUpLoaded + ' ' + IntToStr(UpCount) + ' notes');
    end;
    Body := Body + ']}';

    Result := SignedPut(FNotesApiUrl, Body) <> '';
    if not Result then
        DebugLn('TWebSyncTrans.UploadNotes - PUT failed : ' + ErrorString);
end;

function TWebSyncTrans.DoRemoteManifest(const RemoteManifest: string; MetaData: TNoteInfoList = nil): boolean;
begin
    // No manifest concept in this protocol - every UploadNotes/DeleteNote
    // call is already a self-contained, atomic PUT. See unit header for why
    // this transport isn't special-cased in sync.pas the way SyncGithub is
    // (which would let us batch a whole sync's changes into one call here
    // instead of per DeleteNote/UploadNotes call).
    Result := True;
end;

function TWebSyncTrans.DownLoadNote(const ID: string; const RevNo: Integer): string;
var
    ResponseJson, NoteXml: string;
    Root, NoteArr: TJsonNode;
begin
    Result := '';
    ResponseJson := SignedGet(FNotesApiUrl + '/' + ID);
    if ResponseJson = '' then exit('');

    Root := TJsonNode.Create;
    try
        if not Root.TryParse(ResponseJson) then exit('');
        NoteArr := Root.Find('note');
        if (NoteArr = nil) or (NoteArr.Count < 1) then exit('');
        NoteXml := BuildNoteXmlFromJson(NoteArr.Child(0));
    finally
        Root.Free;
    end;

    if not DirectoryExists(NotesDir + 'Temp') then
        ForceDirectoriesUTF8(NotesDir + 'Temp');
    Result := NotesDir + 'Temp' + PathDelim + ID + '.note';
    SaveStringToFile(NoteXml, Result);
    if not FileExists(Result) then Result := '';
end;

function TWebSyncTrans.ConnectViaOAuth(out ErrMsg: string): boolean;
var
    DiscoveryJson, ReqTokenResp, AccessResp: string;
    Root: TJsonNode;
    RequestTokenUrl, AuthorizeUrl, AccessTokenUrl: string;
    ReqToken, ReqSecret, Verifier, CallbackUrl, AuthUrl: string;
    Params: TOAuthParams;
    Client: TFPHttpClient;
    Server: TFPHTTPServer;
    Catcher: TOAuthCallbackCatcher;
    Got: boolean;

begin
    Result := False;
    ErrMsg := '';
    RemoteAddress := AppendSlash(RemoteAddress);

    DiscoveryJson := '';
    Client := TFPHttpClient.Create(nil);
    try
        Client.AddHeader('User-Agent', 'Mozilla/5.0 (compatible; fpweb)');
        try
            DiscoveryJson := Client.Get(RemoteAddress + 'api/1.0');
        except
            on E: Exception do begin
                ErrMsg := 'Failed to reach server: ' + E.Message;
                exit;
            end;
        end;
    finally
        Client.Free;
    end;

    Root := TJsonNode.Create;
    try
        if not Root.TryParse(DiscoveryJson) then begin
            ErrMsg := 'Server did not return a valid discovery document';
            exit;
        end;
        RequestTokenUrl := JsonStr(Root, 'oauth_request_token_url', '');
        AuthorizeUrl := JsonStr(Root, 'oauth_authorize_url', '');
        AccessTokenUrl := JsonStr(Root, 'oauth_access_token_url', '');
    finally
        Root.Free;
    end;
    if (RequestTokenUrl = '') or (AuthorizeUrl = '') or (AccessTokenUrl = '') then begin
        ErrMsg := 'Server discovery document is missing OAuth URLs';
        exit;
    end;

    CallbackUrl := 'http://127.0.0.1:' + IntToStr(OAuthCallbackPort) + '/callback';

    // ---- Step 1: request token ----
    Params := TOAuthParams.Create;
    ReqTokenResp := '';
    try
        Params.AddParam('oauth_callback', CallbackUrl);
        OAuthSignRequest('POST', RequestTokenUrl, Params, '', '');
        Client := TFPHttpClient.Create(nil);
        try
            Client.AddHeader('Authorization', OAuthAuthHeader(Params));
            try
                ReqTokenResp := Client.FormPost(RequestTokenUrl, '');
            except
                on E: Exception do begin
                    ErrMsg := 'Failed to obtain a request token: ' + E.Message;
                    exit;
                end;
            end;
        finally
            Client.Free;
        end;
    finally
        Params.Free;
    end;

    ReqToken := ExtractFormValue(ReqTokenResp, 'oauth_token');
    ReqSecret := ExtractFormValue(ReqTokenResp, 'oauth_token_secret');
    if (ReqToken = '') or (ReqSecret = '') then begin
        ErrMsg := 'Server did not return a request token: ' + ReqTokenResp;
        exit;
    end;

    // ---- Step 2: open browser, wait for the redirect on a local listener ----
    AuthUrl := AuthorizeUrl + '?oauth_token=' + OAuthPercentEncode(ReqToken);
    Got := False;
    Verifier := '';
    Server := TFPHTTPServer.Create(nil);
    Catcher := TOAuthCallbackCatcher.Create;
    try
        Catcher.Server := Server;
        Catcher.Got := False;
        Server.Port := OAuthCallbackPort;
        Server.OnRequest := @Catcher.HandleRequest;
        if ProgressProcedure <> nil then
            ProgressProcedure('Waiting for you to authorize in your browser...');
        {$ifdef LCL}
        OpenURL(AuthUrl);
        {$endif}
        // Active := True blocks accepting connections until Catcher.HandleRequest
        // sets it False - safe here only because callers are expected to
        // invoke ConnectViaOAuth off the GUI thread, see unit header.
        Server.Active := True;
        Got := Catcher.Got;
        Verifier := Catcher.Verifier;
    finally
        Server.Free;
        Catcher.Free;
    end;

    if (not Got) or (Verifier = '') then begin
        ErrMsg := 'Did not receive an authorization callback (timed out, or was cancelled in the browser).';
        exit;
    end;

    // ---- Step 3: exchange the verifier for a permanent access token ----
    Params := TOAuthParams.Create;
    AccessResp := '';
    try
        Params.AddParam('oauth_verifier', Verifier);
        OAuthSignRequest('POST', AccessTokenUrl, Params, ReqToken, ReqSecret);
        Client := TFPHttpClient.Create(nil);
        try
            Client.AddHeader('Authorization', OAuthAuthHeader(Params));
            try
                AccessResp := Client.FormPost(AccessTokenUrl, '');
            except
                on E: Exception do begin
                    ErrMsg := 'Failed to exchange verifier for an access token: ' + E.Message;
                    exit;
                end;
            end;
        finally
            Client.Free;
        end;
    finally
        Params.Free;
    end;

    FAccessToken := ExtractFormValue(AccessResp, 'oauth_token');
    FAccessTokenSecret := ExtractFormValue(AccessResp, 'oauth_token_secret');
    if (FAccessToken = '') or (FAccessTokenSecret = '') then begin
        ErrMsg := 'Server did not return an access token: ' + AccessResp;
        exit;
    end;

    SaveAccessToken;
    Result := True;
end;

end.
