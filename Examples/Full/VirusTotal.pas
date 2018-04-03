//API docs: https://developers.virustotal.com/v2.0/

unit VirusTotal;

interface

{ /$DEFINE vtDateTimeHelper }

uses
  Windows,
{$IFDEF vtDateTimeHelper}
  DateTimeHelper,
{$ENDIF}
  XSuperObject;

{ TODO -oOwner -cGeneral : Translate time to TDateTime }
type
  TvtFileSend = packed record
    verbose_msg, resource, scan_id, permalink, sha256, sha1, md5: string;
  end;

  TvtURLSend = packed record
  public
    verbose_msg, resource, url, scan_id, permalink: string;
    scan_date: string;
  end;

  TvtAntiVirusItemFile = packed record
    detected: Boolean;
    name, version, result, update: string;
  end;

  TvtAntiVirusItemURL = packed record
    detected: Boolean;
    name, result: string;
  end;

  TvtFileReport = packed record
    scan_id, sha1, resource, scan_date, permalink, verbose_msg, sha256,
      md5: string;
    response_code, total, positives: Integer;
    scans: TArray<TvtAntiVirusItemFile>;
  end;

  TvtIPreport = packed record
  public
    verbose_msg, resource, url, scan_id, scan_date, permalink,
      filescan_id: string;
    response_code, total, positives: Integer;
    scans: TArray<TvtAntiVirusItemURL>;
  end;

  TvtURLReport = packed record
    verbose_msg, url, scan_id, scan_date, permalink,
      filescan_id: string;
    response_code, total, positives: Integer;
    scans: TArray<TvtAntiVirusItemURL>;
  end;

{$M+}

  TVirusTotalAPI = class
  strict private
  const
    SERVER = 'https://www.virustotal.com/vtapi/v2/';
  private
    FApiKey: string;
  public
    function ScanFile(const FileName: string): TvtFileSend;
    function RescanFile(const Hash: string): TvtFileSend; overload;
    function RescanFile(const Hash: TArray<string>)
      : TArray<TvtFileSend>; overload;
    function reportFile(const Hash: TArray<string>)
      : TArray<TvtFileReport>; overload;
    function reportFile(const Hash: string): TvtFileReport; overload;
    function scanURL(const URLs: TArray<string>): TArray<TvtURLSend>; overload;
    function scanURL(const url: string): TvtURLSend; overload;
    function reportURL(const url: string; scan: Boolean = False)
      : TvtURLReport; overload;
    function reportURL(const URLs: TArray<string>; scan: Boolean = False)
      : TArray<TvtURLReport>; overload;
    // function reportIpAddress(Const IP: String): TArray<TvtURLReport>; overload;
    constructor Create;
    destructor Destroy; override;
  published
    property ApiKey: string read FApiKey write FApiKey;
  end;

implementation

uses
  System.SysUtils, System.Net.HttpClient, System.Net.Mime;

{ TVirusTotalAPI }

constructor TVirusTotalAPI.Create;
begin
  ApiKey := '564375a55556bb03a912e08dda03d628a147f95e9098b07e7ecf279fadd2d931';
end;

destructor TVirusTotalAPI.Destroy;
begin
  inherited;
end;

function TVirusTotalAPI.reportFile(const Hash: string): TvtFileReport;
var
  List: TArray<TvtFileReport>;
begin
  List := reportFile([Hash]);
  if Length(List) > 0 then
    Result := List[0]
  else
    ZeroMemory(@Result, SizeOf(TvtFileReport));
end;

function TVirusTotalAPI.reportURL(const url: string; scan: Boolean)
  : TvtURLReport;
var
  List: TArray<TvtURLReport>;
begin
  List := reportURL([url], scan);
  if Length(List) > 0 then
    Result := List[0]
  else
    ZeroMemory(@Result, SizeOf(TvtURLReport));
end;

function TVirusTotalAPI.reportURL(const URLs: TArray<string>; scan: Boolean)
  : TArray<TvtURLReport>;

  function Get(S: string): TvtURLReport;
  var
    X: ISuperObject;
    Y: IMember;
    I: Integer;
  begin
    X := TSuperObject.Create(S);

    ZeroMemory(@Result, SizeOf(Result));
    with Result do begin
      scan_id := X.S['scan_id'];
      url := X.S['url'];
      filescan_id := X.S['filescan_id'];
      scan_date := X.S['scan_date'];
      permalink := X.S['permalink'];
      verbose_msg := X.S['verbose_msg'];
      response_code := X.I['response_code'];
      total := X.I['total'];
      positives := X.I['positives'];

      SetLength(scans, X.O['scans'].Count);
      I := 0;
      for Y in X.O['scans'] do begin
        scans[I] := TSuperRecord<TvtAntiVirusItemURL>.FromJSON(Y.AsObject.AsJSON);
        scans[I].name := Y.Name;
        Inc(I);
      end;
    end;
  end;

const
  API = 'url/report';
var
  HTTP: THTTPClient;
  Part: TMultipartFormData;
  I: Integer;
  X: ISuperArray;
  sContent: string;
begin
  SetLength(Result, 0);
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('resource', string.Join(#13#10, URLs));
    if scan then
      Part.AddField('scan', '1');
    Part.AddField('apikey', ApiKey);
    sContent := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    if sContent = '' then
      Exit;
    X := SA(sContent);
    if X = nil then
      Exit;
    SetLength(Result, Length(URLs));
    if Length(URLs) > 1 then
    begin
      for I := 0 to X.Length - 1 do
        Result[I] := Get(X.O[I].AsJSON);
    end
    else
      Result[0] := Get(X.AsJSON);
  finally
    Part.Free;
    HTTP.Free;
  end;
end;

function TVirusTotalAPI.reportFile(const Hash: TArray<string>)
  : TArray<TvtFileReport>;

  function Get(S: string): TvtFileReport;
  var
    X: ISuperObject;
    Y: IMember;
    I: Integer;
  begin
    X := TSuperObject.Create(S);

    ZeroMemory(@Result, SizeOf(Result));
    with Result do begin
      scan_id := X.S['scan_id'];
      sha1 := X.S['sha1'];
      resource := X.S['resource'];
      scan_date := X.S['scan_date'];
      permalink := X.S['permalink'];
      verbose_msg := X.S['verbose_msg'];
      sha256 := X.S['sha256'];
      md5 := X.S['md5'];
      response_code := X.I['response_code'];
      total := X.I['total'];
      positives := X.I['positives'];

      SetLength(scans, X.O['scans'].Count);
      I := 0;
      for Y in X.O['scans'] do begin
        scans[I] := TSuperRecord<TvtAntiVirusItemFile>.FromJSON(Y.AsObject.AsJSON);
        scans[I].name := Y.Name;
        Inc(I);
      end;
    end;
  end;

const
  API = 'file/report';
var
  HTTP: THTTPClient;
  Part: TMultipartFormData;
  I: Integer;
  Y: ISuperArray;
  sContent: string;
begin
  SetLength(Result, 0);
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('resource', string.Join(', ', Hash));
    Part.AddField('apikey', ApiKey);
    sContent := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    if sContent = '' then
      Exit;
    Y := SA(sContent);
    if Y = nil then
      Exit;
    SetLength(Result, Length(Hash));
    if Length(Hash) > 1 then
    begin
      for I := 0 to Y.Length - 1 do
        Result[I] := Get(Y.O[I].AsJSON);
    end
    else
      Result[0] := Get(Y.AsJSON);
  finally
    Part.Free;
    HTTP.Free;
  end;

end;

function TVirusTotalAPI.RescanFile(const Hash: TArray<string>)
  : TArray<TvtFileSend>;
const
  API = 'file/rescan';
var
  HTTP: THTTPClient;
  Part: TMultipartFormData;
  I: Integer;
  X: ISuperArray;
  Y: ISuperObject;
  sContent: string;
begin
  SetLength(Result, 0);
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('resource', string.Join(', ', Hash));
    Part.AddField('apikey', ApiKey);
    sContent := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    if sContent = '' then
      Exit;
    if Length(Hash) > 1 then begin
      X := SA(sContent);
      if X = nil then
        Exit;
      SetLength(Result, X.Length);
      for I := 0 to X.Length - 1 do
        Result[I] := TSuperRecord<TvtFileSend>.FromJSON(X.O[I]);
    end
    else begin
      Y := SO(sContent);
      if Y = nil then
        Exit;
      SetLength(Result, 1);
      Result[0] := TSuperRecord<TvtFileSend>.FromJSON(Y);
    end;
  finally
    Part.Free;
    HTTP.Free;
  end;
end;

function TVirusTotalAPI.RescanFile(const Hash: string): TvtFileSend;
var
  List: TArray<TvtFileSend>;
begin
  List := RescanFile([Hash]);
  if Length(List) > 0 then
    Result := List[0]
  else
    ZeroMemory(@Result, SizeOf(TvtFileSend));
end;

function TVirusTotalAPI.ScanFile(const FileName: string): TvtFileSend;
const
  API = 'file/scan';
var
  HTTP: THTTPClient;
  Part: TMultipartFormData;
  sContent: string;
begin
  ZeroMemory(@Result, SizeOf(TvtFileSend));
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddFile('file', FileName);
    Part.AddField('apikey', ApiKey);
    sContent := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    if sContent = '' then
      Exit;
    Result := TSuperRecord<TvtFileSend>.FromJSON(sContent);
  finally
    Part.Free;
    HTTP.Free;
  end;
end;

function TVirusTotalAPI.scanURL(const url: string): TvtURLSend;
var
  List: TArray<TvtURLSend>;
begin
  List := scanURL([url]);
  if Length(List) > 0 then
    Result := List[0]
  else
    ZeroMemory(@Result, SizeOf(TvtURLSend));
end;

function TVirusTotalAPI.scanURL(const URLs: TArray<string>): TArray<TvtURLSend>;
const
  API = 'url/scan';
var
  HTTP: THTTPClient;
  Part: TMultipartFormData;
  I: Integer;
  X: ISuperArray;
  sContent: string;
begin
  SetLength(Result, 0);
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('url', string.Join(#13#10, URLs));
    Part.AddField('apikey', ApiKey);
    sContent := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    if sContent = '' then
      Exit;
    X := SA(sContent);
    if X = nil then
      Exit;
    SetLength(Result, Length(URLs));
    if Length(URLs) > 1 then
    begin
      for I := 0 to X.Length - 1 do
        Result[I] := TSuperRecord<TvtURLSend>.FromJSON(X.O[I]);
    end
    else
      Result[0] := TSuperRecord<TvtURLSend>.FromJSON(X.AsJSON);
  finally
    Part.Free;
    HTTP.Free;
  end;
end;

end.
