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
    version, result, update: string;
  end;

  TvtAntiVirusItemURL = packed record
    detected: Boolean;
    result: string;
  end;

  TvtAVItemsURL = packed record
  public
    Opera, TrendMicro, Phishtank, BitDefender, MalwareDomainList, ParetoLogic,
      Avira, Wepawet: TvtAntiVirusItemURL;
    [ALIAS('Dr.Web')]
    drWeb: TvtAntiVirusItemURL;
    [ALIAS('Malc0de Database')]
    Malc0deDatabase: TvtAntiVirusItemURL;
    [ALIAS('G-Data')]
    G_Data: TvtAntiVirusItemURL;
    [ALIAS('Websense ThreatSeeker')]
    WebsenseThreatSeeker: TvtAntiVirusItemURL;
  end;

  TvtAVItemsFile = packed record
  public
    AVG, AVware, AegisLab, Agnitum, Alibaba, Arcabit, Avast, Avira, BitDefender,
      Bkav, ByteHero, CMC, ClamAV, Comodo, Cyren, Emsisoft, Fortinet, GData,
      Ikarus, Jiangmin, K7AntiVirus, K7GW, Kaspersky, Malwarebytes, McAfee,
      Microsoft, Panda, Rising, SUPERAntiSpyware, Sophos, Symantec, Tencent,
      TheHacker, TotalDefense, TrendMicro, VBA32, VIPRE, ViRobot, Zillya, Zoner,
      nProtect: TvtAntiVirusItemFile;
    [ALIAS('Ad-Aware')]
    Ad_Aware: TvtAntiVirusItemFile;
    [ALIAS('AhnLab-V3')]
    AhnLab_V3: TvtAntiVirusItemFile;
    [ALIAS('Antiy-AVL')]
    Antiy_AVL: TvtAntiVirusItemFile;
    [ALIAS('Baidu-International')]
    Baidu_International: TvtAntiVirusItemFile;
    [ALIAS('CAT-QuickHeal')]
    CAT_QuickHeal: TvtAntiVirusItemFile;
    [ALIAS('ESET-NOD32')]
    ESET_NOD32: TvtAntiVirusItemFile;
    [ALIAS('F-Prot')]
    F_Prot: TvtAntiVirusItemFile;
    [ALIAS('F-Secure')]
    F_Secure: TvtAntiVirusItemFile;
    [ALIAS('McAfee-GW-Edition')]
    McAfee_GW_Edition: TvtAntiVirusItemFile;
    [ALIAS('MicroWorld-eScan')]
    MicroWorld_eScan: TvtAntiVirusItemFile;
    [ALIAS('NANO-Antivirus')]
    NANO_Antivirus: TvtAntiVirusItemFile;
    [ALIAS('TrendMicro-HouseCall')]
    TrendMicro_HouseCall: TvtAntiVirusItemFile;
  end;

  TvtFileReport = packed record
    scan_id, sha1, resource, scan_date, permalink, verbose_msg, sha256,
      md5: string;
    response_code, total, positives: Integer;
    scans: TvtAVItemsFile;
  end;

  TvtIPreport = packed record
  public
    verbose_msg, resource, url, scan_id, scan_date, permalink,
      filescan_id: string;
    response_code, total, positives: Integer;
    scans: TvtAVItemsURL;
  end;

  TvtURLReport = packed record
    verbose_msg, resource, url, scan_id, scan_date, permalink,
      filescan_id: string;
    response_code, total, positives: Integer;
    scans: TvtAVItemsURL;
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
  ApiKey := 'e2fd0cd961bdeaf2d054871299a6c2f056d7a5dbda813b93000a81a64087b341';
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
        Result[I] := TSuperRecord<TvtURLReport>.FromJSON(X.O[I]);
    end
    else
      Result[0] := TSuperRecord<TvtURLReport>.FromJSON(X.AsJSON);
  finally
    Part.Free;
    HTTP.Free;
  end;
end;

function TVirusTotalAPI.reportFile(const Hash: TArray<string>)
  : TArray<TvtFileReport>;
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
        Result[I] := TSuperRecord<TvtFileReport>.FromJSON(Y.O[I]);
    end
    else
      Result[0] := TSuperRecord<TvtFileReport>.FromJSON(Y.AsJSON);
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
  sContent: string;
begin
  HTTP := THTTPClient.Create;
  Part := TMultipartFormData.Create;
  try
    Part.AddField('resource', string.Join(', ', Hash));
    Part.AddField('apikey', ApiKey);
    sContent := HTTP.Post(SERVER + API, Part).ContentAsString(TEncoding.UTF8);
    if sContent = '' then
      Exit;
    X := SA(sContent);
    if X = nil then
      Exit;
    SetLength(Result, X.Length);
    for I := 0 to X.Length - 1 do
      Result[I] := TSuperRecord<TvtFileSend>.FromJSON(X.O[I]);
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
