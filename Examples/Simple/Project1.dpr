program Project1;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  System.SysUtils,
  VirusTotal in '..\..\VirusTotal.pas',
  XSuperObject in '..\..\libs\x-superobject\XSuperObject.pas',
  XSuperJSON in '..\..\libs\x-superobject\XSuperJSON.pas';

Var
  VT: TVirusTotalAPI;
  ResultScan: TvtURLReport;
  I: Integer;

begin
  VT := TVirusTotalAPI.Create;
  try
    try
      { TODO -oUser -cConsole Main : Insert code here }
      ResultScan := VT.reportURL('https://codmasters.ru/');
      Writeln(Format('Result: %d / %d', [ResultScan.positives, ResultScan.total]));
      for I := Low(ResultScan.scans) to High(ResultScan.scans) do
        with ResultScan.scans[I] do
          if detected then
            Writeln(Name, ': ', result);
    except
      on E: Exception do
        Writeln(E.ClassName, ': ', E.Message);
    end;
  finally
    VT.Free;
    Readln;
  end;
end.
