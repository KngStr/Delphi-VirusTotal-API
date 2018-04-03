program VirusTotalAPIDemo;

uses
  Vcl.Forms,
  Main in 'Main.pas' {Frm_VtAPI},
  VirusTotal in '..\..\VirusTotal.pas',
  XSuperObject in '..\..\libs\x-superobject\XSuperObject.pas',
  XSuperJSON in '..\..\libs\x-superobject\XSuperJSON.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFrm_VtAPI, Frm_VtAPI);
  Application.Run;
end.
