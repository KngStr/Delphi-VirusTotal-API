unit Main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms,
  Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.TabNotBk,
  XSuperJSON, XSuperObject, VirusTotal;

type
  TFrm_VtAPI = class(TForm)
    Mmo: TMemo;
    DlgOpen: TOpenDialog;
    TbNb: TTabbedNotebook;
    Edt_Url: TEdit;
    Lbl_Url: TLabel;
    Btn_ScanUrl: TButton;
    Btn_ScanFile: TButton;
    Btn_Select: TButton;
    Btn_ReportFile: TButton;
    Lbl_File: TLabel;
    Edt_File: TEdit;
    Btn_ReportUrl: TButton;
    Btn_RescanFile: TButton;
    procedure Btn_SelectClick(Sender: TObject);
    procedure Btn_ScanFileClick(Sender: TObject);
    procedure Btn_ReportFileClick(Sender: TObject);
    procedure Btn_ScanUrlClick(Sender: TObject);
    procedure Btn_ReportUrlClick(Sender: TObject);
    procedure Btn_RescanFileClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    { Private declarations }
  protected
    procedure WMDropFiles(var Msg: TMessage); message WM_DROPFILES;
  public
    { Public declarations }
  end;

var
  Frm_VtAPI: TFrm_VtAPI;
  VT: TVirusTotalAPI;
  vtFileSend: TvtFileSend;
  vtURLSend: TvtURLSend;

implementation

{$R *.dfm}

uses ShellAPI;

{ TMainForm }

procedure TFrm_VtAPI.Btn_ReportUrlClick(Sender: TObject);
var
  I: Integer;
begin
  if Edt_Url.Text = '' then begin
    Mmo.Lines.Add('use scan first!');
    Exit;
  end;

  with VT.reportURL(Edt_Url.Text) do begin
    Mmo.Lines.Add(Format('%s', [scan_date]));
    Mmo.Lines.Add(Format('code:%d / %s', [response_code, verbose_msg]));

    if response_code <> 1 then
      Exit;
    Mmo.Lines.Add(Format('positives: %d / %d', [positives, total]));

    for I := 0 to Length(scans) - 1 do
      with scans[I] do
        if detected then
          Mmo.Lines.Add(Format('%-20s:%s'#13#10, [name, result]));
  end;
end;

procedure TFrm_VtAPI.Btn_RescanFileClick(Sender: TObject);
begin
  if vtFileSend.sha256 = '' then begin
    Mmo.Lines.Add('use scan first!');
    Exit;
  end;

  vtFileSend := VT.RescanFile(vtFileSend.sha256);

  Mmo.Lines.Add(Format('---%s---', [Edt_File.Text]));
  Mmo.Lines.Add(vtFileSend.permalink);
end;

procedure TFrm_VtAPI.Btn_ScanFileClick(Sender: TObject);
begin
  vtFileSend := VT.ScanFile(Edt_File.Text);

  Mmo.Lines.Add(Format('---%s---', [Edt_File.Text]));
  Mmo.Lines.Add(vtFileSend.permalink);
end;

procedure TFrm_VtAPI.Btn_ScanUrlClick(Sender: TObject);
begin
  vtURLSend := VT.scanURL(Edt_Url.Text);

  Mmo.Lines.Add(Format('---%s---', [Edt_Url.Text]));
  Mmo.Lines.Add(vtURLSend.permalink);
end;

procedure TFrm_VtAPI.Btn_SelectClick(Sender: TObject);
begin
  DlgOpen.Execute;
  Edt_File.Text := DlgOpen.FileName;
end;

procedure TFrm_VtAPI.FormCreate(Sender: TObject);
begin
  DragAcceptFiles(Handle, True);
end;

procedure TFrm_VtAPI.FormDestroy(Sender: TObject);
begin
  DragAcceptFiles(Handle, False);
end;

procedure TFrm_VtAPI.WMDropFiles(var Msg: TMessage);
var
  hDrop: THandle;
  FileCount: Integer;
  NameLen: Integer;
  I: Integer;
  S: string;

begin
  hDrop:= Msg.wParam;
  FileCount:= DragQueryFile (hDrop , $FFFFFFFF, nil, 0);

  for I:= 0 to FileCount - 1 do begin
    NameLen:= DragQueryFile(hDrop, I, nil, 0) + 1;
    SetLength(S, NameLen);
    DragQueryFile(hDrop, I, Pointer(S), NameLen);

    Edt_File.Text := S;
    Break;
  end;

  DragFinish(hDrop);
end;

procedure TFrm_VtAPI.Btn_ReportFileClick(Sender: TObject);
var
  I: Integer;
begin
  if vtFileSend.sha256 = '' then begin
    Mmo.Lines.Add('use scan first!');
    Exit;
  end;

  with VT.reportFile(vtFileSend.sha256) do begin
    Mmo.Lines.Add(Format('%s', [scan_date]));
    Mmo.Lines.Add(Format('code:%d / %s', [response_code, verbose_msg]));

    if response_code <> 1 then
      Exit;
    Mmo.Lines.Add(Format('positives: %d / %d', [positives, total]));

    for I := 0 to Length(scans) - 1 do
      with scans[I] do
        if detected then
          Mmo.Lines.Add(Format('%-20s:%s'#13#10, [name, result]));
  end;
end;

initialization
  VT := TVirusTotalAPI.Create;
finalization
  VT.Free;

end.
