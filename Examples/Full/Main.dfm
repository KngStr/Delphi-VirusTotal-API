object Frm_VtAPI: TFrm_VtAPI
  Left = 0
  Top = 0
  BorderStyle = bsSingle
  Caption = 'VirusTotal API Demo'
  ClientHeight = 419
  ClientWidth = 611
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -13
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    611
    419)
  PixelsPerInch = 96
  TextHeight = 16
  object Mmo: TMemo
    Left = 0
    Top = 119
    Width = 611
    Height = 300
    Align = alBottom
    Anchors = [akLeft, akTop, akRight, akBottom]
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object TbNb: TTabbedNotebook
    Left = 0
    Top = 0
    Width = 613
    Height = 113
    Anchors = [akLeft, akTop, akRight]
    TabFont.Charset = DEFAULT_CHARSET
    TabFont.Color = clBtnText
    TabFont.Height = -11
    TabFont.Name = 'Tahoma'
    TabFont.Style = []
    TabOrder = 1
    object TTabPage
      Left = 4
      Top = 27
      Caption = 'File'
      object Lbl_File: TLabel
        Left = 7
        Top = 3
        Width = 50
        Height = 13
        Caption = 'Test File:'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
      end
      object Btn_ScanFile: TButton
        Left = 7
        Top = 52
        Width = 75
        Height = 25
        Caption = 'Scan File'
        TabOrder = 0
        TabStop = False
        OnClick = Btn_ScanFileClick
      end
      object Btn_Select: TButton
        Left = 479
        Top = 20
        Width = 75
        Height = 25
        Caption = 'Select File'
        TabOrder = 1
        OnClick = Btn_SelectClick
      end
      object Btn_ReportFile: TButton
        Left = 186
        Top = 52
        Width = 75
        Height = 25
        Caption = 'Report File'
        TabOrder = 2
        TabStop = False
        OnClick = Btn_ReportFileClick
      end
      object Edt_File: TEdit
        Left = 7
        Top = 22
        Width = 466
        Height = 24
        TabOrder = 3
      end
      object Btn_RescanFile: TButton
        Left = 96
        Top = 52
        Width = 75
        Height = 25
        Caption = 'ReScan File'
        TabOrder = 4
        TabStop = False
        OnClick = Btn_RescanFileClick
      end
    end
    object TTabPage
      Left = 4
      Top = 27
      Caption = 'Url'
      object Lbl_Url: TLabel
        Left = 7
        Top = 3
        Width = 47
        Height = 13
        Caption = 'Test Url:'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
      end
      object Edt_Url: TEdit
        Left = 7
        Top = 22
        Width = 569
        Height = 24
        TabOrder = 0
      end
      object Btn_ScanUrl: TButton
        Left = 7
        Top = 52
        Width = 75
        Height = 25
        Caption = 'Scan Url'
        TabOrder = 1
        OnClick = Btn_ScanUrlClick
      end
      object Btn_ReportUrl: TButton
        Left = 96
        Top = 52
        Width = 75
        Height = 25
        Caption = 'Report Url'
        TabOrder = 2
        OnClick = Btn_ReportUrlClick
      end
    end
  end
  object DlgOpen: TOpenDialog
    Left = 399
    Top = 65527
  end
end
