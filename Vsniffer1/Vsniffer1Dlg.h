
// Vsniffer1Dlg.h : ͷ�ļ�
//

#pragma once
#include "Dumper.h"
#include "DeviceOp.h"
#include "afxwin.h"

// CVsniffer1Dlg �Ի���
class CVsniffer1Dlg : public CDialogEx
{
// ����
public:
	CVsniffer1Dlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_VSNIFFER1_DIALOG };

	DeviceOp deviceop = DeviceOp();

	Dumper *dumper;
	int tcp = 0;
	int udp = 0;
	int icmp = 0;
	int ip = 0;
	int arp = 0;

	int DevId;
	static UINT CVsniffer1Dlg::BeginDumper(void *param);
	static UINT CVsniffer1Dlg::UpdateResult(void *param);
	CString device_detail;
	bool startSniff = false;
	bool autoupdate = false;

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnLbnSelchangeList1();
	afx_msg void OnBnClickedStart();
	afx_msg void OnBnClickedGetdevice();
	CEdit Details;
	CEdit devId;
	afx_msg void OnBnClickedCount();
	CStatic m_tcp;
	CStatic m_udp;
	CStatic m_icmp;
	CStatic m_ip;
	CStatic m_arp;
	afx_msg void OnBnClickedUpdate();
	afx_msg void OnBnClickedButton5();
};
