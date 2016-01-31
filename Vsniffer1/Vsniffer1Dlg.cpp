
// Vsniffer1Dlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "Vsniffer1.h"
#include "Vsniffer1Dlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CVsniffer1Dlg �Ի���



CVsniffer1Dlg::CVsniffer1Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CVsniffer1Dlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CVsniffer1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	//	DDX_Control(pDX, IDC_DEVICEINFO, Details);
	DDX_Control(pDX, IDC_DEVICE, devId);
	DDX_Control(pDX, IDC_TCP, m_tcp);
	DDX_Control(pDX, IDC_UDP, m_udp);
	DDX_Control(pDX, IDC_ICMP, m_icmp);
	DDX_Control(pDX, IDC_IP, m_ip);
	DDX_Control(pDX, IDC_ARP, m_arp);
}

BEGIN_MESSAGE_MAP(CVsniffer1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
//	ON_LBN_SELCHANGE(IDC_LIST1, &CVsniffer1Dlg::OnLbnSelchangeList1)
	ON_BN_CLICKED(IDC_START, &CVsniffer1Dlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_GETDEVICE, &CVsniffer1Dlg::OnBnClickedGetdevice)
	ON_BN_CLICKED(IDC_COUNT, &CVsniffer1Dlg::OnBnClickedCount)
	ON_BN_CLICKED(IDC_UPDATE, &CVsniffer1Dlg::OnBnClickedUpdate)
	ON_BN_CLICKED(IDC_BUTTON5, &CVsniffer1Dlg::OnBnClickedButton5)
END_MESSAGE_MAP()


// CVsniffer1Dlg ��Ϣ�������

BOOL CVsniffer1Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO:  �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CVsniffer1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CVsniffer1Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CVsniffer1Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CVsniffer1Dlg::OnLbnSelchangeList1()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}


void CVsniffer1Dlg::OnBnClickedStart()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CString id = CString("");
	devId.GetWindowTextW(id);
	DevId=_ttoi(id);
	//id.Format(_T("%d"),i);
	//dumper.init();
	//dumper.startCapture(false, NULL);
	//CreateThread();
	dumper =new Dumper(this->deviceop.mapdevs[DevId]);
	AfxBeginThread(BeginDumper,this);
}
UINT CVsniffer1Dlg::BeginDumper(void* param)
{
	CVsniffer1Dlg* ret = (CVsniffer1Dlg*)param;
	ret->dumper->init();
	ret->dumper->startCapture(false, NULL);
	return 0;
}

void CVsniffer1Dlg::OnBnClickedGetdevice()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CString ret = deviceop.showDevices();
	//CString detail = CString(ret);
	GetDlgItem(IDC_STATIC)->SetWindowTextW(ret);
	
}


void CVsniffer1Dlg::OnBnClickedCount()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	/*
	int tcp = 0;
	int udp = 0;
	int icmp = 0;
	int ip = 0;
	int arp = 0;

	*/
	this->autoupdate = true;

	CString tmp;
	int b = this->dumper->tcp;
	tmp.Format(_T("%d"), b);
	m_tcp.SetWindowTextW(tmp);
	b = this->dumper->udp;
	tmp.Format(_T("%d"), b);
	m_udp.SetWindowTextW(tmp);	
	b = this->dumper->icmp;
	tmp.Format(_T("%d"), b);
	m_icmp.SetWindowTextW(tmp);	
	b = this->dumper->ip;
	tmp.Format(_T("%d"), b);
	m_ip.SetWindowTextW(tmp);	
	b = this->dumper->arp;
	tmp.Format(_T("%d"), b);
	m_arp.SetWindowTextW(tmp);
	
}


void CVsniffer1Dlg::OnBnClickedUpdate()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	this->autoupdate = true;
	AfxBeginThread(UpdateResult, this);
}
UINT CVsniffer1Dlg::UpdateResult(void *param)
{
	CVsniffer1Dlg *ret = (CVsniffer1Dlg*)param;
	CString tmp;
	
	while (ret->autoupdate)
	{
		Sleep(200);
		int b = ret->dumper->tcp;
		tmp.Format(_T("%d"), b);
		ret->m_tcp.SetWindowTextW(tmp);
		b = ret->dumper->udp;
		tmp.Format(_T("%d"), b);
		ret->m_udp.SetWindowTextW(tmp);
		b = ret->dumper->icmp;
		tmp.Format(_T("%d"), b);
		ret->m_icmp.SetWindowTextW(tmp);
		b = ret->dumper->ip;
		tmp.Format(_T("%d"), b);
		ret->m_ip.SetWindowTextW(tmp);
		b = ret->dumper->arp;
		tmp.Format(_T("%d"), b);
		ret->m_arp.SetWindowTextW(tmp);
	}
	return 0;
}


void CVsniffer1Dlg::OnBnClickedButton5()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	this->autoupdate = false;
}
