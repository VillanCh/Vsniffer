
// Vsniffer1.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CVsniffer1App: 
// �йش����ʵ�֣������ Vsniffer1.cpp
//

class CVsniffer1App : public CWinApp
{
public:
	CVsniffer1App();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CVsniffer1App theApp;