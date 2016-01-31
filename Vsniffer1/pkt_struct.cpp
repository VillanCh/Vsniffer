#ifndef __PKT_STRUCT_H__
#define __PKT_STRUCT_H__
#include "winpcap_basic.h"

// ��̫��Э���ʽ�Ķ���  
typedef struct ether_header {
	u_char ether_dhost[6];      // Ŀ���ַ  
	u_char ether_shost[6];      // Դ��ַ  
	u_short ether_type;         // ��̫������  
}ether_header;

// �û�����4�ֽڵ�IP��ַ  
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;


// ���ڱ���IPV4���ײ�  
typedef struct ip_header {
#ifdef WORDS_BIGENDIAN  
	u_char ip_version : 4, header_length : 4;
#else  
	u_char header_length : 4, ip_version : 4;
#endif  

	u_char ver_ihl;     // �汾�Լ��ײ����ȣ���4λ  
	u_char tos;         // ��������  
	u_short tlen;       // �ܳ���  
	u_short identification;     // ���ʶ��  
	u_short offset;         // ����ƫ��  
	u_char ttl;         // ��������  
	u_char proto;       // Э������  
	u_short checksum;       // ��ͷ������  
	ip_address saddr;   // ԴIP��ַ  
	ip_address daddr;   // Ŀ��IP��ַ  
	u_int op_pad;       //��ѡ ����ֶ�  
}ip_header;

// ����TCP�ײ�  
typedef struct tcp_header {
	u_short sport;
	u_short dport;
	u_int sequence;     // ������  
	u_int ack;                  // �ظ���  

#ifdef WORDS_BIGENDIAN  
	u_char offset : 4, reserved : 4;        // ƫ�� Ԥ��  
#else  
	u_char reserved : 4, offset : 4;        // Ԥ�� ƫ��  
#endif  

	u_char flags;               // ��־  
	u_short windows;            // ���ڴ�С  
	u_short checksum;           // У���  
	u_short urgent_pointer;     // ����ָ��  
}tcp_header;

typedef struct udp_header {
	u_int32_t sport;            // Դ�˿�  
	u_int32_t dport;            // Ŀ��˿�  
	u_int8_t zero;              // ����λ  
	u_int8_t proto;             // Э���ʶ  
	u_int16_t datalen;          // UDP���ݳ���  
}udp_header;

typedef struct icmp_header {
	u_int8_t type;              // ICMP����  
	u_int8_t code;              // ����  
	u_int16_t checksum;         // У���  
	u_int16_t identification;   // ��ʶ  
	u_int16_t sequence;         // ���к�  
	u_int32_t init_time;        // ����ʱ���  
	u_int16_t recv_time;        // ����ʱ���  
	u_int16_t send_time;        // ����ʱ���  
}icmp_header;

typedef struct arp_header {
	u_int16_t arp_hardware_type;
	u_int16_t arp_protocol_type;
	u_int8_t arp_hardware_length;
	u_int8_t arp_protocol_length;
	u_int16_t arp_operation_code;
	u_int8_t arp_source_ethernet_address[6];
	u_int8_t arp_source_ip_address[4];
	u_int8_t arp_destination_ethernet_address[6];
	u_int8_t arp_destination_ip_address[4];
}arp_header;

#endif