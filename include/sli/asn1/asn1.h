/* SEQLABS_VTING --> */
#ifndef _ASN1_H
#define _ASN1_H


/*Memory defines*/
//#define ASN1_MALLOC(_x_) alloc(GLOBAL_HEAP_ID, _x_) /*alloc is already aligned to 64*/
//#define ASN1_FREE(_x_)   free(GLOBAL_HEAP_ID, _x_)

//#define ASN1_MALLOC(_x_) clrMalloc(CLR_MEM_HEAP_ID, _x_)
//#define ASN1_FREE(_x_)   clrFree(CLR_MEM_HEAP_ID, _x_)


#include <malloc.h>
#define ASN1_MALLOC(_x_) malloc(_x_)
#define ASN1_FREE(_x_) free(_x_)
#define ASN1_CALLOC(_x_, _s_) calloc(_x_,_s_)


#define ASN1_EOC             0
#define ASN1_BOOLEAN         1 //
#define ASN1_INTEGER         2 //
#define ASN1_BITSTRING       3 // 
#define ASN1_OCTETSTRING     4 //
#define ASN1_NULL            5 //
#define ASN1_OBJECTID        6 //
#define ASN1_OBJECTDESC      7
#define ASN1_EXTERNAL        8
#define ASN1_REAL            9
#define ASN1_ENUMERATED      10
#define ASN1_EMBEDDEDPDV     11
#define ASN1_UTF8STRING      12
#define ASN1_RELATIVEOID     13
#define ASN1_RESERVED_0      14
#define ASN1_RESERVED_1      15
#define ASN1_SEQUENCE        16 //
#define ASN1_SEQUENCEOF      16 //
#define ASN1_SET             17
#define ASN1_SETOF           17
#define ASN1_NUMERICSTRING   18
#define ASN1_PRINTABLESTRING 19
#define ASN1_T61STRING       20
#define ASN1_VIDEOTEXSTRING  21
#define ASN1_IA5STRING       22
#define ASN1_UTCTIME         23
#define ASN1_GENERALIZEDTIME 24
#define ASN1_GRAPHICSTRIN    25
#define ASN1_VISIBLESTRING   26
#define ASN1_GENERALSTRING   27
#define ASN1_UNIVERSALSTRING 28
#define ASN1_CHARACTERSTRING 29
#define ASN1_BMPSTRING       30
#define ASN1_OPTION			 31

#define ASN1_CLS_UNIVERSAL   0x00
#define ASN1_CLS_APPLICATION 0x01
#define ASN1_CLS_CONTEXT     0x02
#define ASN1_CLS_PRIVATE     0x03

#define ASN1_CTYPE_PRIMITIVE   0x00
#define ASN1_CTYPE_CONSTRUCTED 0x01



#define AP_OK 0
#define AP_ERROR 1
#define AP_ERROR_LENGTH_OVERFLOW 2
#define AP_ERROR_LENGTH_UNKNOWN 3

#define AP_FREENODEONLY 0
#define AP_FREECONTENT 1


typedef struct dernode
{
	uint8_t cls;
	uint8_t composition;
	uint8_t tag;
	size_t length; 	 /*length of content*/
	void* content; 	 /*value for node*/
 	void* raw;	    	/*Entire buffer with tag, length etc... in it*/
	size_t rawlength;	/*length of entire buffer*/
	struct dernode* next;
	struct dernode* children;
} dernode;


typedef void (*der_iterator)(dernode* node,void* additional);



// DER encoding
dernode* asn1_newNode(uint8_t type);
void asn1_addSibling(dernode* sibling,dernode* newsibling);
void asn1_addChild(dernode* parent,dernode* child);

size_t asn1_getSize(dernode* root);
size_t asn1_encode(uint8_t* buffer,dernode* root);


dernode *asn1_copyNode( dernode *in, uint8_t follow_sibling );

// DER parsing
int asn1_parseDER(dernode** node,uint8_t* buffer,size_t buffersize);
dernode * asn1_parseSingleNode( uint8_t *buffer, size_t buffersize );

int asn1_getSiblingCount(dernode* node);
dernode* asn1_getSibling(dernode* node,int index);

int asn1_getChildCount(dernode* node);
dernode* asn1_getChild(dernode* node,int index);

// utilities
void asn1_setInteger(dernode* node,int value);
int asn1_getInteger(dernode* node);

//Checks the first byte for >= 0x80, adds '00' if necessary.
//Will always allocate a buffer for node and copy the value.
int asn1_setBigInt(dernode* node, uint8_t *value, size_t length);
//Copies the number from node to value, removing the [00] if necessary.
//If length is not large enough to hold the number then the variable will hold the necessary length on -1 return
int asn1_getBigInt(dernode* node, uint8_t *value, size_t *length);

void asn1_walkTree(dernode* node,der_iterator iterator,void* additional);
void asn1_freeTree(dernode* node,int mode);

#endif
/* SEQLABS_VTING <-- */
