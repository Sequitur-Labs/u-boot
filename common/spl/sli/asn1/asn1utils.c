#include <common.h>
#include <sli/asn1/asn1.h>

//-----------------------------------------------
// private
static void asn1_flip(uint8_t* dst,uint8_t* src,size_t len)
{
	size_t index;
	for (index=0;index<len;index++)
		dst[index]=src[len-1-index];
}

#define END_LITTLE 0
#define END_BIG 1

static size_t asn1_getMinimumBytes(uint8_t* num,size_t len,int endian)
{
	size_t res=0;

	switch (endian)
	{
	case END_BIG:
		{
			size_t index=0;
			for (index=0;index<len;index++)
			{
				if (num[index])
				{
					res=len-index;
					break;
				}
			}
		}
		break;
	case END_LITTLE:
		{
			int index;
			for (index=len-1;index>=0;index--)
			{
				if (num[index])
				{
					res=len-index;
					break;
				}
			}
		}
		break;
	default: break;
	}

	if (res==0)
		res+=1;
		

	return res;
}
//-----------------------------------------------
//-----------------------------------------------
//-----------------------------------------------
//-----------------------------------------------
//-----------------------------------------------
//-----------------------------------------------
// public


// this will always allocate a buffer of minimum size
void asn1_setInteger(dernode* node,int value)
{
	if (node->tag==ASN1_INTEGER)
	{
		size_t len=sizeof(value);
		uint8_t* buffer, *intbuffer=NULL;
		size_t minbytes=0,ptrstart=0;


		// little endian
		buffer=(uint8_t*)ASN1_MALLOC(len);
		memset(buffer, 0, len);
		asn1_flip(buffer,(uint8_t*)&value,len);

		// big endian
		// buffer=(uint8_t*)&value;

		// everything from this point on is big endian
		minbytes=asn1_getMinimumBytes(buffer,len,END_BIG);
		ptrstart=len-minbytes;

		node->length=minbytes;

		intbuffer=(uint8_t*)ASN1_MALLOC(minbytes);
		memset(intbuffer, 0, minbytes);
		memcpy(intbuffer,buffer+ptrstart,minbytes);

		node->content=intbuffer;

		if (buffer!=(uint8_t*)&value)
			ASN1_FREE(buffer);
	}
}

int asn1_getInteger(dernode* node)
{
	int res=0;
	if (node->tag==ASN1_INTEGER)
	{
		// error condition - this will be encountered for bigints...
		if (node->length<=sizeof(int))
		{
			uint8_t* resptr=(uint8_t*)&res;
			
			// little endian
			asn1_flip(resptr,node->content,node->length);

			// big endian
			// TBD
		}
	}
	return res;
}

//Checks the first byte for >= 0x80, adds '00' if necessary.
//Will always allocate a buffer for node and copy the value.
int asn1_setBigInt(dernode* node, uint8_t *value, size_t length){
	int res=0;
	int offset=0;
	if(!node || !value){
		return -1;
	}
	if(value[0] >= 0x80){
		length++;
		offset++;
	}
	node->tag=ASN1_INTEGER;
	node->length=length;
	//allocate at set to '0'
	node->content = ASN1_CALLOC(length, sizeof(uint8_t));
	memcpy(node->content+offset, value, length);
	return res;
}

//Copies the number from node to value, removing the [00] if necessary.
//If length is not large enough to hold the number then the variable will hold the necessary length on -1 return
int asn1_getBigInt(dernode* node, uint8_t *value, size_t *length){
	int res=0;
	int vlen=0;
	int index=0;
	uint8_t *bigint = NULL;
	if(!node || !value || !length){
		return -2;
	}
	bigint = (uint8_t*)node->content;
	vlen = node->length;
	while(bigint[index] == 0x00){
		index++;
		vlen--;
	}
	if(*length < vlen){
		*length=vlen;
		return -1;
	}
	memcpy(value, node->content+(node->length-vlen), vlen);
	return res;
}


void asn1_walkTree(dernode* node,der_iterator iterator,void* additional)
{
	if (node)
	{
		if (node->next)
			asn1_walkTree(node->next,iterator,additional);

		if (node->children)
			asn1_walkTree(node->children,iterator,additional);

		iterator(node,additional);
	}
}



static void free_node(dernode* node,void* additional)
{
	int* mode=(int*)additional;
	if (*mode==AP_FREECONTENT)
		ASN1_FREE(node->content);

	ASN1_FREE(node);
}

void asn1_freeTree(dernode* node,int mode)
{
	asn1_walkTree(node,free_node,(void*)&mode);
}













